package uiapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/providers"
	"gorm.io/gorm"
)

const (
	defaultSyncTTL = time.Hour
	// maxRepoCacheAge caps how long we skip a full API fetch even if PushedAt
	// hasn't changed, so dormant repos still get a periodic consistency check.
	maxRepoCacheAge = 7 * 24 * time.Hour
)

// WarmCache pre-populates the in-memory cache on startup for all enabled
// providers. It first attempts to restore from the DB (no API calls); only
// when DB data is missing or stale does it fall through to a full API warm.
// Runs in a background goroutine so it never blocks server startup.
func WarmCache(db *gorm.DB, store *providerconfig.Store, c cache.Store) {
	go func() {
		// Small delay so the server is fully up before hammering provider APIs.
		time.Sleep(5 * time.Second)

		ctx := context.Background()

		providerList, err := store.ListEnabled(ctx)
		if err != nil {
			log.Printf("cache warmer: list providers: %v", err)
			return
		}

		for _, p := range providerList {
			ttl := providerTTL(p)
			if rebuildFromDB(ctx, db, c, p, ttl) {
				log.Printf("cache warmer: restored %s from DB (no API calls)", p.DisplayName)
				continue
			}
			warmProvider(ctx, db, store, c, p, false)
		}

		log.Printf("cache warmer: done")
	}()
}

// providerTTL returns the effective cache TTL based on the provider's poll_interval.
func providerTTL(p providerconfig.ProviderInstance) time.Duration {
	if p.PollInterval != nil && *p.PollInterval > 0 {
		return time.Duration(*p.PollInterval) * time.Second
	}
	return defaultSyncTTL
}

// rebuildFromDB attempts to restore the in-memory cache for a provider from
// persisted DB data without making any provider API calls.
// Returns true if enough fresh cache entries were found and restored.
func rebuildFromDB(ctx context.Context, db *gorm.DB, c cache.Store, p providerconfig.ProviderInstance, ttl time.Duration) bool {
	dbCaches, err := assets.ListRepoCacheByProvider(ctx, db, p.ID)
	if err != nil || len(dbCaches) == 0 {
		return false
	}

	var repoList []providers.RepoData
	freshCount := 0

	for _, dc := range dbCaches {
		var details providers.RepoDetails
		if json.Unmarshal([]byte(dc.DetailsJSON), &details) != nil || details.FullPath == "" {
			continue
		}
		repoList = append(repoList, details.RepoData)

		fresh := time.Since(dc.SyncedAt) < ttl
		if !fresh {
			continue
		}
		freshCount++

		var commits []providers.CommitInfo
		var contribs []providers.ContributorInfo
		_ = json.Unmarshal([]byte(dc.CommitsJSON), &commits)
		_ = json.Unmarshal([]byte(dc.ContributorsJSON), &contribs)

		detailsKey := fmt.Sprintf("provider:details:%s:%s", p.ID, strings.Trim(details.FullPath, "/"))
		resp := RepoDetailsResponse{Details: &details, Readme: dc.ReadmeContent, Commits: commits, Contributors: contribs}
		_ = cache.SetJSON(ctx, c, detailsKey, resp, ttl)
		_ = cache.SetJSON(ctx, c, fmt.Sprintf("contributors:%s", dc.RepoID), RepoContributorsResponse{Contributors: contribs}, ttl)
	}

	// Only consider it a successful rebuild if a strict majority of repos are fresh.
	if freshCount == 0 || freshCount*2 <= len(dbCaches) {
		return false
	}

	if len(repoList) > 0 {
		_ = cache.SetJSON(ctx, c, "provider:repos:"+p.ID, repoList, ttl)
	}

	return true
}

// warmProvider syncs all repos for a provider: repos are upserted to DB, and
// for each repo the full detail set (details, readme, commits, contributors)
// is fetched and stored in both DB and in-memory cache.
//
// On subsequent sync runs (within TTL), stale checks skip the API and restore
// directly from DB — so provider API quota is only consumed once per TTL.
// Set forceRefresh to true to always refresh repo details/contributors.
func warmProvider(ctx context.Context, db *gorm.DB, store *providerconfig.Store, c cache.Store, p providerconfig.ProviderInstance, forceRefresh bool) {
	token, err := store.GetActiveToken(ctx, p.ID)
	if err != nil {
		return
	}

	client := providerconfig.NewProviderClient(p.Type, p.BaseURL, token)
	if client == nil {
		return
	}

	ttl := providerTTL(p)

	// Fetch all repos (paginated).
	var allRepos []providers.RepoData
	page := 1
	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, p.OwnerPath, providers.ListOptions{
			Page:     page,
			PageSize: 100,
		})
		if err != nil {
			log.Printf("cache warmer: list repos for %s: %v", p.DisplayName, err)
			break
		}
		allRepos = append(allRepos, repos...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	// Cache the full repo list for list-page DB-backed fallback.
	if len(allRepos) > 0 {
		_ = cache.SetJSON(ctx, c, "provider:repos:"+p.ID, allRepos, ttl)
	}

	log.Printf("cache warmer: syncing %d repos for %s", len(allRepos), p.DisplayName)

	skipped := 0
	fetched := 0
	for _, repo := range allRepos {
		path := strings.Trim(repo.FullPath, "/")
		idx := strings.LastIndex(path, "/")
		if idx < 0 {
			continue
		}
		org := path[:idx]
		slug := path[idx+1:]
		if org == "" || slug == "" {
			continue
		}

		// Use PushedAt as the best proxy for last commit date, fall back to UpdatedAt.
		providerUpdatedAt := repo.PushedAt
		if providerUpdatedAt.IsZero() {
			providerUpdatedAt = repo.UpdatedAt
		}
		var providerUpdatedAtPtr *time.Time
		if !providerUpdatedAt.IsZero() {
			providerUpdatedAtPtr = &providerUpdatedAt
		}

		repoRecord, err := assets.UpsertRepo(ctx, db, assets.RepoInput{
			Provider:           p.Type,
			ProviderInstanceID: p.ID,
			Org:                org,
			Slug:               slug,
			ProviderUpdatedAt:  providerUpdatedAtPtr,
		})
		if err != nil {
			log.Printf("cache warmer: upsert repo %s: %v", path, err)
			continue
		}

		detailsCacheKey := fmt.Sprintf("provider:details:%s:%s", p.ID, path)
		contribCacheKey := fmt.Sprintf("contributors:%s", repoRecord.ID)

		if !forceRefresh {
			// Skip full API fetch if the repo hasn't been pushed since our last cache
			// and the cache isn't older than maxRepoCacheAge.
			if dbCache, dbErr := assets.GetRepoCache(ctx, db, repoRecord.ID); dbErr == nil {
				pushedAt := repo.PushedAt
				if pushedAt.IsZero() {
					pushedAt = repo.UpdatedAt
				}
				repoChanged := pushedAt.IsZero() || pushedAt.After(dbCache.SyncedAt)
				cacheStale := time.Since(dbCache.SyncedAt) >= maxRepoCacheAge

				if !repoChanged && !cacheStale {
					// Nothing changed — restore to in-memory if needed, skip API.
					if _, ok, _ := cache.GetJSON[RepoDetailsResponse](ctx, c, detailsCacheKey); !ok {
						var details providers.RepoDetails
						var commits []providers.CommitInfo
						var contribs []providers.ContributorInfo
						if json.Unmarshal([]byte(dbCache.DetailsJSON), &details) == nil {
							_ = json.Unmarshal([]byte(dbCache.CommitsJSON), &commits)
							_ = json.Unmarshal([]byte(dbCache.ContributorsJSON), &contribs)
							resp := RepoDetailsResponse{Details: &details, Readme: dbCache.ReadmeContent, Commits: commits, Contributors: contribs}
							_ = cache.SetJSON(ctx, c, detailsCacheKey, resp, ttl)
							_ = cache.SetJSON(ctx, c, contribCacheKey, RepoContributorsResponse{Contributors: contribs}, ttl)
						}
					}
					skipped++
					continue
				}
			}
		}

		// Repo changed or no cache — fetch fresh data from provider API.
		var details *providers.RepoDetails
		var readme string
		var commits []providers.CommitInfo
		var contribs []providers.ContributorInfo

		fetchRepoFullData(ctx, p, token, path, &details, &readme, &commits, &contribs)

		if contribs == nil {
			contribs = []providers.ContributorInfo{}
		}
		if commits == nil {
			commits = []providers.CommitInfo{}
		}
		contribs = enrichContributors(contribs, commits)
		commits = enrichCommits(commits, contribs)
		if details != nil && details.Stats.Contributors == 0 && len(contribs) > 0 {
			details.Stats.Contributors = len(contribs)
		}

		// Persist to DB so subsequent syncs and restarts can skip the API.
		if details != nil {
			detailsBytes, _ := json.Marshal(details)
			commitsBytes, _ := json.Marshal(commits)
			contribsBytes, _ := json.Marshal(contribs)
			if dbErr := assets.UpsertRepoCache(ctx, db, repoRecord.ID,
				string(detailsBytes), readme, string(commitsBytes), string(contribsBytes),
			); dbErr != nil {
				log.Printf("cache warmer: persist cache %s: %v", path, dbErr)
			}
		}

		// Populate in-memory cache — skip details if the API call failed.
		if details != nil {
			resp := RepoDetailsResponse{Details: details, Readme: readme, Commits: commits, Contributors: contribs}
			_ = cache.SetJSON(ctx, c, detailsCacheKey, resp, ttl)
		}
		_ = cache.SetJSON(ctx, c, contribCacheKey, RepoContributorsResponse{Contributors: contribs}, ttl)

		fetched++
		// Throttle to avoid hammering provider APIs.
		time.Sleep(200 * time.Millisecond)
	}
	log.Printf("cache warmer: %s done — %d fetched, %d skipped (unchanged)", p.DisplayName, fetched, skipped)
}

// fetchRepoFullData fetches details, readme, commits, and contributors for a
// single repo in parallel (4 concurrent provider API calls).
func fetchRepoFullData(ctx context.Context, p providerconfig.ProviderInstance, token, repoPath string,
	details **providers.RepoDetails, readme *string, commits *[]providers.CommitInfo, contribs *[]providers.ContributorInfo,
) {
	if repoPath == "" {
		return
	}
	var wg sync.WaitGroup

	switch p.Type {
	case providerconfig.ProviderGitHub:
		parts := strings.SplitN(repoPath, "/", 2)
		if len(parts) != 2 {
			return
		}
		cl := providers.NewGitHubClient(githubAPIBaseURL(p.BaseURL), token)
		wg.Add(4)
		go func() { defer wg.Done(); *details, _ = cl.GetRepoDetails(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *readme, _ = cl.GetReadme(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *commits, _ = cl.GetCommitLog(ctx, parts[0], parts[1], 10) }()
		go func() { defer wg.Done(); *contribs, _ = cl.GetContributors(ctx, repoPath, 30) }()

	case providerconfig.ProviderGitLab:
		cl := providers.NewGitLabClient(p.BaseURL, token)
		wg.Add(4)
		go func() { defer wg.Done(); *details, _ = cl.GetRepoDetails(ctx, repoPath) }()
		go func() { defer wg.Done(); *readme, _ = cl.GetReadme(ctx, repoPath) }()
		go func() { defer wg.Done(); *commits, _ = cl.GetCommitLog(ctx, repoPath, 10) }()
		go func() { defer wg.Done(); *contribs, _ = cl.GetContributors(ctx, repoPath, 30) }()

	case providerconfig.ProviderGitea, providerconfig.ProviderForgejo:
		parts := strings.SplitN(repoPath, "/", 2)
		if len(parts) != 2 {
			return
		}
		cl := providers.NewGiteaClient(p.BaseURL, token)
		wg.Add(4)
		go func() { defer wg.Done(); *details, _ = cl.GetRepoDetails(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *readme, _ = cl.GetReadme(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *commits, _ = cl.GetCommitLog(ctx, parts[0], parts[1], 10) }()
		go func() { defer wg.Done(); *contribs, _ = cl.GetContributors(ctx, repoPath, 30) }()
	}

	wg.Wait()
}
