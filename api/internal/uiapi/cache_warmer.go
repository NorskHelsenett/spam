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
	// repoListTTL is the in-memory TTL for the provider repo list. It is kept
	// long so that the list survives rate-limit periods between sync cycles.
	// The list is refreshed on every successful sync, not on expiry.
	repoListTTL = 24 * time.Hour
)

// WarmCache pre-populates the in-memory cache on startup for all enabled
// providers. It uses a single API call per provider to check completeness,
// then only fetches what is missing rather than re-syncing everything.
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

		var wg sync.WaitGroup
		for _, p := range providerList {
			wg.Add(1)
			go func(p providerconfig.ProviderInstance) {
				defer wg.Done()
				warmProviderSmart(ctx, db, store, c, p)
			}(p)
		}
		wg.Wait()

		log.Printf("cache warmer: done")
	}()
}

// warmProviderSmart uses one API call to get the provider's total repo count,
// compares it to the DB and cache, then picks the cheapest path to completeness:
//
//  1. DB count == provider total AND all cache is fresh → restore from DB only (0 extra API calls).
//  2. DB count == provider total BUT some cache is stale/missing → restore what we have from DB,
//     then fetch only the missing repos (no pagination needed).
//  3. DB count < provider total (or count unknown) → full paginated sync.
func warmProviderSmart(ctx context.Context, db *gorm.DB, store *providerconfig.Store, c cache.Store, p providerconfig.ProviderInstance) {
	ttl := providerTTL(p)
	freshSince := time.Now().Add(-ttl)

	token, _ := store.GetActiveToken(ctx, p.ID)
	client := providerconfig.NewProviderClient(p.Type, p.BaseURL, token)

	// 1 API call to get the provider's total repo count.
	providerTotal := -1
	if client != nil {
		if count, err := client.CountRepos(ctx, p.OwnerPath); err == nil {
			providerTotal = count
		} else {
			log.Printf("cache warmer: %s count error: %v", p.DisplayName, err)
		}
	}

	dbCount, err := assets.CountReposByProvider(ctx, db, p.ID)
	if err != nil {
		log.Printf("cache warmer: %s db count error: %v", p.DisplayName, err)
	}
	freshCount, err := assets.CountFreshRepoCacheByProvider(ctx, db, p.ID, freshSince)
	if err != nil {
		log.Printf("cache warmer: %s fresh count error: %v", p.DisplayName, err)
	}

	log.Printf("cache warmer: %s — provider=%d db=%d fresh=%d/%d",
		p.DisplayName, providerTotal, dbCount, freshCount, dbCount)

	// Case 1: all provider repos are cached and fresh (DB may have extra stale rows
	// from repos deleted/made-private on the provider) — restore from DB only.
	if providerTotal >= 0 && freshCount >= int64(providerTotal) {
		if rebuildFromDB(ctx, db, c, p, ttl) {
			log.Printf("cache warmer: %s fully restored from DB", p.DisplayName)
			return
		}
	}

	// Case 2: DB has at least as many repos as provider but some cache is missing/stale.
	if providerTotal >= 0 && dbCount >= int64(providerTotal) && freshCount < int64(providerTotal) {
		rebuildFromDB(ctx, db, c, p, ttl) // restore what we can
		missing := int64(providerTotal) - freshCount
		log.Printf("cache warmer: %s filling %d stale/missing cache entries", p.DisplayName, missing)
		warmMissingCache(ctx, db, c, p, token, freshSince)
		return
	}

	// Case 3a: count call failed (e.g. rate limited) but DB has repos — use DB as
	// source of truth and fill missing cache entries without pagination.
	if providerTotal < 0 && dbCount > 0 {
		rebuildFromDB(ctx, db, c, p, ttl)
		if freshCount < dbCount {
			log.Printf("cache warmer: %s count unavailable, filling %d stale/missing from DB", p.DisplayName, dbCount-freshCount)
			warmMissingCache(ctx, db, c, p, token, freshSince)
		}
		return
	}

	// Case 3b: DB is out of date or first run — full paginated sync.
	warmProvider(ctx, db, store, c, p, false)
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
		_ = cache.SetJSON(ctx, c, "provider:repos:"+p.ID, repoList, repoListTTL)
	}

	return true
}

// warmProvider syncs a provider in two phases:
//  1. Discover: paginate all repos, upsert identity to DB, refresh in-memory list.
//  2. Enrich: fill missing/stale per-repo cache (details, readme, commits, contributors).
//
// Splitting the phases makes syncs resilient to rate limits — if enrichment is
// interrupted, the next cycle skips discovery (DB already up to date) and resumes
// enrichment from where it left off.
// Set forceRefresh to true to re-fetch details for all repos, not just stale ones.
func warmProvider(ctx context.Context, db *gorm.DB, store *providerconfig.Store, c cache.Store, p providerconfig.ProviderInstance, forceRefresh bool) {
	token, err := store.GetActiveToken(ctx, p.ID)
	if err != nil {
		return
	}
	client := providerconfig.NewProviderClient(p.Type, p.BaseURL, token)
	if client == nil {
		return
	}

	// Phase 1: discover all repos and persist identity to DB.
	if err := discoverRepos(ctx, db, c, p, token, client); err != nil {
		log.Printf("cache warmer: %s discover failed: %v", p.DisplayName, err)
		return
	}

	// Phase 2: enrich repos without fresh cache.
	freshSince := time.Now().Add(-providerTTL(p))
	if forceRefresh {
		freshSince = time.Now() // treat everything as stale
	}
	warmMissingCache(ctx, db, c, p, token, freshSince)
}

// discoverRepos paginates all repos from the provider, upserts their identity
// into the repos table, and updates the in-memory repo list.
func discoverRepos(ctx context.Context, db *gorm.DB, c cache.Store, p providerconfig.ProviderInstance, token string, client providers.Client) error {
	var allRepos []providers.RepoData
	page := 1
	for {
		repos, pageInfo, err := client.ListPublicRepos(ctx, p.OwnerPath, providers.ListOptions{
			Page:     page,
			PageSize: 100,
		})
		if err != nil {
			log.Printf("cache warmer: %s list page %d: %v", p.DisplayName, page, err)
			return err
		}
		allRepos = append(allRepos, repos...)
		if !pageInfo.HasNextPage {
			break
		}
		page++
	}

	if len(allRepos) == 0 {
		return nil
	}

	// Update in-memory list immediately so the UI sees fresh data.
	_ = cache.SetJSON(ctx, c, "provider:repos:"+p.ID, allRepos, repoListTTL)

	// Upsert all repos to DB (identity only — no detail fetching yet).
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
		providerUpdatedAt := repo.PushedAt
		if providerUpdatedAt.IsZero() {
			providerUpdatedAt = repo.UpdatedAt
		}
		var providerUpdatedAtPtr *time.Time
		if !providerUpdatedAt.IsZero() {
			providerUpdatedAtPtr = &providerUpdatedAt
		}
		if _, err := assets.UpsertRepo(ctx, db, assets.RepoInput{
			Provider:           p.Type,
			ProviderInstanceID: p.ID,
			Org:                org,
			Slug:               slug,
			ExternalID:         repo.ExternalID,
			ProviderUpdatedAt:  providerUpdatedAtPtr,
		}); err != nil {
			log.Printf("cache warmer: %s upsert %s: %v", p.DisplayName, path, err)
		}
	}

	log.Printf("cache warmer: %s discovered %d repos", p.DisplayName, len(allRepos))
	return nil
}

// fetchRepoFullData fetches details, readme, commits, and contributors for a
// single repo in parallel (4 concurrent provider API calls).
// Returns the error from the details fetch so callers can distinguish 429 from 404.
func fetchRepoFullData(ctx context.Context, p providerconfig.ProviderInstance, token, repoPath string,
	details **providers.RepoDetails, readme *string, commits *[]providers.CommitInfo, contribs *[]providers.ContributorInfo,
) error {
	if repoPath == "" {
		return fmt.Errorf("empty repo path")
	}
	var wg sync.WaitGroup
	var detailsErr error

	switch p.Type {
	case providerconfig.ProviderGitHub:
		parts := strings.SplitN(repoPath, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid path: %s", repoPath)
		}
		cl := providers.NewGitHubClient(githubAPIBaseURL(p.BaseURL), token)
		wg.Add(4)
		go func() { defer wg.Done(); *details, detailsErr = cl.GetRepoDetails(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *readme, _ = cl.GetReadme(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *commits, _ = cl.GetCommitLog(ctx, parts[0], parts[1], 10) }()
		go func() { defer wg.Done(); *contribs, _ = cl.GetContributors(ctx, repoPath, 30) }()

	case providerconfig.ProviderGitLab:
		cl := providers.NewGitLabClient(p.BaseURL, token)
		wg.Add(4)
		go func() { defer wg.Done(); *details, detailsErr = cl.GetRepoDetails(ctx, repoPath) }()
		go func() { defer wg.Done(); *readme, _ = cl.GetReadme(ctx, repoPath) }()
		go func() { defer wg.Done(); *commits, _ = cl.GetCommitLog(ctx, repoPath, 10) }()
		go func() { defer wg.Done(); *contribs, _ = cl.GetContributors(ctx, repoPath, 30) }()

	case providerconfig.ProviderGitea, providerconfig.ProviderForgejo:
		parts := strings.SplitN(repoPath, "/", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid path: %s", repoPath)
		}
		cl := providers.NewGiteaClient(p.BaseURL, token)
		wg.Add(4)
		go func() { defer wg.Done(); *details, detailsErr = cl.GetRepoDetails(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *readme, _ = cl.GetReadme(ctx, parts[0], parts[1]) }()
		go func() { defer wg.Done(); *commits, _ = cl.GetCommitLog(ctx, parts[0], parts[1], 10) }()
		go func() { defer wg.Done(); *contribs, _ = cl.GetContributors(ctx, repoPath, 30) }()
	}

	wg.Wait()
	return detailsErr
}

// warmMissingCache fetches and persists cache entries only for repos that are
// missing or stale — no pagination, no re-discovery, just targeted gap-filling.
// Uses a conservative 500ms delay between repos to avoid rate-limit (429) errors.
func warmMissingCache(ctx context.Context, db *gorm.DB, c cache.Store, p providerconfig.ProviderInstance, token string, freshSince time.Time) {
	repos, err := assets.ListReposWithStaleCacheByProvider(ctx, db, p.ID, freshSince)
	if err != nil {
		log.Printf("cache warmer: %s list stale repos: %v", p.DisplayName, err)
		return
	}
	if len(repos) == 0 {
		return
	}

	ttl := providerTTL(p)
	fetched := 0

	skipped := 0
	for _, repo := range repos {
		path := repo.Org + "/" + repo.Slug

		// If the repo hasn't been pushed since the last cache entry and the
		// cache isn't older than maxRepoCacheAge, restore from DB — no API call.
		if dbCache, err := assets.GetRepoCache(ctx, db, repo.ID); err == nil {
			providerUpdatedAt := repo.ProviderUpdatedAt
			repoUnchanged := providerUpdatedAt != nil && !providerUpdatedAt.After(dbCache.SyncedAt)
			cacheStale := time.Since(dbCache.SyncedAt) >= maxRepoCacheAge
			if repoUnchanged && !cacheStale {
				detailsCacheKey := fmt.Sprintf("provider:details:%s:%s", p.ID, strings.Trim(path, "/"))
				if _, ok, _ := cache.GetJSON[RepoDetailsResponse](ctx, c, detailsCacheKey); !ok {
					var details providers.RepoDetails
					var commits []providers.CommitInfo
					var contribs []providers.ContributorInfo
					if json.Unmarshal([]byte(dbCache.DetailsJSON), &details) == nil {
						_ = json.Unmarshal([]byte(dbCache.CommitsJSON), &commits)
						_ = json.Unmarshal([]byte(dbCache.ContributorsJSON), &contribs)
						resp := RepoDetailsResponse{Details: &details, Readme: dbCache.ReadmeContent, Commits: commits, Contributors: contribs}
						_ = cache.SetJSON(ctx, c, detailsCacheKey, resp, ttl)
						_ = cache.SetJSON(ctx, c, fmt.Sprintf("contributors:%s", repo.ID), RepoContributorsResponse{Contributors: contribs}, ttl)
					}
				}
				skipped++
				continue
			}
		}

		var details *providers.RepoDetails
		var readme string
		var commits []providers.CommitInfo
		var contribs []providers.ContributorInfo

		if err := fetchRepoFullData(ctx, p, token, path, &details, &readme, &commits, &contribs); err != nil {
			if err == providers.ErrRateLimited {
				log.Printf("cache warmer: %s rate limited — stopping fill, will retry next cycle", p.DisplayName)
				break
			}
			log.Printf("cache warmer: %s skip %s: %v", p.DisplayName, path, err)
			continue
		}

		if contribs == nil {
			contribs = []providers.ContributorInfo{}
		}
		if commits == nil {
			commits = []providers.CommitInfo{}
		}
		contribs = enrichContributors(contribs, commits)
		commits = enrichCommits(commits, contribs)
		if details.Stats.Contributors == 0 && len(contribs) > 0 {
			details.Stats.Contributors = len(contribs)
		}

		detailsBytes, _ := json.Marshal(details)
		commitsBytes, _ := json.Marshal(commits)
		contribsBytes, _ := json.Marshal(contribs)
		if dbErr := assets.UpsertRepoCache(ctx, db, repo.ID,
			string(detailsBytes), readme, string(commitsBytes), string(contribsBytes),
		); dbErr != nil {
			log.Printf("cache warmer: %s persist cache %s: %v", p.DisplayName, path, dbErr)
		}

		detailsCacheKey := fmt.Sprintf("provider:details:%s:%s", p.ID, strings.Trim(path, "/"))
		contribCacheKey := fmt.Sprintf("contributors:%s", repo.ID)
		resp := RepoDetailsResponse{Details: details, Readme: readme, Commits: commits, Contributors: contribs}
		_ = cache.SetJSON(ctx, c, detailsCacheKey, resp, ttl)
		_ = cache.SetJSON(ctx, c, contribCacheKey, RepoContributorsResponse{Contributors: contribs}, ttl)

		fetched++
		// Conservative throttle to stay well under provider rate limits.
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("cache warmer: %s fill done — %d fetched, %d skipped (unchanged), %d total", p.DisplayName, fetched, skipped, len(repos))
}
