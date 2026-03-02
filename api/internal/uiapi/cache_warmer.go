package uiapi

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/providers"
	"gorm.io/gorm"
)

// WarmCache pre-populates the in-memory cache on startup for all enabled
// providers: repos are indexed and contributor lists are fetched and stored.
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
			warmProvider(ctx, db, store, c, p)
		}

		log.Printf("cache warmer: done")
	}()
}

func warmProvider(ctx context.Context, db *gorm.DB, store *providerconfig.Store, c cache.Store, p providerconfig.ProviderInstance) {
	token, err := store.GetActiveToken(ctx, p.ID)
	if err != nil || token == "" {
		return
	}

	client := providerconfig.NewProviderClient(p.Type, p.BaseURL, token)
	if client == nil {
		return
	}

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

	log.Printf("cache warmer: warming %d repos for %s", len(allRepos), p.DisplayName)

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

		// Index the repo with provider's last-activity date.
		providerUpdatedAt := repo.PushedAt
		if providerUpdatedAt.IsZero() {
			providerUpdatedAt = repo.UpdatedAt
		}
		var providerUpdatedAtPtr *time.Time
		if !providerUpdatedAt.IsZero() {
			providerUpdatedAtPtr = &providerUpdatedAt
		}
		if _, err := assets.UpsertRepo(ctx, db, assets.RepoInput{
			Provider:          p.Type,
			Org:               org,
			Slug:              slug,
			ProviderUpdatedAt: providerUpdatedAtPtr,
		}); err != nil {
			log.Printf("cache warmer: upsert repo %s: %v", path, err)
			continue
		}

		// Pre-fetch and cache contributors.
		repoID := fmt.Sprintf("%s:%s:%s", p.Type, org, slug)
		cacheKey := fmt.Sprintf("contributors:%s", repoID)
		if _, ok, _ := cache.GetJSON[RepoContributorsResponse](ctx, c, cacheKey); ok {
			continue // already cached
		}

		contribs, err := client.GetContributors(ctx, repo.FullPath, 5)
		if err != nil {
			contribs = []providers.ContributorInfo{}
		}
		if contribs == nil {
			contribs = []providers.ContributorInfo{}
		}

		resp := RepoContributorsResponse{Contributors: contribs}
		_ = cache.SetJSON(ctx, c, cacheKey, resp, contributorCacheTTL)

		// Throttle to avoid hammering provider APIs.
		time.Sleep(200 * time.Millisecond)
	}
}
