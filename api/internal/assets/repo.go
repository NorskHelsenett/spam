package assets

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/dbutil"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RepoCacheKey returns the kv_store key for a repo's provider cache entry.
func RepoCacheKey(repoID string) string { return "repo:cache:" + repoID }

type RepoInput struct {
	Provider           string
	ProviderInstanceID string
	Org                string
	Slug               string
	ExternalID         string
	IsPrivate          *bool
	CreatedByUserID    string
	ProviderUpdatedAt  *time.Time
}

type RepoCommitInput struct {
	RepoID    string
	CommitSHA string
	Ref       string
}

func UpsertRepo(ctx context.Context, db *gorm.DB, input RepoInput) (*Repo, error) {
	provider := strings.TrimSpace(input.Provider)
	if provider == "" {
		provider = "manual"
	}
	org := strings.TrimSpace(input.Org)
	slug := strings.TrimSpace(input.Slug)
	providerInstanceID := strings.TrimSpace(input.ProviderInstanceID)

	if org == "" || slug == "" {
		return nil, errors.New("org and slug required")
	}
	if providerInstanceID == "" {
		return nil, errors.New("provider instance id required")
	}

	externalID := strings.TrimSpace(input.ExternalID)

	var repo Repo

	// When externalID is known, use it as the canonical key so that a previously
	// truncated org/slug gets corrected rather than a duplicate entry being created.
	if externalID != "" {
		err := db.WithContext(ctx).
			Where("provider_instance_id = ? AND external_id = ?", providerInstanceID, externalID).
			First(&repo).Error
		if err == nil {
			// Found by external ID — update path if it was truncated/stale.
			updates := map[string]any{}
			if repo.Org != org || repo.Slug != slug {
				updates["org"] = org
				updates["slug"] = slug
			}
			if input.IsPrivate != nil && repo.IsPrivate != *input.IsPrivate {
				updates["is_private"] = *input.IsPrivate
			}
			if input.ProviderUpdatedAt != nil && !input.ProviderUpdatedAt.IsZero() {
				updates["provider_updated_at"] = input.ProviderUpdatedAt
			}
			if len(updates) > 0 {
				db.WithContext(ctx).Model(&repo).Updates(updates)
				repo.Org = org
				repo.Slug = slug
				if input.IsPrivate != nil {
					repo.IsPrivate = *input.IsPrivate
				}
			}
			return &repo, nil
		}
	}

	result := db.WithContext(ctx).
		Where("provider_instance_id = ? AND org = ? AND slug = ?", providerInstanceID, org, slug).
		Attrs(Repo{
			ID:                 uuid.NewString(),
			Provider:           provider,
			Org:                org,
			Slug:               slug,
			ExternalID:         externalID,
			IsPrivate:          input.IsPrivate != nil && *input.IsPrivate,
			ProviderInstanceID: providerInstanceID,
			CreatedByUserID:    input.CreatedByUserID,
		}).FirstOrCreate(&repo)

	if result.Error != nil {
		// Handle race condition: another request inserted the same row
		// between our SELECT and INSERT. Retry with a plain lookup.
		if dbutil.IsDuplicateKeyError(result.Error) {
			if err := db.WithContext(ctx).Where("provider_instance_id = ? AND org = ? AND slug = ?", providerInstanceID, org, slug).First(&repo).Error; err != nil {
				return nil, err
			}
			return &repo, nil
		}
		return nil, result.Error
	}

	updates := map[string]any{}
	if input.ProviderUpdatedAt != nil && !input.ProviderUpdatedAt.IsZero() {
		updates["provider_updated_at"] = input.ProviderUpdatedAt
	}
	if externalID != "" && repo.ExternalID != externalID {
		updates["external_id"] = externalID
	}
	if input.IsPrivate != nil && repo.IsPrivate != *input.IsPrivate {
		updates["is_private"] = *input.IsPrivate
	}
	if len(updates) > 0 {
		db.WithContext(ctx).Model(&repo).Updates(updates)
	}

	// When we just inserted a new repo, opportunistically relink any
	// previously-scanned images whose OCI source label points at it.
	// No-op for the far more common "already existed" case so this
	// doesn't slow down every provider-sync tick.
	if result.RowsAffected == 1 {
		if _, err := imagescan.RelinkRepoImages(ctx, db, repo.ID); err != nil {
			// Non-fatal — the periodic backfill (or a future image
			// upload) will still converge.
			_ = err
		}
		// Apply provider default_grants so newly-discovered repos
		// don't become invisible to every non-admin. The helper is
		// best-effort: grant insertion failures are logged, not
		// propagated.
		acl.ApplyIngestDefaults(ctx, db, providerInstanceID, acl.RepoIdentity{
			Provider:           provider,
			ProviderInstanceID: providerInstanceID,
			Owner:              org,
			Slug:               slug,
		})
	}

	return &repo, nil
}

func UpsertRepoCommit(ctx context.Context, db *gorm.DB, input RepoCommitInput) (*RepoCommit, error) {
	if input.RepoID == "" || input.CommitSHA == "" {
		return nil, errors.New("repo id and commit sha required")
	}

	var commit RepoCommit
	where := RepoCommit{
		RepoID:    input.RepoID,
		CommitSHA: input.CommitSHA,
	}
	result := db.WithContext(ctx).Where(where).Attrs(RepoCommit{
		ID:  uuid.NewString(),
		Ref: input.Ref,
	}).FirstOrCreate(&commit)

	if result.Error != nil {
		if dbutil.IsDuplicateKeyError(result.Error) {
			if err := db.WithContext(ctx).Where(where).First(&commit).Error; err != nil {
				return nil, err
			}
			return &commit, nil
		}
		return nil, result.Error
	}
	return &commit, nil
}

// sanitizeForDB removes null bytes and invalid UTF-8 sequences that PostgreSQL
// rejects in text columns. 0x00 is valid UTF-8 but Postgres TEXT forbids it.
func sanitizeForDB(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", ""), "")
}

// UpsertRepoCache saves or updates cached provider data for a repo in kv_store.
// All string fields are sanitized to remove null bytes and invalid UTF-8.
func UpsertRepoCache(ctx context.Context, c cache.Store, repoID, detailsJSON, readmeContent, commitsJSON, contributorsJSON string) error {
	data := RepoCacheData{
		DetailsJSON:      sanitizeForDB(detailsJSON),
		ReadmeContent:    sanitizeForDB(readmeContent),
		CommitsJSON:      sanitizeForDB(commitsJSON),
		ContributorsJSON: sanitizeForDB(contributorsJSON),
		SyncedAt:         time.Now(),
	}
	return cache.SetJSON(ctx, c, RepoCacheKey(repoID), data, MaxRepoCacheAge)
}

// GetRepoCache retrieves the cached provider data for a repo from kv_store.
// Returns (nil, gorm.ErrRecordNotFound) when no entry exists.
func GetRepoCache(ctx context.Context, c cache.Store, repoID string) (*RepoCacheData, error) {
	data, ok, err := cache.GetJSON[RepoCacheData](ctx, c, RepoCacheKey(repoID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return &data, nil
}

// CountReposByProvider returns the number of repos for a provider instance.
func CountReposByProvider(ctx context.Context, db *gorm.DB, providerInstanceID string) (int64, error) {
	var count int64
	err := db.WithContext(ctx).Model(&Repo{}).
		Where("provider_instance_id = ?", providerInstanceID).
		Count(&count).Error
	return count, err
}

// CountFreshRepoCacheByProvider returns the number of repos with a cache entry
// whose SyncedAt is after freshSince, using kv_store for cache lookups.
// Note: performs one kv_store lookup per repo (N+1); acceptable since this
// runs on background warm paths, not hot request paths.
func CountFreshRepoCacheByProvider(ctx context.Context, db *gorm.DB, c cache.Store, providerInstanceID string, freshSince time.Time) (int64, error) {
	var repoIDs []string
	if err := db.WithContext(ctx).Model(&Repo{}).
		Where("provider_instance_id = ?", providerInstanceID).
		Pluck("id", &repoIDs).Error; err != nil {
		return 0, err
	}
	var count int64
	for _, id := range repoIDs {
		entry, ok, _ := cache.GetJSON[RepoCacheData](ctx, c, RepoCacheKey(id))
		if ok && entry.SyncedAt.After(freshSince) {
			count++
		}
	}
	return count, nil
}

// ListReposWithStaleCacheByProvider returns repos whose cache is missing or
// whose SyncedAt is not after freshSince, using kv_store for cache lookups.
// Note: performs one kv_store lookup per repo (N+1); acceptable since this
// runs on background warm paths, not hot request paths.
func ListReposWithStaleCacheByProvider(ctx context.Context, db *gorm.DB, c cache.Store, providerInstanceID string, freshSince time.Time) ([]Repo, error) {
	var repos []Repo
	if err := db.WithContext(ctx).
		Where("provider_instance_id = ?", providerInstanceID).
		Find(&repos).Error; err != nil {
		return nil, err
	}
	var stale []Repo
	for _, repo := range repos {
		entry, ok, _ := cache.GetJSON[RepoCacheData](ctx, c, RepoCacheKey(repo.ID))
		if !ok || !entry.SyncedAt.After(freshSince) {
			stale = append(stale, repo)
		}
	}
	return stale, nil
}

// ListRepoCacheByProvider returns all kv_store cache entries for repos
// belonging to a provider instance.
func ListRepoCacheByProvider(ctx context.Context, db *gorm.DB, c cache.Store, providerInstanceID string) ([]RepoCacheEntry, error) {
	var repos []Repo
	if err := db.WithContext(ctx).
		Where("provider_instance_id = ?", providerInstanceID).
		Find(&repos).Error; err != nil {
		return nil, err
	}
	var entries []RepoCacheEntry
	for _, repo := range repos {
		data, ok, _ := cache.GetJSON[RepoCacheData](ctx, c, RepoCacheKey(repo.ID))
		if ok {
			entries = append(entries, RepoCacheEntry{RepoID: repo.ID, RepoCacheData: data})
		}
	}
	return entries, nil
}

func FindRepo(ctx context.Context, db *gorm.DB, repoID string) (*Repo, error) {
	var repo Repo
	if err := db.WithContext(ctx).First(&repo, "id = ?", repoID).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

// FindRepoByCommitSHA looks up a repo via the repo_commits table using the commit hash.
// Returns the first matching repo if multiple repos share the same commit (e.g. forks).
func FindRepoByCommitSHA(ctx context.Context, db *gorm.DB, commitSHA string) (*Repo, error) {
	var repo Repo
	err := db.WithContext(ctx).
		Joins("JOIN repo_commits ON repo_commits.repo_id = repos.id").
		Where("repo_commits.commit_sha = ?", commitSHA).
		First(&repo).Error
	if err != nil {
		return nil, err
	}
	return &repo, nil
}
