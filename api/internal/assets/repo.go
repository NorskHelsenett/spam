package assets

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/dbutil"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RepoInput struct {
	Provider           string
	ProviderInstanceID string
	Org                string
	Slug               string
	ExternalID         string
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
			if input.ProviderUpdatedAt != nil && !input.ProviderUpdatedAt.IsZero() {
				updates["provider_updated_at"] = input.ProviderUpdatedAt
			}
			if len(updates) > 0 {
				db.WithContext(ctx).Model(&repo).Updates(updates)
				repo.Org = org
				repo.Slug = slug
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
	if len(updates) > 0 {
		db.WithContext(ctx).Model(&repo).Updates(updates)
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

// UpsertRepoCache saves or updates cached provider data for a repo.
// All string fields are sanitized to valid UTF-8 before storage because
// provider READMEs and commit messages may contain non-UTF-8 bytes or null bytes.
func UpsertRepoCache(ctx context.Context, db *gorm.DB, repoID, detailsJSON, readmeContent, commitsJSON, contributorsJSON string) error {
	rc := &RepoCache{
		RepoID:           repoID,
		DetailsJSON:      sanitizeForDB(detailsJSON),
		ReadmeContent:    sanitizeForDB(readmeContent),
		CommitsJSON:      sanitizeForDB(commitsJSON),
		ContributorsJSON: sanitizeForDB(contributorsJSON),
		SyncedAt:         time.Now(),
	}
	return db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "repo_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"details_json", "readme_content", "commits_json", "contributors_json", "synced_at",
			}),
		}).
		Create(rc).Error
}

// GetRepoCache retrieves the cached provider data for a repo.
// Returns gorm.ErrRecordNotFound if no entry exists.
func GetRepoCache(ctx context.Context, db *gorm.DB, repoID string) (*RepoCache, error) {
	var rc RepoCache
	if err := db.WithContext(ctx).First(&rc, "repo_id = ?", repoID).Error; err != nil {
		return nil, err
	}
	return &rc, nil
}

// CountReposByProvider returns the number of repos for a provider instance.
func CountReposByProvider(ctx context.Context, db *gorm.DB, providerInstanceID string) (int64, error) {
	var count int64
	err := db.WithContext(ctx).Model(&Repo{}).
		Where("provider_instance_id = ?", providerInstanceID).
		Count(&count).Error
	return count, err
}

// CountFreshRepoCacheByProvider returns the number of cache entries synced after freshSince.
func CountFreshRepoCacheByProvider(ctx context.Context, db *gorm.DB, providerInstanceID string, freshSince time.Time) (int64, error) {
	var count int64
	err := db.WithContext(ctx).Table("repo_caches").
		Joins("JOIN repos ON repos.id = repo_caches.repo_id").
		Where("repos.provider_instance_id = ? AND repo_caches.synced_at > ?", providerInstanceID, freshSince).
		Count(&count).Error
	return count, err
}

// ListReposWithStaleCacheByProvider returns repos whose cache is missing or older than freshSince.
func ListReposWithStaleCacheByProvider(ctx context.Context, db *gorm.DB, providerInstanceID string, freshSince time.Time) ([]Repo, error) {
	var repos []Repo
	err := db.WithContext(ctx).
		Joins("LEFT JOIN repo_caches ON repo_caches.repo_id = repos.id AND repo_caches.synced_at > ?", freshSince).
		Where("repos.provider_instance_id = ?", providerInstanceID).
		Where("repo_caches.repo_id IS NULL").
		Find(&repos).Error
	return repos, err
}

// ListRepoCacheByProvider returns all cache entries for repos belonging to a provider instance.
func ListRepoCacheByProvider(ctx context.Context, db *gorm.DB, providerInstanceID string) ([]RepoCache, error) {
	var caches []RepoCache
	err := db.WithContext(ctx).
		Joins("JOIN repos ON repos.id = repo_caches.repo_id").
		Where("repos.provider_instance_id = ?", providerInstanceID).
		Find(&caches).Error
	return caches, err
}

func FindRepo(ctx context.Context, db *gorm.DB, repoID string) (*Repo, error) {
	var repo Repo
	if err := db.WithContext(ctx).First(&repo, "id = ?", repoID).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

func FindRepoCommit(ctx context.Context, db *gorm.DB, commitID string) (*RepoCommit, error) {
	var commit RepoCommit
	if err := db.WithContext(ctx).First(&commit, "id = ?", commitID).Error; err != nil {
		return nil, err
	}
	return &commit, nil
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
