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

	var repo Repo
	result := db.WithContext(ctx).
		Where("provider_instance_id = ? AND org = ? AND slug = ?", providerInstanceID, org, slug).
		Attrs(Repo{
			ID:                 uuid.NewString(),
			Provider:           provider,
			Org:                org,
			Slug:               slug,
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

	if input.ProviderUpdatedAt != nil && !input.ProviderUpdatedAt.IsZero() {
		db.WithContext(ctx).Model(&repo).UpdateColumn("provider_updated_at", input.ProviderUpdatedAt)
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

// UpsertRepoCache saves or updates cached provider data for a repo.
// All string fields are sanitized to valid UTF-8 before storage because
// provider READMEs and commit messages may contain non-UTF-8 bytes.
func UpsertRepoCache(ctx context.Context, db *gorm.DB, repoID, detailsJSON, readmeContent, commitsJSON, contributorsJSON string) error {
	rc := &RepoCache{
		RepoID:           repoID,
		DetailsJSON:      strings.ToValidUTF8(detailsJSON, ""),
		ReadmeContent:    strings.ToValidUTF8(readmeContent, ""),
		CommitsJSON:      strings.ToValidUTF8(commitsJSON, ""),
		ContributorsJSON: strings.ToValidUTF8(contributorsJSON, ""),
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
