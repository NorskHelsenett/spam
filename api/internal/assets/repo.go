package assets

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/dbutil"
	"github.com/google/uuid"
	"gorm.io/gorm"
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
	if input.Org == "" || input.Slug == "" {
		return nil, errors.New("org and slug required")
	}

	var repo Repo
	var where Repo
	var providerInstanceIDPtr *string
	if input.ProviderInstanceID != "" {
		providerInstanceIDPtr = &input.ProviderInstanceID
		where = Repo{
			ProviderInstanceID: providerInstanceIDPtr,
			Org:                input.Org,
			Slug:               input.Slug,
		}
	} else {
		where = Repo{
			Provider: provider,
			Org:      input.Org,
			Slug:     input.Slug,
		}
	}

	result := db.WithContext(ctx).Where(where).Attrs(Repo{
		ID:                 uuid.NewString(),
		Provider:           provider,
		ProviderInstanceID: providerInstanceIDPtr,
		CreatedByUserID:    input.CreatedByUserID,
	}).FirstOrCreate(&repo)

	if result.Error != nil {
		// Handle race condition: another request inserted the same row
		// between our SELECT and INSERT. Retry with a plain lookup.
		if dbutil.IsDuplicateKeyError(result.Error) {
			if err := db.WithContext(ctx).Where(where).First(&repo).Error; err != nil {
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
