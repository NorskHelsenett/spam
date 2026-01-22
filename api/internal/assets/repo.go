package assets

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RepoInput struct {
	Provider        string
	Org             string
	Slug            string
	CreatedByUserID string
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

	repo := Repo{
		ID:              uuid.NewString(),
		Provider:        provider,
		Org:             input.Org,
		Slug:            input.Slug,
		CreatedByUserID: input.CreatedByUserID,
	}

	result := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "provider"}, {Name: "org"}, {Name: "slug"}},
		DoNothing: true,
	}).Create(&repo)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		if err := db.WithContext(ctx).Where("provider = ? AND org = ? AND slug = ?", provider, input.Org, input.Slug).First(&repo).Error; err != nil {
			return nil, err
		}
	}

	return &repo, nil
}

func UpsertRepoCommit(ctx context.Context, db *gorm.DB, input RepoCommitInput) (*RepoCommit, error) {
	if input.RepoID == "" || input.CommitSHA == "" {
		return nil, errors.New("repo id and commit sha required")
	}

	commit := RepoCommit{
		ID:        uuid.NewString(),
		RepoID:    input.RepoID,
		CommitSHA: input.CommitSHA,
		Ref:       input.Ref,
	}

	result := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "repo_id"}, {Name: "commit_sha"}},
		DoNothing: true,
	}).Create(&commit)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		if err := db.WithContext(ctx).Where("repo_id = ? AND commit_sha = ?", input.RepoID, input.CommitSHA).First(&commit).Error; err != nil {
			return nil, err
		}
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
