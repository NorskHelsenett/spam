package assets

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
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

	var repo Repo
	result := db.WithContext(ctx).Where(Repo{
		Provider: provider,
		Org:      input.Org,
		Slug:     input.Slug,
	}).Attrs(Repo{
		ID:              uuid.NewString(),
		CreatedByUserID: input.CreatedByUserID,
	}).FirstOrCreate(&repo)

	if result.Error != nil {
		return nil, result.Error
	}
	return &repo, nil
}

func UpsertRepoCommit(ctx context.Context, db *gorm.DB, input RepoCommitInput) (*RepoCommit, error) {
	if input.RepoID == "" || input.CommitSHA == "" {
		return nil, errors.New("repo id and commit sha required")
	}

	var commit RepoCommit
	result := db.WithContext(ctx).Where(RepoCommit{
		RepoID:    input.RepoID,
		CommitSHA: input.CommitSHA,
	}).Attrs(RepoCommit{
		ID:  uuid.NewString(),
		Ref: input.Ref,
	}).FirstOrCreate(&commit)

	if result.Error != nil {
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
