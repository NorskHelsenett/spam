package assets

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

// isDuplicateKeyError returns true when a Postgres unique-constraint violation
// (SQLSTATE 23505) caused the error, which can happen when concurrent
// FirstOrCreate calls race.
func isDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

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
	where := Repo{
		Provider: provider,
		Org:      input.Org,
		Slug:     input.Slug,
	}
	result := db.WithContext(ctx).Where(where).Attrs(Repo{
		ID:              uuid.NewString(),
		CreatedByUserID: input.CreatedByUserID,
	}).FirstOrCreate(&repo)

	if result.Error != nil {
		// Handle race condition: another request inserted the same row
		// between our SELECT and INSERT. Retry with a plain lookup.
		if isDuplicateKeyError(result.Error) {
			if err := db.WithContext(ctx).Where(where).First(&repo).Error; err != nil {
				return nil, err
			}
			return &repo, nil
		}
		return nil, result.Error
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
		if isDuplicateKeyError(result.Error) {
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
