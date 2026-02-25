package dbutil

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// IsDuplicateKeyError returns true when a Postgres unique-constraint violation
// (SQLSTATE 23505) caused the error, which can happen when concurrent
// FirstOrCreate calls race.
func IsDuplicateKeyError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
