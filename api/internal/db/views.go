package db

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/gorm"
)

// ViewSchemaVersion tracks the SQL hash of each managed materialized view so
// that the view is only dropped and recreated when its definition changes.
type ViewSchemaVersion struct {
	Name string `gorm:"primaryKey"`
	Hash string
}

// sbomViewRefreshLockID is a stable advisory lock key used to ensure only one
// replica refreshes the SBOM materialized views at a time.
const sbomViewRefreshLockID = 8_742_635_912

// EnsureViews applies SQL view definitions from the provided file paths.
// Each file is hashed; the view is only dropped and recreated when the hash
// differs from what is stored in view_schema_versions. A PostgreSQL advisory
// lock serialises concurrent replicas so only one does the work.
func EnsureViews(ctx context.Context, db *gorm.DB, paths ...string) error {
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read view sql %s: %w", path, err)
		}
		if len(payload) == 0 {
			continue
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(payload))

		if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			sum := sha256.Sum256([]byte(path))
			lockKey := int64(binary.BigEndian.Uint64(sum[:8]))
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", lockKey).Error; err != nil {
				return fmt.Errorf("acquire advisory lock: %w", err)
			}

			var stored ViewSchemaVersion
			result := tx.First(&stored, "name = ?", path)
			if result.Error == nil && stored.Hash == hash {
				return nil // view definition unchanged, skip
			}

			if err := tx.Exec(string(payload)).Error; err != nil {
				return fmt.Errorf("exec view sql %s: %w", path, err)
			}

			return tx.Save(&ViewSchemaVersion{Name: path, Hash: hash}).Error
		}); err != nil {
			return fmt.Errorf("ensure view %s: %w", path, err)
		}
	}
	return nil
}

// EnsureViewsPopulated blocks until all SBOM materialized views are populated.
// It must be called at startup before the HTTP server begins serving traffic.
// One replica performs the refresh; others poll until it completes.
// The refresh itself runs under context.Background() so a SIGTERM does not abort
// it mid-way; the caller's ctx is only used for the polling loop. This means a
// SIGTERM during an in-progress refresh will wait for it to finish before the
// server shuts down.
func EnsureViewsPopulated(ctx context.Context, db *gorm.DB) error {
	refreshCtx := context.Background()
	for {
		populated, err := viewsPopulated(ctx, db)
		if err != nil {
			return err
		}
		if populated {
			return nil
		}

		// Try to be the replica that does the refresh. Transaction-scoped advisory
		// lock ensures the same connection is used for lock + refresh + unlock.
		if err := db.WithContext(refreshCtx).Transaction(func(tx *gorm.DB) error {
			var acquired bool
			if err := tx.Raw("SELECT pg_try_advisory_xact_lock(?)", sbomViewRefreshLockID).Scan(&acquired).Error; err != nil || !acquired {
				return nil // another replica is refreshing, we will poll
			}
			if err := tx.Exec("REFRESH MATERIALIZED VIEW sbom_component_view").Error; err != nil {
				return fmt.Errorf("refresh sbom_component_view: %w", err)
			}
			if err := tx.Exec("REFRESH MATERIALIZED VIEW sbom_metadata_view").Error; err != nil {
				return fmt.Errorf("refresh sbom_metadata_view: %w", err)
			}
			return nil
		}); err != nil {
			log.Printf("populate views: %v", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func viewsPopulated(ctx context.Context, db *gorm.DB) (bool, error) {
	var populated bool
	err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname IN ('sbom_component_view', 'sbom_metadata_view')",
	).Scan(&populated).Error
	return populated, err
}

// RefreshMaterializedViews refreshes SBOM materialized views and records refresh time.
// It uses a PostgreSQL advisory lock so that in a multi-replica deployment only one
// instance performs the refresh — others skip rather than queue up behind it.
// CONCURRENTLY is used so reads are not blocked during the refresh, but it must run
// outside a transaction block, so a session-level advisory lock is used instead.
func RefreshMaterializedViews(ctx context.Context, db *gorm.DB) error {
	// Session-level advisory lock: must acquire and release on the same connection.
	sqlDB, err := db.WithContext(ctx).DB()
	if err != nil {
		return fmt.Errorf("get raw db: %w", err)
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire db connection: %w", err)
	}
	defer conn.Close()

	var acquired bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", sbomViewRefreshLockID).Scan(&acquired); err != nil {
		return fmt.Errorf("acquire refresh lock: %w", err)
	}
	if !acquired {
		log.Printf("skipping materialized view refresh: another replica holds the lock")
		return nil
	}
	defer conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", sbomViewRefreshLockID) //nolint:errcheck

	var populated bool
	if err := db.WithContext(ctx).Raw(
		"SELECT COALESCE(bool_and(ispopulated), false) FROM pg_matviews WHERE matviewname IN ('sbom_component_view', 'sbom_metadata_view')",
	).Scan(&populated).Error; err != nil {
		return fmt.Errorf("check view population: %w", err)
	}

	refresh := "REFRESH MATERIALIZED VIEW CONCURRENTLY"
	if !populated {
		refresh = "REFRESH MATERIALIZED VIEW"
	}
	if err := db.WithContext(ctx).Exec(refresh + " sbom_component_view").Error; err != nil {
		return fmt.Errorf("refresh sbom_component_view: %w", err)
	}
	if err := db.WithContext(ctx).Exec(refresh + " sbom_metadata_view").Error; err != nil {
		return fmt.Errorf("refresh sbom_metadata_view: %w", err)
	}

	refreshedAt := time.Now().UTC()
	if err := db.WithContext(ctx).Exec(`
		INSERT INTO materialized_view_refreshes (name, refreshed_at)
		VALUES
			('sbom_component_view', ?),
			('sbom_metadata_view', ?)
		ON CONFLICT (name)
		DO UPDATE SET refreshed_at = EXCLUDED.refreshed_at
	`, refreshedAt, refreshedAt).Error; err != nil {
		return fmt.Errorf("record refresh: %w", err)
	}

	return nil
}
