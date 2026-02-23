package db

import (
	"context"
	"crypto/sha256"
	"fmt"
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
			// Advisory lock scoped to this transaction — released on commit/rollback.
			// The lock key is derived from the path so each view has its own lock.
			lockKey := int64(sha256.Sum256([]byte(path))[0])<<56 |
				int64(sha256.Sum256([]byte(path))[1])<<48
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

// RefreshMaterializedViews refreshes SBOM materialized views and records refresh time.
func RefreshMaterializedViews(ctx context.Context, db *gorm.DB) error {
	if err := db.WithContext(ctx).Exec("REFRESH MATERIALIZED VIEW sbom_component_view").Error; err != nil {
		return fmt.Errorf("refresh sbom_component_view: %w", err)
	}
	if err := db.WithContext(ctx).Exec("REFRESH MATERIALIZED VIEW sbom_metadata_view").Error; err != nil {
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
