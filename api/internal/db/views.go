package db

import (
	"context"
	"fmt"
	"os"
	"time"

	"gorm.io/gorm"
)

// EnsureViews applies SQL view definitions from the provided file paths.
func EnsureViews(ctx context.Context, db *gorm.DB, paths ...string) error {
	for _, path := range paths {
		payload, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read view sql %s: %w", path, err)
		}
		if len(payload) == 0 {
			continue
		}
		if err := db.WithContext(ctx).Exec(string(payload)).Error; err != nil {
			return fmt.Errorf("exec view sql %s: %w", path, err)
		}
	}
	return nil
}

// RefreshMaterializedViews refreshes SBOM materialized views and records refresh time.
func RefreshMaterializedViews(ctx context.Context, db *gorm.DB) error {
	if err := db.WithContext(ctx).Exec("REFRESH MATERIALIZED VIEW CONCURRENTLY sbom_component_view").Error; err != nil {
		return fmt.Errorf("refresh sbom_component_view: %w", err)
	}
	if err := db.WithContext(ctx).Exec("REFRESH MATERIALIZED VIEW CONCURRENTLY sbom_metadata_view").Error; err != nil {
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
