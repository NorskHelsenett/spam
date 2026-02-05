package db

import (
	"context"
	"fmt"
	"os"

	"gorm.io/gorm"
)

// RunSeedSQL executes a SQL seed script if provided.
func RunSeedSQL(ctx context.Context, db *gorm.DB, path string) error {
	if path == "" {
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read seed sql: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}

	if err := db.WithContext(ctx).Exec(string(payload)).Error; err != nil {
		return fmt.Errorf("exec seed sql: %w", err)
	}
	return nil
}

