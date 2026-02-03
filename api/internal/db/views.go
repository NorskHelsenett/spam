package db

import (
	"context"
	"fmt"
	"os"

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
