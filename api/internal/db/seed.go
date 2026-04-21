package db

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gorm.io/gorm"
)

// RunSeedSQL executes one or more SQL seed scripts. `paths` is a
// comma-separated list so operators can point SPAM_SEED_SQL at several
// focused files (dev_seed.sql, image_scan_seed.sql, scam_seed.sql)
// without hand-concatenating them. Files are executed in order; a
// failure aborts the sequence.
func RunSeedSQL(ctx context.Context, db *gorm.DB, paths string) error {
	paths = strings.TrimSpace(paths)
	if paths == "" {
		return nil
	}
	for _, path := range strings.Split(paths, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read seed sql %q: %w", path, err)
		}
		if len(payload) == 0 {
			continue
		}
		if err := db.WithContext(ctx).Exec(string(payload)).Error; err != nil {
			return fmt.Errorf("exec seed sql %q: %w", path, err)
		}
	}
	return nil
}

