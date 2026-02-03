package db

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/NorskHelsenett/spam/internal/artifacts"
	"github.com/NorskHelsenett/spam/internal/inventory"
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

// SeedSBOMComponentsFromFile parses a local SBOM and populates inventory tables.
func SeedSBOMComponentsFromFile(ctx context.Context, db *gorm.DB, path, format string) error {
	if path == "" {
		return nil
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read seed sbom: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}

	hash := sha256.Sum256(payload)

	var sbom artifacts.SBOM
	if err := db.WithContext(ctx).Where("content_hash = ?", hash[:]).First(&sbom).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("find seed sbom: %w", err)
	}

	parsed, err := inventory.ParseSBOMFull(format, payload)
	if err != nil {
		return fmt.Errorf("parse seed sbom: %w", err)
	}

	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		_, err := inventory.UpsertParsedSBOM(ctx, tx, sbom.ID, parsed)
		return err
	})
}
