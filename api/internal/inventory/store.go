package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UpsertComponentInput struct {
	Name      string
	PURL      string
	Ecosystem string
}

// UpsertComponentWithCache upserts a component using an in-memory cache to avoid
// duplicate database operations within the same transaction.
func UpsertComponentWithCache(ctx context.Context, db *gorm.DB, input UpsertComponentInput, cache map[string]*Component) (*Component, error) {
	if input.Name == "" {
		return nil, nil
	}

	// Derive ecosystem from PURL if not provided
	ecosystem := input.Ecosystem
	if ecosystem == "" && input.PURL != "" {
		ecosystem = ecosystemFromPURL(input.PURL)
	}

	// Strip version from PURL
	basePURL := stripPURLVersion(input.PURL)

	// Cache key matches unique constraint: (name, ecosystem, purl)
	// Use "<NULL>" as placeholder for empty PURL in cache key
	purlKey := basePURL
	if purlKey == "" {
		purlKey = "<NULL>"
	}
	cacheKey := input.Name + "::" + ecosystem + "::" + purlKey

	// Check cache first
	if cached, ok := cache[cacheKey]; ok {
		return cached, nil
	}

	// Not in cache, do the actual upsert
	component, err := UpsertComponent(ctx, db, input)
	if err != nil {
		return nil, err
	}

	// Store in cache for future lookups
	if component != nil {
		cache[cacheKey] = component
	}

	return component, nil
}

func UpsertComponent(ctx context.Context, db *gorm.DB, input UpsertComponentInput) (*Component, error) {
	if input.Name == "" {
		return nil, nil
	}

	ecosystem := input.Ecosystem
	if ecosystem == "" && input.PURL != "" {
		ecosystem = ecosystemFromPURL(input.PURL)
	}

	// Strip version from PURL - Component is version-agnostic
	// e.g., "pkg:npm/lodash@4.17.21" -> "pkg:npm/lodash"
	basePURL := stripPURLVersion(input.PURL)

	// Convert to sql.NullString - empty string becomes NULL
	var purlNull sql.NullString
	if basePURL != "" {
		purlNull = sql.NullString{String: basePURL, Valid: true}
	}

	// Use ON CONFLICT DO UPDATE to handle race conditions atomically.
	// The "dummy" update ensures the row is touched even on conflict.
	component := Component{
		ID:        uuid.NewString(),
		Name:      input.Name,
		PURL:      purlNull,
		Ecosystem: ecosystem,
	}

	result := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "name"}, {Name: "ecosystem"}, {Name: "purl"}},
			DoUpdates: clause.AssignmentColumns([]string{"name"}), // No-op update
		}).
		Create(&component)

	if result.Error != nil {
		return nil, fmt.Errorf("upsert component name=%q ecosystem=%q purl=%q: %w", input.Name, ecosystem, basePURL, result.Error)
	}

	// Fetch the actual record to get the correct ID (may differ on conflict)
	var existing Component
	query := db.WithContext(ctx).Where("name = ? AND ecosystem = ?", input.Name, ecosystem)

	if basePURL == "" {
		query = query.Where("purl IS NULL")
	} else {
		query = query.Where("purl = ?", basePURL)
	}

	if err := query.First(&existing).Error; err != nil {
		return nil, fmt.Errorf("fetch component name=%q ecosystem=%q purl=%q: %w", input.Name, ecosystem, basePURL, err)
	}

	return &existing, nil
}

func UpsertComponentVersion(ctx context.Context, db *gorm.DB, componentID, version string) (*ComponentVersion, error) {
	if componentID == "" {
		return nil, nil
	}

	cv := ComponentVersion{
		ID:          uuid.NewString(),
		ComponentID: componentID,
		Version:     version,
	}

	// Use ON CONFLICT DO UPDATE to handle race conditions atomically.
	// The "dummy" update (id = id) ensures the row is returned even on conflict.
	// This is more reliable than DO NOTHING + separate SELECT.
	result := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "component_id"}, {Name: "version"}},
			DoUpdates: clause.AssignmentColumns([]string{"component_id"}), // No-op update
		}).
		Create(&cv)

	if result.Error != nil {
		return nil, fmt.Errorf("upsert component version component=%q version=%q: %w", componentID, version, result.Error)
	}

	// After ON CONFLICT DO UPDATE, cv.ID might still have our generated UUID.
	// Fetch the actual record to get the correct ID.
	var existing ComponentVersion
	if err := db.WithContext(ctx).
		Where("component_id = ? AND version = ?", componentID, version).
		First(&existing).Error; err != nil {
		return nil, fmt.Errorf("fetch version component=%q version=%q: %w", componentID, version, err)
	}

	return &existing, nil
}

func UpsertSBOMComponent(ctx context.Context, db *gorm.DB, sbomID, componentVersionID, scope string) error {
	if sbomID == "" || componentVersionID == "" {
		return nil
	}

	link := SBOMComponent{
		ID:                 uuid.NewString(),
		SBOMID:             sbomID,
		ComponentVersionID: componentVersionID,
		Scope:              scope,
	}

	// Use ON CONFLICT to make this idempotent.
	// If the same (sbom_id, component_version_id) already exists, do nothing.
	// This handles job retries safely.
	result := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "sbom_id"}, {Name: "component_version_id"}},
			DoNothing: true,
		}).
		Create(&link)

	return result.Error
}

// CreateComponentDependency creates a dependency relationship between two component versions.
// This is idempotent - calling it multiple times with the same arguments has no additional effect.
func CreateComponentDependency(ctx context.Context, db *gorm.DB, sbomID, dependentID, dependencyID string) error {
	if sbomID == "" || dependentID == "" || dependencyID == "" {
		return nil
	}

	dep := ComponentDependency{
		ID:           uuid.NewString(),
		SBOMID:       sbomID,
		DependentID:  dependentID,
		DependencyID: dependencyID,
	}

	// Use ON CONFLICT to make this idempotent.
	// If the same dependency already exists, do nothing.
	// This handles job retries safely.
	result := db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "sbom_id"}, {Name: "dependent_id"}, {Name: "dependency_id"}},
			DoNothing: true,
		}).
		Create(&dep)

	return result.Error
}

func ecosystemFromPURL(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, "pkg:") {
		return ""
	}
	trimmed = strings.TrimPrefix(trimmed, "pkg:")
	if trimmed == "" {
		return ""
	}
	parts := strings.SplitN(trimmed, "/", 2)
	return parts[0]
}

// stripPURLVersion removes version, qualifiers, and subpath from a PURL.
// e.g., "pkg:npm/lodash@4.17.21?foo=bar#sub" -> "pkg:npm/lodash"
func stripPURLVersion(purl string) string {
	trimmed := strings.TrimSpace(purl)
	if trimmed == "" {
		return ""
	}

	// Extract subpath if present (#...) - we need to preserve this
	subpath := ""
	if idx := strings.Index(trimmed, "#"); idx != -1 {
		subpath = trimmed[idx:] // Keep the # and everything after
		trimmed = trimmed[:idx]
	}

	// Remove qualifiers (?...)
	if idx := strings.Index(trimmed, "?"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	// Remove version (@...)
	if idx := strings.Index(trimmed, "@"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	// Re-append subpath after stripping version
	return trimmed + subpath
}
