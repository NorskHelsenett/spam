package inventory

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"
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

	// Strip version from PURL
	basePURL := stripPURLVersion(input.PURL)
	cacheKey := basePURL
	if cacheKey == "" {
		// For components without PURL, use name+ecosystem as cache key
		eco := input.Ecosystem
		if eco == "" {
			eco = ecosystemFromPURL(input.PURL)
		}
		cacheKey = "name:" + input.Name + "::" + eco
	}

	// Check cache first
	if cached, ok := cache[cacheKey]; ok {
		return cached, nil
	}

	// Not in cache, do the actual upsert
	component, err := UpsertComponent(ctx, db, input)
	if err != nil {
		return nil, fmt.Errorf("cache miss for key=%q input.PURL=%q basePURL=%q: %w", cacheKey, input.PURL, basePURL, err)
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

	var component Component

	// If PURL provided, try to find existing first
	if basePURL != "" {
		err := db.WithContext(ctx).Where("purl = ?", basePURL).First(&component).Error
		if err == nil {
			return &component, nil
		}
		if err != gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("lookup purl %q: %w", basePURL, err)
		}

		// Not found, create new
		component = Component{
			ID:        uuid.NewString(),
			Name:      input.Name,
			PURL:      basePURL,
			Ecosystem: ecosystem,
		}
		if err := db.WithContext(ctx).Create(&component).Error; err != nil {
			// Debug: check what's actually in the DB
			var existing Component
			db.WithContext(ctx).Where("purl = ?", basePURL).First(&existing)
			return nil, fmt.Errorf("create component purl=%q (input.PURL=%q) name=%q existing.ID=%q existing.PURL=%q: %w",
				basePURL, input.PURL, input.Name, existing.ID, existing.PURL, err)
		}
		return &component, nil
	}

	// No PURL - look up by name and ecosystem first
	err := db.WithContext(ctx).
		Where("name = ? AND ecosystem = ? AND purl = ''", input.Name, ecosystem).
		First(&component).Error
	if err == nil {
		return &component, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	// Not found, create new
	component = Component{
		ID:        uuid.NewString(),
		Name:      input.Name,
		PURL:      "",
		Ecosystem: ecosystem,
	}
	if err := db.WithContext(ctx).Create(&component).Error; err != nil {
		return nil, err
	}

	return &component, nil
}

func UpsertComponentVersion(ctx context.Context, db *gorm.DB, componentID, version string) (*ComponentVersion, error) {
	if componentID == "" {
		return nil, nil
	}

	var cv ComponentVersion

	// Try to find existing first
	err := db.WithContext(ctx).
		Where("component_id = ? AND version = ?", componentID, version).
		First(&cv).Error
	if err == nil {
		return &cv, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, err
	}

	// Not found, create new
	cv = ComponentVersion{
		ID:          uuid.NewString(),
		ComponentID: componentID,
		Version:     version,
	}
	if err := db.WithContext(ctx).Create(&cv).Error; err != nil {
		return nil, err
	}

	return &cv, nil
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

	return db.WithContext(ctx).Create(&link).Error
}

// CreateComponentDependency creates a dependency relationship between two component versions.
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

	return db.WithContext(ctx).Create(&dep).Error
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

	// Remove subpath (#...)
	if idx := strings.Index(trimmed, "#"); idx != -1 {
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

	return trimmed
}
