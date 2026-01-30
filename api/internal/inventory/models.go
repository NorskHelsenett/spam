package inventory

import (
	"database/sql"
	"time"
)

// Component describes a unique software component.
// PURL is the base PURL without version (e.g., "pkg:npm/lodash" not "pkg:npm/lodash@4.17.21").
// Components are uniquely identified by (name, ecosystem, purl).
// PURL can be NULL when not available - use sql.NullString for proper NULL handling.
type Component struct {
	ID        string         `gorm:"primaryKey;size:36"`
	PURL      sql.NullString `gorm:"column:purl;type:varchar(1024);uniqueIndex:ux_component_identity"`
	Name      string         `gorm:"size:255;not null;uniqueIndex:ux_component_identity"`
	Ecosystem string         `gorm:"size:64;not null;default:'';uniqueIndex:ux_component_identity"`
	CreatedAt time.Time
}

// ComponentVersion captures a version for a component.
type ComponentVersion struct {
	ID          string `gorm:"primaryKey;size:36"`
	ComponentID string `gorm:"size:36;not null;uniqueIndex:ux_component_version;index:idx_cv_component"`
	Version     string `gorm:"size:128;not null;uniqueIndex:ux_component_version"`
	CreatedAt   time.Time
}

// SBOMComponent links an SBOM to component versions.
// Each (sbom_id, component_version_id) pair is unique.
type SBOMComponent struct {
	ID                 string `gorm:"primaryKey;size:36"`
	SBOMID             string `gorm:"size:36;not null;uniqueIndex:ux_sbom_component;index:idx_sbom_component_sbom"`
	ComponentVersionID string `gorm:"size:36;not null;uniqueIndex:ux_sbom_component;index:idx_sbom_component_cv"`
	Scope              string `gorm:"size:32"`
	CreatedAt          time.Time
}

// ComponentDependency represents a dependency relationship between component versions.
// The DependentID depends on the DependencyID.
// Each (sbom_id, dependent_id, dependency_id) triple is unique.
type ComponentDependency struct {
	ID           string `gorm:"primaryKey;size:36"`
	SBOMID       string `gorm:"size:36;not null;uniqueIndex:ux_component_dep;index:idx_component_dep_sbom"`
	DependentID  string `gorm:"size:36;not null;uniqueIndex:ux_component_dep;index:idx_component_dep_dependent"`
	DependencyID string `gorm:"size:36;not null;uniqueIndex:ux_component_dep;index:idx_component_dep_dependency"`
	CreatedAt    time.Time
}
