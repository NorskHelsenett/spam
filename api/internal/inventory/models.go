package inventory

import "time"

// Component describes a unique software component.
// PURL is the base PURL without version (e.g., "pkg:npm/lodash" not "pkg:npm/lodash@4.17.21")
type Component struct {
	ID        string `gorm:"primaryKey;size:36"`
	PURL      string `gorm:"column:purl;size:1024"`
	Name      string `gorm:"size:255;not null"`
	Ecosystem string `gorm:"size:64"`
	CreatedAt time.Time
}

// ComponentVersion captures a version for a component.
type ComponentVersion struct {
	ID          string `gorm:"primaryKey;size:36"`
	ComponentID string `gorm:"size:36;not null;uniqueIndex:ux_component_version"`
	Version     string `gorm:"size:128;not null;uniqueIndex:ux_component_version"`
	CreatedAt   time.Time
}

// SBOMComponent links an SBOM to component versions.
type SBOMComponent struct {
	ID                 string `gorm:"primaryKey;size:36"`
	SBOMID             string `gorm:"size:36;not null;index:idx_sbom_component_sbom"`
	ComponentVersionID string `gorm:"size:36;not null;index"`
	Scope              string `gorm:"size:32"`
	CreatedAt          time.Time
}

// ComponentDependency represents a dependency relationship between component versions.
// The DependentID depends on the DependencyID.
type ComponentDependency struct {
	ID           string `gorm:"primaryKey;size:36"`
	SBOMID       string `gorm:"size:36;not null;index:idx_component_dep_sbom"`
	DependentID  string `gorm:"size:36;not null;index:idx_component_dep_dependent"`  // The component that has the dependency
	DependencyID string `gorm:"size:36;not null;index:idx_component_dep_dependency"` // The component being depended on
	CreatedAt    time.Time
}
