package inventory

import "time"

// Component describes a unique software component.
type Component struct {
	ID        string `gorm:"primaryKey;size:36"`
	PURL      string `gorm:"column:purl;size:1024;uniqueIndex:ux_component_purl,where:purl IS NOT NULL"`
	Name      string `gorm:"size:255;not null;index:idx_component_name"`
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
	SBOMID             string `gorm:"size:36;not null;uniqueIndex:ux_sbom_component;index:idx_sbom_component_sbom"`
	ComponentVersionID string `gorm:"size:36;not null;uniqueIndex:ux_sbom_component;index"`
	Scope              string `gorm:"size:32"`
	CreatedAt          time.Time
}
