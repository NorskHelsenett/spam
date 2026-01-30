package manifests

import (
	"time"

	"gorm.io/datatypes"
)

// Manifest represents a dependency manifest file from a repository
type Manifest struct {
	ID        string         `gorm:"primaryKey;size:36" json:"id"`
	RunID     string         `gorm:"size:36;index" json:"run_id"`
	RepoID    string         `gorm:"size:36;index" json:"repo_id"`
	Path      string         `gorm:"size:512" json:"path"`       // Relative path in repo
	Type      string         `gorm:"size:64;index" json:"type"`  // csproj, package.json, pom.xml, etc.
	Content   string         `gorm:"type:text" json:"content"`   // Original file content as text
	Metadata  datatypes.JSON `gorm:"type:jsonb" json:"metadata"` // Parsed metadata
	CreatedAt time.Time      `json:"created_at"`
}

// ManifestDependency represents a dependency extracted from a manifest
type ManifestDependency struct {
	ID         string    `gorm:"primaryKey;size:36" json:"id"`
	ManifestID string    `gorm:"size:36;index" json:"manifest_id"`
	Name       string    `gorm:"size:512;index" json:"name"`
	Version    string    `gorm:"size:128" json:"version"`
	Constraint string    `gorm:"size:256" json:"constraint"`     // Version constraint/range
	Ecosystem  string    `gorm:"size:64;index" json:"ecosystem"` // nuget, npm, pypi, maven, etc.
	Scope      string    `gorm:"size:64" json:"scope"`           // production, dev, test, etc.
	Direct     bool      `json:"direct"`                         // true = direct dependency, false = transitive
	CreatedAt  time.Time `json:"created_at"`
}
