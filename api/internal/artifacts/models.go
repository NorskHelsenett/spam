package artifacts

import "time"

const (
	AssetTypeRepoCommit  = "REPO_COMMIT"
	AssetTypeImageDigest = "IMAGE_DIGEST"
)

// SBOM stores the raw SBOM document and metadata.
type SBOM struct {
	ID               string `gorm:"primaryKey;size:36"`
	Format           string `gorm:"size:32;not null"`
	ContentHash      []byte `gorm:"type:bytea;uniqueIndex:ux_sbom_hash"`
	ContentBytes     []byte `gorm:"type:bytea"`
	CreatedAt        time.Time
	IngestedByUserID string `gorm:"size:36"`
}

// SBOMBinding ties an SBOM to an asset reference.
// Each asset (repo commit or image digest) can have only one SBOM binding.
type SBOMBinding struct {
	ID              string `gorm:"primaryKey;size:36"`
	AssetType       string `gorm:"size:32;not null;uniqueIndex:ux_sbom_binding_asset"`
	AssetRefID      string `gorm:"size:36;not null;uniqueIndex:ux_sbom_binding_asset"`
	SBOMID          string `gorm:"size:36;not null;index:idx_sbom_binding_sbom"`
	Source          string `gorm:"size:32;not null"`
	CreatedAt       time.Time
	CreatedByUserID string `gorm:"size:36"`
}
