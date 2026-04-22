// Package acl implements scope-pattern access control.
//
// Grants are expressed as structured patterns over resource attributes
// (e.g. provider+owner for repos, cluster_id for clusters). A grant
// with a missing field wildcards that attribute, so a single grant on
// `{provider:'github', owner:'me'}` covers every repo under
// github.com/me/*.
//
// The Provider interface is the single extension point for future
// authorization sources (OIDC-claim-derived grants, a GitHub App,
// external RBAC/OPA). Initial shipping implementation is LocalProvider
// which reads from the acl_grants table.
package acl

import (
	"time"

	"gorm.io/datatypes"
)

// Subject types.
const (
	SubjectUser  = "user"
	SubjectGroup = "group"
)

// Scope types.
const (
	ScopeRepo    = "repo"
	ScopeCluster = "cluster"
	ScopeImage   = "image"
)

// Actions. Only `read` is implemented in Phase 2/3.
const (
	ActionRead = "read"
)

// Grant sources. `migration` rows are grandfathered from the pre-ACL
// world and surface in the admin "review grandfathered grants" report
// so they can be tightened once explicit grants exist.
const (
	SourceMigration     = "migration"
	SourceExplicit      = "explicit"
	SourceIngestDefault = "ingest_default"
)

// Grant is a single row in acl_grants. A grant says "this subject
// (user or group) may perform `action` on resources of `scope_type`
// that match `scope_pattern`".
type Grant struct {
	ID              string         `gorm:"primaryKey;size:36" json:"id"`
	SubjectType     string         `gorm:"size:16;not null;index:idx_acl_lookup,priority:1" json:"subject_type"`
	SubjectID       string         `gorm:"size:128;not null;index:idx_acl_lookup,priority:2" json:"subject_id"`
	ScopeType       string         `gorm:"size:16;not null;index:idx_acl_lookup,priority:3" json:"scope_type"`
	ScopePattern    datatypes.JSON `gorm:"type:jsonb;not null" json:"scope_pattern"`
	Action          string         `gorm:"size:16;not null;default:'read'" json:"action"`
	Source          string         `gorm:"size:24;not null;default:'explicit'" json:"source"`
	CreatedAt       time.Time      `json:"created_at"`
	CreatedByUserID string         `gorm:"size:36" json:"created_by,omitempty"`
}

func (Grant) TableName() string { return "acl_grants" }

// ScopePattern is the structured matcher stored as JSONB in
// `acl_grants.scope_pattern`. All fields are optional; missing = wildcard.
// Which fields are meaningful depends on ScopeType.
//
//   - repo:    Provider, ProviderInstanceID, Owner, Slug
//   - cluster: ClusterID
//   - image:   Registry, Repository, Digest (explicit image grants only;
//              normal image access inherits from the source repo via
//              ScopeImages when the image is signature-verified).
type ScopePattern struct {
	Provider           string `json:"provider,omitempty"`
	ProviderInstanceID string `json:"provider_instance_id,omitempty"`
	Owner              string `json:"owner,omitempty"`
	Slug               string `json:"slug,omitempty"`

	ClusterID string `json:"cluster_id,omitempty"`

	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// IsWildcard reports whether the pattern matches every resource of
// its scope type (all relevant fields unset).
func (p ScopePattern) IsWildcard() bool {
	return p == ScopePattern{}
}
