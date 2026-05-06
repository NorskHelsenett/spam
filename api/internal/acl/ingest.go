package acl

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// RepoIdentity captures the fields of a newly ingested repo that an
// ingest-default grant narrows down to. The resulting grant's
// scope_pattern is {provider, owner, slug} so the row is a specific
// grant that stays valid even if the provider's default_grants list
// changes later.
type RepoIdentity struct {
	Provider           string
	ProviderInstanceID string
	Owner              string
	Slug               string
}

// DefaultGrantSubject is one entry in a provider's default_grants list.
type DefaultGrantSubject struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
}

// ApplyIngestDefaults inserts acl_grants(source='ingest_default') for
// every subject listed in the provider's default_grants JSON. Each row
// is narrowed to the specific repo identity, so the grant is
// auditable per-repo and survives provider reconfiguration.
//
// Duplicates (same subject + identity) are silently swallowed via the
// ux_acl_grant_identity unique index. Errors are logged but never
// returned — an ACL seeding failure must not fail the upstream repo
// upsert.
func ApplyIngestDefaults(ctx context.Context, db *gorm.DB, providerInstanceID string, repo RepoIdentity) {
	if db == nil || providerInstanceID == "" {
		return
	}

	var row struct {
		DefaultGrants datatypes.JSON
	}
	if err := db.WithContext(ctx).
		Table("provider_instances").
		Select("default_grants").
		Where("id = ?", providerInstanceID).
		Scan(&row).Error; err != nil {
		return
	}
	if len(row.DefaultGrants) == 0 {
		return
	}

	var entries []DefaultGrantSubject
	if err := json.Unmarshal(row.DefaultGrants, &entries); err != nil || len(entries) == 0 {
		return
	}

	pattern := ScopePattern{
		Provider:           repo.Provider,
		ProviderInstanceID: repo.ProviderInstanceID,
		Owner:              repo.Owner,
		Slug:               repo.Slug,
	}
	patternJSON, err := json.Marshal(pattern)
	if err != nil {
		return
	}

	now := time.Now().UTC()
	for _, e := range entries {
		if e.SubjectType == "" || e.SubjectID == "" {
			continue
		}
		if e.SubjectType != SubjectUser && e.SubjectType != SubjectGroup {
			continue
		}
		grant := Grant{
			ID:           uuid.NewString(),
			SubjectType:  e.SubjectType,
			SubjectID:    e.SubjectID,
			ScopeType:    ScopeRepo,
			ScopePattern: datatypes.JSON(patternJSON),
			Action:       ActionRead,
			Source:       SourceIngestDefault,
			CreatedAt:    now,
		}
		if err := db.WithContext(ctx).Create(&grant).Error; err != nil {
			// Duplicate key races, invalid rows — log and move on so
			// repo ingestion doesn't stall.
			log.Printf("acl: ingest_default grant for %s/%s (%s:%s): %v",
				repo.Owner, repo.Slug, e.SubjectType, e.SubjectID, err)
		}
	}
}
