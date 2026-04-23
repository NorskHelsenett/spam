package vulnmeta

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Get returns cached metadata for vuln_id, or (nil, false, nil) if no
// row exists. Used by the detail endpoint before deciding whether to
// fall back to a synchronous fetch.
func Get(ctx context.Context, db *gorm.DB, vulnID string) (*Metadata, bool, error) {
	var m Metadata
	err := db.WithContext(ctx).Where("vuln_id = ?", vulnID).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &m, true, nil
}

// GetByAlias finds a metadata row where `aliases` contains the given
// ID. Lets the UI resolve "CVE-2024-1234" to a row stored under
// "GHSA-abcd-…" (or vice-versa) when a scanner reports the alias but
// enrichment came through the canonical form.
func GetByAlias(ctx context.Context, db *gorm.DB, aliasID string) (*Metadata, bool, error) {
	var m Metadata
	err := db.WithContext(ctx).
		Where(`aliases @> ?`, []byte(`["`+aliasID+`"]`)).
		Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &m, true, nil
}

// Upsert writes metadata, overwriting any existing row for the same
// vuln_id. Called by the fetcher after a successful external pull.
// Every field is replaced — partial updates go through a merge step
// in fetch.go, not here.
func Upsert(ctx context.Context, db *gorm.DB, m *Metadata) error {
	return db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "vuln_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"title", "description", "severity",
				"cvss_score", "cvss_vector",
				"cwes", "references", "aliases", "sources",
				"published_at", "modified_at",
				"raw_json", "fetched_at",
			}),
		}).
		Create(m).Error
}

// IDsMissingMetadata filters vulnIDs down to those without a cached
// row, so the enrichment enqueuer only creates jobs for new vulns.
// Returns in the same order as input with duplicates removed.
func IDsMissingMetadata(ctx context.Context, db *gorm.DB, vulnIDs []string) ([]string, error) {
	if len(vulnIDs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(vulnIDs))
	uniq := make([]string, 0, len(vulnIDs))
	for _, id := range vulnIDs {
		if id == "" || id == "_none" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	if len(uniq) == 0 {
		return nil, nil
	}

	var present []string
	if err := db.WithContext(ctx).
		Raw(`SELECT vuln_id FROM vuln_metadata WHERE vuln_id IN ?`, uniq).
		Scan(&present).Error; err != nil {
		return nil, err
	}
	presentSet := make(map[string]struct{}, len(present))
	for _, id := range present {
		presentSet[id] = struct{}{}
	}

	out := uniq[:0]
	for _, id := range uniq {
		if _, ok := presentSet[id]; !ok {
			out = append(out, id)
		}
	}
	return out, nil
}
