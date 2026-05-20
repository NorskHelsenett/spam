package uiapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// ImageSecretRow is one row in the Images tab of the Secrets dashboard —
// one image_digests row with a non-empty betterleaks finding list from its
// most recent scan.
type ImageSecretRow struct {
	ImageID       string     `json:"image_id"`
	Registry      string     `json:"registry"`
	Repository    string     `json:"repository"`
	Digest        string     `json:"digest"`
	FindingCount  int64      `json:"finding_count"`
	LastScannedAt *time.Time `json:"last_scanned_at,omitempty"`
}

// ImageSecretsTableHandler returns the Images tab payload for the Secrets
// dashboard. Data is derived at query time by decoding the latest
// betterleaks artifact per image_digest_id — no denormalized findings
// table yet. If row counts grow enough that the JSON decode in the planner
// starts to hurt, add an image_secret_findings table the scanner result
// handler writes to and point this query at it.
//
// Clean (zero-finding) images are filtered out — the page is about "what
// needs attention", consistent with the Repositories tab.
func ImageSecretsTableHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		// Image-ACL splice: admins/global_readers get TRUE; cluster-only
		// users get a cluster_image_inventory-projected subquery (see
		// acl.ReadableImageClause). Restricted callers with no matching
		// grants short-circuit to an empty list.
		imageClause, err := acl.ReadableImageClause(r.Context(), acl.ProviderFromRequest(r), acl.SubjectFromRequest(r), "id")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		if imageClause.Deny() {
			writeJSON(w, http.StatusOK, []ImageSecretRow{})
			return
		}
		aclSQL, aclArgs := aclWhereFragment(imageClause)

		rows := []ImageSecretRow{}
		// try_bytea_to_jsonb (see migration 20260511a) catches conversion
		// errors per row and returns NULL on bad bytes / malformed JSON.
		// Without it a single corrupted artifact 500'd the whole
		// endpoint, because Postgres can evaluate WHERE predicates in
		// any order and a "filter bad rows first" guard didn't reliably
		// prevent the cast.
		query := fmt.Sprintf(`
			WITH latest_per_image AS (
				SELECT DISTINCT ON (isr.image_digest_id)
					isr.image_digest_id,
					isr.finished_at,
					try_bytea_to_jsonb(isa.content) AS payload
				FROM image_scan_runs isr
				JOIN image_scan_artifacts isa
					ON isa.scan_run_id = isr.id
				WHERE isa.category = 'secrets'
				  AND isa.scanner  = 'betterleaks'
				  AND isa.content IS NOT NULL
				  AND octet_length(isa.content) > 2
				ORDER BY isr.image_digest_id, isr.finished_at DESC NULLS LAST
			)
			SELECT
				id.id         AS image_id,
				id.registry   AS registry,
				id.repository AS repository,
				id.digest     AS digest,
				jsonb_array_length(l.payload) AS finding_count,
				l.finished_at AS last_scanned_at
			FROM latest_per_image l
			JOIN image_digests id ON id.id = l.image_digest_id
			WHERE l.payload IS NOT NULL
			  AND jsonb_typeof(l.payload) = 'array'
			  AND jsonb_array_length(l.payload) > 0
			  AND %s
			ORDER BY finding_count DESC, l.finished_at DESC NULLS LAST
			LIMIT 500
		`, aclSQL)
		if err := db.WithContext(r.Context()).Raw(query, aclArgs...).Scan(&rows).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}
