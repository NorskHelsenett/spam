package uiapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// ImageSecretRow is one row in the Images tab of the Secrets dashboard —
// one image_digests row with a non-empty betterleaks finding list from its
// most recent scan.
type ImageSecretRow struct {
	ImageID        string     `json:"image_id"`
	Registry       string     `json:"registry"`
	Repository     string     `json:"repository"`
	Digest         string     `json:"digest"`
	FindingCount   int64      `json:"finding_count"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
	ClusterCount   int64      `json:"cluster_count,omitempty"`
	NamespaceCount int64      `json:"namespace_count,omitempty"`
	ContainerCount int64      `json:"container_count,omitempty"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`
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
		includeInactive := isSecretImageTruthy(r.URL.Query().Get("include_inactive")) ||
			strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("scope")), "all")

		// try_bytea_to_jsonb (see migration 20260511a) catches conversion
		// errors per row and returns NULL on bad bytes / malformed JSON.
		// Without it a single corrupted artifact 500'd the whole
		// endpoint, because Postgres can evaluate WHERE predicates in
		// any order and a "filter bad rows first" guard didn't reliably
		// prevent the cast.
		// Live filter is composed alongside the ACL clause so a single
		// fmt.Sprintf handles both — appending the live predicate as a
		// separate string concat after Sprintf would put it before the
		// ORDER BY, which is brittle if the format ever changes.
		liveFilter := ""
		if !includeInactive {
			liveFilter = "AND liu.digest IS NOT NULL"
		}
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
			),
			live_image_usage AS (
				SELECT
					cr.data->>'registry' AS registry,
					cr.data->>'image'    AS repository,
					cr.data->>'digest'   AS digest,
					COUNT(DISTINCT cr.data->>'cluster_id') AS cluster_count,
					COUNT(DISTINCT cr.data->>'namespace')  AS namespace_count,
					COUNT(*)                               AS container_count,
					MAX(cr.received_at)                    AS last_seen
				FROM cluster_record cr
				WHERE cr.is_present = TRUE
				  AND cr.data->>'kind' = 'Container'
				  AND cr.data->>'pod_phase' = 'Running'
				  AND COALESCE(cr.data->>'digest', '') <> ''
				GROUP BY cr.data->>'registry', cr.data->>'image', cr.data->>'digest'
			)
			SELECT
				id.id         AS image_id,
				id.registry   AS registry,
				id.repository AS repository,
				id.digest     AS digest,
				jsonb_array_length(l.payload) AS finding_count,
				l.finished_at AS last_scanned_at,
				COALESCE(liu.cluster_count, 0)   AS cluster_count,
				COALESCE(liu.namespace_count, 0) AS namespace_count,
				COALESCE(liu.container_count, 0) AS container_count,
				liu.last_seen                    AS last_seen
			FROM latest_per_image l
			JOIN image_digests id ON id.id = l.image_digest_id
			LEFT JOIN live_image_usage liu
				ON liu.registry = id.registry
			   AND liu.repository = id.repository
			   AND liu.digest = id.digest
			WHERE l.payload IS NOT NULL
			  AND jsonb_typeof(l.payload) = 'array'
			  AND jsonb_array_length(l.payload) > 0
			  AND %s
			  %s
			ORDER BY finding_count DESC, l.finished_at DESC NULLS LAST
			LIMIT 500
		`, aclSQL, liveFilter)
		if err := db.WithContext(r.Context()).Raw(query, aclArgs...).Scan(&rows).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

func isSecretImageTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
