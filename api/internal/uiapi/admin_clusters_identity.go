package uiapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// ClusterIdentityMerge is one entry in the diagnostic's `merges` list:
// a cluster_key with the set of raw cluster_ids that collapsed onto it.
// Length 1 means "no collapse, single raw id == cluster_key" and is
// excluded from the response so the list only carries actual merges.
type ClusterIdentityMerge struct {
	ClusterKey    string   `json:"cluster_key"`
	RawClusterIDs []string `json:"raw_cluster_ids"`
}

// ClusterIdentityNoROR is one entry in the diagnostic's `no_ror_metadata`
// list: a logical cluster (post-merge cluster_key) for which no record
// has ever carried `data->'ror_metadata'`. Useful for spotting agents
// running an old release that hasn't picked up the SCAM identity-cutover
// payload yet.
type ClusterIdentityNoROR struct {
	ClusterKey string    `json:"cluster_key"`
	ClusterID  string    `json:"cluster_id"`
	ClusterEnv string    `json:"cluster_env,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
}

// ClusterIdentityReport is the wire shape for /api/admin/clusters/identity.
type ClusterIdentityReport struct {
	RawClusterIDCount int                    `json:"raw_cluster_id_count"`
	ClusterKeyCount   int                    `json:"cluster_key_count"`
	MergeCount        int                    `json:"merge_count"`
	Merges            []ClusterIdentityMerge `json:"merges"`
	NoRORCount        int                    `json:"no_ror_count"`
	NoROR             []ClusterIdentityNoROR `json:"no_ror_metadata"`
}

// AdminClusterIdentityHandler exposes a per-cluster view of the SCAM
// identity-cutover merge: how many raw cluster_ids exist in
// cluster_record, how many distinct cluster_keys they collapse onto,
// which keys carry more than one raw id (the actual merges), and which
// logical clusters still have no ror_metadata on any record (typically
// because the SCAM agent hasn't been bumped to the post-cutover release
// yet).
//
// The cluster_key derivation matches the cluster_summary MV exactly:
//
//	COALESCE(NULLIF(data->'ror_metadata'->>'cluster_id',''), data->>'cluster_id')
//
// so the numbers in this report align 1:1 with what /api/clusters/summary
// shows after the merge. Use this to answer "is the dedup too harsh"
// (Merges list shows which raw_ids got collapsed) and "which agents are
// behind on the identity cutover" (NoROR list).
//
// Admin-only.
func AdminClusterIdentityHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := authService.RequireAdmin(r); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		rep := ClusterIdentityReport{
			Merges: []ClusterIdentityMerge{},
			NoROR:  []ClusterIdentityNoROR{},
		}

		// Single round-trip aggregate: per cluster_key, the set of raw
		// cluster_ids it merges, plus a flag for whether any record in
		// the group carried ror_metadata. Filtering to non-DELETE rows
		// mirrors what cluster_summary itself reads, so counts match the
		// dashboard.
		type row struct {
			ClusterKey    string    `gorm:"column:cluster_key"`
			RawIDs        string    `gorm:"column:raw_ids"`
			HasROR        bool      `gorm:"column:has_ror"`
			AnyClusterID  string    `gorm:"column:any_cluster_id"`
			AnyClusterEnv string    `gorm:"column:any_cluster_env"`
			LastSeen      time.Time `gorm:"column:last_seen"`
		}
		var rows []row
		if err := db.WithContext(ctx).Raw(`
			WITH base AS (
				SELECT
					COALESCE(NULLIF(data->'ror_metadata'->>'cluster_id',''), data->>'cluster_id') AS cluster_key,
					data->>'cluster_id'                                                          AS raw_id,
					(data->'ror_metadata' IS NOT NULL)                                           AS has_ror,
					COALESCE(data->>'environment','')                                            AS env,
					received_at
				FROM cluster_record
				WHERE COALESCE(data->>'msg','') <> 'DELETE'
				  AND data->>'cluster_id' IS NOT NULL
			)
			SELECT
				cluster_key,
				string_agg(DISTINCT raw_id, ',' ORDER BY raw_id)                                AS raw_ids,
				BOOL_OR(has_ror)                                                                AS has_ror,
				-- Canonical cluster_id surfaced in the dashboard: prefer the
				-- UID identity (record carries ror_metadata) over the slug.
				(array_agg(raw_id ORDER BY has_ror DESC, received_at DESC))[1]                  AS any_cluster_id,
				(array_agg(env    ORDER BY has_ror DESC, received_at DESC))[1]                  AS any_cluster_env,
				MAX(received_at)                                                                AS last_seen
			FROM base
			GROUP BY cluster_key
			ORDER BY last_seen DESC
		`).Scan(&rows).Error; err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}

		rawSet := make(map[string]struct{}, len(rows)*2)
		for _, rw := range rows {
			rep.ClusterKeyCount++
			ids := splitNonEmpty(rw.RawIDs, ",")
			for _, id := range ids {
				rawSet[id] = struct{}{}
			}
			if len(ids) > 1 {
				rep.Merges = append(rep.Merges, ClusterIdentityMerge{
					ClusterKey:    rw.ClusterKey,
					RawClusterIDs: ids,
				})
			}
			if !rw.HasROR {
				rep.NoROR = append(rep.NoROR, ClusterIdentityNoROR{
					ClusterKey: rw.ClusterKey,
					ClusterID:  rw.AnyClusterID,
					ClusterEnv: rw.AnyClusterEnv,
					LastSeen:   rw.LastSeen,
				})
			}
		}
		rep.RawClusterIDCount = len(rawSet)
		rep.MergeCount = rep.RawClusterIDCount - rep.ClusterKeyCount
		rep.NoRORCount = len(rep.NoROR)

		writeJSON(w, http.StatusOK, rep)
	}
}

// splitNonEmpty splits s on sep and drops empty fields. string_agg can
// emit a stray empty when an input row's value collapsed to '', so we
// don't trust the SQL output blindly.
func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
