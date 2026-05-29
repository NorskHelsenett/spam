package uiapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// BreakdownResponse is the wire shape of /api/triage/{asset_type}/{asset_id}/breakdown.
// One drill-down panel per asset — replaces the row-only summary with
// concrete subjects so the operator answers "why is this here" without
// chasing three sub-pages. The shape is union-flavoured: only the
// fields relevant to asset_type are populated. The frontend reads
// asset_type and renders accordingly.
type BreakdownResponse struct {
	AssetType string                       `json:"asset_type"`
	AssetID   string                       `json:"asset_id"`
	AssetSlug string                       `json:"asset_slug"`
	Signals   assetrisk.Signals            `json:"signals"`
	Tier      string                       `json:"tier"`
	Threat    int                          `json:"threat_score"`
	Trust     int                          `json:"trust_score"`
	TrustGrade string                      `json:"trust_grade"`
	Reasons   []assetrisk.Reason           `json:"reasons"`

	// Drivers
	CVEs            []BreakdownCVE         `json:"cves,omitempty"`
	Secrets         []BreakdownSecret      `json:"secrets,omitempty"`
	ContributingImages []BreakdownImage    `json:"contributing_images,omitempty"`
	ExposedEndpoints   []BreakdownEndpoint `json:"exposed_endpoints,omitempty"`

	// Live VEX rows scoped to this asset — global or asset-scoped.
	// Rendered in the drill-down so the operator can see which CVEs are
	// already suppressed and by whom.
	SuppressedCVEs []BreakdownVEX `json:"suppressed_cves,omitempty"`

	// Live bucket ack (newest non-revoked) and full history. The live
	// ack drives the "currently suppressed" banner; History is the
	// "who did it and why" log.
	LiveAck  *assetrisk.Acknowledgment  `json:"live_ack,omitempty"`
	History  []assetrisk.Acknowledgment `json:"history"`
}

type BreakdownCVE struct {
	VulnID       string  `json:"vuln_id"`
	Severity     string  `json:"severity"`
	FixedVersion string  `json:"fixed_version,omitempty"`
	PURL         string  `json:"purl,omitempty"`
	IsKEV        bool    `json:"is_kev"`
	EPSS         float32 `json:"epss,omitempty"`
}

type BreakdownSecret struct {
	SecretHash string `json:"secret_hash"`
	RuleID     string `json:"rule_id,omitempty"`
	Source     string `json:"source,omitempty"`
}

type BreakdownImage struct {
	ImageID       string `json:"image_id"`
	Digest        string `json:"digest"`
	Slug          string `json:"slug"`
	CriticalCount int64  `json:"critical_count"`
	KEVCount      int64  `json:"kev_count"`
	Namespace     string `json:"namespace,omitempty"`
}

type BreakdownEndpoint struct {
	Host         string `json:"host"`
	Namespace    string `json:"namespace,omitempty"`
	ExposureKind string `json:"exposure_kind,omitempty"`
	ExposureName string `json:"exposure_name,omitempty"`
}

type BreakdownVEX struct {
	ID            string  `json:"id"`
	VulnID        string  `json:"vuln_id"`
	PURL          string  `json:"purl"`
	Status        string  `json:"status"`
	Justification string  `json:"justification,omitempty"`
	ReasonText    string  `json:"reason_text,omitempty"`
	AssetScope    string  `json:"asset_scope,omitempty"`
	CreatedBy     string  `json:"created_by,omitempty"`
	CreatedAt     string  `json:"created_at"`
	SnoozeUntil   string  `json:"snooze_until,omitempty"`
}

// TriageBreakdownHandler returns the per-asset drill-down. ACL: caller
// must be approved AND able to read the asset (repo via
// ReadableRepoClause, image via ReadableImageClause, cluster via the
// cluster_grants → cluster_record bridge). 404 hides existence from
// callers who lack a grant — same pattern the per-tab handlers use.
func TriageBreakdownHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		assetType := strings.ToLower(chi.URLParam(r, "asset_type"))
		assetID := chi.URLParam(r, "asset_id")
		if assetID == "" {
			http.Error(w, "asset_id required", http.StatusBadRequest)
			return
		}
		switch assetType {
		case "repo", "image", "cluster":
		default:
			http.Error(w, "invalid asset_type", http.StatusBadRequest)
			return
		}

		// ACL check — does the caller see this row in their scoped
		// asset_risk view? One probe query, shared shape across types.
		visible, signals, err := loadAssetSignals(r, db, assetType, assetID)
		if err != nil {
			http.Error(w, "failed to load asset", http.StatusInternalServerError)
			return
		}
		if !visible {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		resp := BreakdownResponse{
			AssetType:  assetType,
			AssetID:    assetID,
			AssetSlug:  signals.AssetSlug,
			Signals:    signals,
			Tier:       assetrisk.Tier(signals),
			Threat:     assetrisk.ThreatScore(signals),
			Trust:      assetrisk.TrustScore(signals),
			TrustGrade: assetrisk.TrustGrade(assetrisk.TrustScore(signals)),
			Reasons:    assetrisk.Reasons(signals),
			History:    []assetrisk.Acknowledgment{},
		}

		// Per-type drivers.
		switch assetType {
		case "repo":
			resp.CVEs, err = loadRepoCVEs(r, db, assetID)
			if err == nil {
				resp.Secrets, err = loadRepoActiveSecrets(r, db, assetID)
			}
		case "image":
			resp.CVEs, err = loadImageCVEs(r, db, assetID)
		case "cluster":
			resp.ContributingImages, err = loadClusterImages(r, db, assetID)
			if err == nil {
				resp.ExposedEndpoints, err = loadClusterEndpoints(r, db, assetID)
			}
		}
		if err != nil {
			http.Error(w, "failed to load drivers", http.StatusInternalServerError)
			return
		}

		// Live VEX scoped to this asset. For images, scope filter
		// matches 'image:<digest>' OR NULL (global); for clusters and
		// repos we just show global VEX that intersect this asset's
		// vulns — keeps the v1 surface small.
		resp.SuppressedCVEs, err = loadScopedVEX(r, db, assetType, assetID, signals.ImageDigest)
		if err != nil {
			http.Error(w, "failed to load suppressed", http.StatusInternalServerError)
			return
		}

		// Ack history (newest first; full audit log for this asset).
		hist, err := assetrisk.HistoryForAsset(r.Context(), db, assetType, assetID)
		if err == nil {
			resp.History = hist
			for i := range hist {
				if hist[i].IsLive(time.Now().UTC()) {
					ack := hist[i]
					resp.LiveAck = &ack
					break
				}
			}
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// loadAssetSignals fetches the asset_risk row for a single asset and
// ACL-checks the caller in one shot. Returns (false, _, nil) when the
// row exists but the caller lacks access OR the row simply isn't in
// asset_risk — collapse both to 404 so the API doesn't leak existence.
func loadAssetSignals(r *http.Request, db *gorm.DB, assetType, assetID string) (bool, assetrisk.Signals, error) {
	subj := acl.SubjectFromRequest(r)
	prov := acl.ProviderFromRequest(r)

	var scopeSQL string
	var scopeArgs []any
	switch assetType {
	case "repo":
		c, err := acl.ReadableRepoClauseStrict(r.Context(), prov, subj, "r")
		if err != nil {
			return false, assetrisk.Signals{}, err
		}
		if c.Deny() {
			return false, assetrisk.Signals{}, nil
		}
		if c.Unrestricted {
			scopeSQL, scopeArgs = "TRUE", nil
		} else {
			scopeSQL = "ar.asset_id IN (SELECT r.id::text FROM repos r WHERE " + c.SQL + ")"
			scopeArgs = c.Args
		}
	case "image":
		c, err := acl.ReadableImageClause(r.Context(), prov, subj, "d")
		if err != nil {
			return false, assetrisk.Signals{}, err
		}
		if c.Deny() {
			return false, assetrisk.Signals{}, nil
		}
		if c.Unrestricted {
			scopeSQL, scopeArgs = "TRUE", nil
		} else {
			scopeSQL = "ar.asset_id IN (SELECT d.id::text FROM image_digests d WHERE " + c.SQL + ")"
			scopeArgs = c.Args
		}
	case "cluster":
		set, unrestricted, err := readableClusterIDSet(r, db)
		if err != nil {
			return false, assetrisk.Signals{}, err
		}
		switch {
		case unrestricted:
			scopeSQL, scopeArgs = "TRUE", nil
		case len(set) == 0:
			return false, assetrisk.Signals{}, nil
		default:
			ids := make([]string, 0, len(set))
			for id := range set {
				ids = append(ids, id)
			}
			scopeSQL = "ar.asset_id IN ?"
			scopeArgs = []any{ids}
		}
	}

	var row assetrisk.Signals
	args := append([]any{assetType, assetID}, scopeArgs...)
	err := db.WithContext(r.Context()).Raw(`
		SELECT
			ar.asset_type, ar.asset_id, ar.asset_slug,
			COALESCE(d.digest, '') AS image_digest,
			critical_count, high_count, kev_count, epss_max,
			has_fix_for_critical, active_secret_count, internet_exposed,
			signed_commits_pct, image_signed, scan_age_days, last_scan_at, has_sbom,
			worst_dep_health_score, archived_dep_count, deprecated_dep_count,
			max_major_behind, major_behind_dep_count
		FROM asset_risk ar
		LEFT JOIN image_digests d ON ar.asset_type = 'image' AND ar.asset_id = d.id::text
		WHERE ar.asset_type = ? AND ar.asset_id = ? AND `+scopeSQL,
		args...).Scan(&row).Error
	if err != nil {
		return false, assetrisk.Signals{}, err
	}
	if row.AssetID == "" {
		return false, assetrisk.Signals{}, nil
	}
	return true, row, nil
}

// breakdownCVELimit caps the per-asset CVE list. v1 keeps it small so
// the dashboard payload stays bounded; the per-asset vuln tab is the
// place to drill in further.
const breakdownCVELimit = 50

func loadRepoCVEs(r *http.Request, db *gorm.DB, repoID string) ([]BreakdownCVE, error) {
	out := []BreakdownCVE{}
	err := db.WithContext(r.Context()).Raw(`
		SELECT DISTINCT ON (canonical)
		       COALESCE(vm.canonical_id, v.vuln_id) AS vuln_id,
		       v.severity,
		       v.fixed_version,
		       ''::text AS purl,
		       (k.cve_id IS NOT NULL) AS is_kev,
		       COALESCE(e.score, 0)::real AS epss,
		       COALESCE(vm.canonical_id, v.vuln_id) AS canonical
		FROM view_unified_repositories_vulnerabilities v
		LEFT JOIN vuln_metadata vm    ON vm.vuln_id = v.vuln_id
		LEFT JOIN cisa_kev_entries k  ON k.cve_id   = COALESCE(vm.canonical_id, v.vuln_id)
		LEFT JOIN epss_entries e      ON e.cve_id   = COALESCE(vm.canonical_id, v.vuln_id)
		WHERE v.repo_id = ?
		ORDER BY canonical,
		         CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,
		         k.cve_id IS NOT NULL DESC,
		         e.score DESC NULLS LAST
		LIMIT ?
	`, repoID, breakdownCVELimit).Scan(&out).Error
	return out, err
}

func loadImageCVEs(r *http.Request, db *gorm.DB, imageID string) ([]BreakdownCVE, error) {
	out := []BreakdownCVE{}
	err := db.WithContext(r.Context()).Raw(`
		SELECT DISTINCT ON (canonical)
		       COALESCE(vm.canonical_id, v.vuln_id) AS vuln_id,
		       v.severity,
		       v.fixed_version,
		       ''::text AS purl,
		       (k.cve_id IS NOT NULL) AS is_kev,
		       COALESCE(e.score, 0)::real AS epss,
		       COALESCE(vm.canonical_id, v.vuln_id) AS canonical
		FROM view_unified_image_vulnerabilities v
		LEFT JOIN vuln_metadata vm    ON vm.vuln_id = v.vuln_id
		LEFT JOIN cisa_kev_entries k  ON k.cve_id   = COALESCE(vm.canonical_id, v.vuln_id)
		LEFT JOIN epss_entries e      ON e.cve_id   = COALESCE(vm.canonical_id, v.vuln_id)
		WHERE v.image_id = ?
		ORDER BY canonical,
		         CASE v.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END,
		         k.cve_id IS NOT NULL DESC,
		         e.score DESC NULLS LAST
		LIMIT ?
	`, imageID, breakdownCVELimit).Scan(&out).Error
	return out, err
}

func loadRepoActiveSecrets(r *http.Request, db *gorm.DB, repoID string) ([]BreakdownSecret, error) {
	out := []BreakdownSecret{}
	// Latest run_secrets row per repo expanded — keeps shape consistent
	// with the asset_risk active_secret_count predicate (status=valid
	// secret_probes only). Limited to top N for payload size.
	err := db.WithContext(r.Context()).Raw(`
		WITH latest AS (
			SELECT findings
			FROM run_secrets
			WHERE repo_id = ?
			ORDER BY created_at DESC
			LIMIT 1
		),
		expanded AS (
			SELECT
				encode(digest(f->>'Secret', 'sha256'), 'hex') AS secret_hash,
				COALESCE(f->>'RuleID', '')      AS rule_id,
				COALESCE(f->>'Source', '')      AS source
			FROM latest, jsonb_array_elements(COALESCE(latest.findings, '[]'::jsonb)) AS f
		)
		SELECT e.secret_hash, e.rule_id, e.source
		FROM expanded e
		JOIN secret_probes sp ON sp.secret_hash = e.secret_hash AND sp.status = 'valid'
		LIMIT 50
	`, repoID).Scan(&out).Error
	return out, err
}

// loadClusterImages: which images running in this cluster contribute
// the most threat? Sorted by KEV first, then critical_count desc.
// Limited to top N — the dashboard drills in here, the full image list
// per cluster lives at /clusters/{id}/images.
func loadClusterImages(r *http.Request, db *gorm.DB, clusterID string) ([]BreakdownImage, error) {
	out := []BreakdownImage{}
	err := db.WithContext(r.Context()).Raw(`
		WITH cluster_images AS (
			SELECT DISTINCT
				cr.data->>'digest' AS digest,
				cr.data->>'namespace' AS namespace
			FROM cluster_record cr
			WHERE cr.data->>'kind' = 'Container'
			  AND COALESCE(cr.data->>'cluster_id','') = ?
			  AND COALESCE(cr.data->>'msg','') <> 'DELETE'
			  AND COALESCE(cr.data->>'digest','') <> ''
		)
		SELECT
			d.id::text AS image_id,
			d.digest,
			COALESCE(NULLIF(d.registry,'') || '/' || d.repository, d.repository, d.id::text) AS slug,
			COALESCE(ar.critical_count, 0) AS critical_count,
			COALESCE(ar.kev_count, 0)      AS kev_count,
			ci.namespace
		FROM cluster_images ci
		JOIN image_digests d ON d.digest = ci.digest
		LEFT JOIN asset_risk ar ON ar.asset_type = 'image' AND ar.asset_id = d.id::text
		WHERE COALESCE(ar.kev_count, 0) > 0
		   OR COALESCE(ar.critical_count, 0) > 0
		ORDER BY ar.kev_count DESC NULLS LAST, ar.critical_count DESC NULLS LAST
		LIMIT 20
	`, clusterID).Scan(&out).Error
	return out, err
}

func loadClusterEndpoints(r *http.Request, db *gorm.DB, clusterID string) ([]BreakdownEndpoint, error) {
	out := []BreakdownEndpoint{}
	err := db.WithContext(r.Context()).Raw(`
		SELECT DISTINCT
			ed.host,
			ed.namespace,
			ed.exposure_kind,
			ed.exposure_name
		FROM exposed_digests ed
		WHERE ed.cluster_id = ?
		ORDER BY ed.host
		LIMIT 50
	`, clusterID).Scan(&out).Error
	return out, err
}

func loadScopedVEX(r *http.Request, db *gorm.DB, assetType, assetID, imageDigest string) ([]BreakdownVEX, error) {
	out := []BreakdownVEX{}
	// Image rows narrow by scope ('image:<digest>') AND global rows.
	// Repo / cluster rows currently only show global VEX — narrow
	// scopes ('cluster:<id>', 'repo:<id>') are reserved for follow-ups.
	var rows []vulnerabilities.ComponentVEX
	q := db.WithContext(r.Context()).
		Where("revoked_at IS NULL").
		Where("snooze_until IS NULL OR snooze_until > NOW()")

	switch assetType {
	case "image":
		if imageDigest != "" {
			q = q.Where("asset_scope IS NULL OR asset_scope = '' OR asset_scope = ?", "image:"+imageDigest)
		} else {
			q = q.Where("asset_scope IS NULL OR asset_scope = ''")
		}
	default:
		q = q.Where("asset_scope IS NULL OR asset_scope = ''")
	}

	if err := q.Order("created_at DESC").Limit(50).Find(&rows).Error; err != nil {
		return out, err
	}
	for _, v := range rows {
		entry := BreakdownVEX{
			ID:            v.ID.String(),
			VulnID:        v.VulnID,
			PURL:          v.PURL,
			Status:        v.Status,
			Justification: v.Justification,
			ReasonText:    v.ReasonText,
			AssetScope:    v.AssetScope,
			CreatedBy:     v.CreatedBy,
			CreatedAt:     v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if v.SnoozeUntil != nil {
			entry.SnoozeUntil = v.SnoozeUntil.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = append(out, entry)
	}
	return out, nil
}
