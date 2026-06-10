package uiapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// TriageImageVuln is one CVE row in the image expansion panel —
// KEV/EPSS-enriched, one row per canonical vuln.
type TriageImageVuln struct {
	VulnID           string     `json:"vuln_id"            gorm:"column:vuln_id"`
	CanonicalID      string     `json:"canonical_id"       gorm:"column:canonical_id"`
	Severity         string     `json:"severity"           gorm:"column:severity"`
	PkgName          string     `json:"pkg_name"           gorm:"column:pkg_name"`
	InstalledVersion string     `json:"installed_version"  gorm:"column:installed_version"`
	FixedVersion     string     `json:"fixed_version"      gorm:"column:fixed_version"`
	EPSS             float32    `json:"epss"               gorm:"column:epss"`
	EPSSPercentile   float32    `json:"epss_percentile"    gorm:"column:epss_percentile"`
	KEV              bool       `json:"kev"                gorm:"column:kev"`
	KEVDueDate       *time.Time `json:"kev_due_date,omitempty" gorm:"column:kev_due_date"`
	KEVRansomware    bool       `json:"kev_ransomware"     gorm:"column:kev_ransomware"`

	// OnPath marks vulns that participate in the attack path the tier
	// rules weigh: in KEV, elevated EPSS, or critical on an
	// internet-exposed digest. The UI hides everything else behind a
	// toggle so the card stays threat-model-sized.
	OnPath bool `json:"on_path" gorm:"column:on_path"`
}

// TriageImageHost is one exposed domain serving the image's digest.
type TriageImageHost struct {
	Host      string `json:"host"       gorm:"column:host"`
	Cluster   string `json:"cluster"    gorm:"column:cluster"`
	ClusterID string `json:"cluster_id" gorm:"column:cluster_id"`
	Namespace string `json:"namespace"  gorm:"column:namespace"`
	TLS       bool   `json:"tls"        gorm:"column:tls"`
}

type triageImageDetailResponse struct {
	Vulns     []TriageImageVuln `json:"vulns"`
	VulnTotal int               `json:"vuln_total"`
	Hosts     []TriageImageHost `json:"hosts"`
}

// triageImageVulnLimit caps the expansion panel — it's a "what drives
// this tier" summary, not the full finding list (that's the image
// profile page).
const triageImageVulnLimit = 20

// triageImageVEXFilter mirrors the VEX exclusion inside asset_risk's
// image_vuln_canonical CTE so the panel never lists a vuln the tier
// didn't count.
const triageImageVEXFilter = `
	NOT EXISTS (
		SELECT 1
		FROM component_vex vex
		LEFT JOIN vuln_metadata vmx ON vmx.vuln_id = vex.vuln_id
		JOIN sbom_component_view sc ON sc.purl = vex.p_url
		JOIN sbom_bindings sb       ON sb.sbom_id     = sc.sbom_id
		                           AND sb.asset_type = 'IMAGE_DIGEST'
		WHERE vex.status IN ('not_affected', 'fixed')
		  AND COALESCE(vmx.canonical_id, vex.vuln_id)
		      = COALESCE(vm.canonical_id, v.vuln_id)
		  AND sb.asset_ref_id::text = v.image_id
	)`

// TriageImageDetailHandler serves the lazy expansion data for an image
// triage row: the top KEV/EPSS-ranked CVEs and the exposed hosts that
// serve the digest. Fetched on row expand so /api/triage itself stays
// one MV scan.
//
// GET /api/triage/image/{id} — {id} is image_digests.id, which triage
// rows already carry as asset_id. ACL-gated by canReadImageByID, 404
// on both missing and forbidden so IDs aren't probeable.
func TriageImageDetailHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "image id required", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		var img struct {
			ID     string
			Digest string
		}
		if err := db.WithContext(ctx).
			Table("image_digests").
			Select("id, digest").
			Where("id = ?", id).
			First(&img).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				notFoundOrForbidden(w)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if ok, err := canReadImageByID(r, db, img.ID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		resp := triageImageDetailResponse{
			Vulns: []TriageImageVuln{},
			Hosts: []TriageImageHost{},
		}

		// Whether the digest is internet-reachable — feeds the on_path
		// projection below (an exposed critical is on the path even
		// without KEV/EPSS signal, mirroring the F4/W4 tier rules).
		var imgExposed bool
		if err := db.WithContext(ctx).Raw(
			"SELECT EXISTS (SELECT 1 FROM exposed_digests WHERE digest = ?)", img.Digest,
		).Scan(&imgExposed).Error; err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// One row per canonical vuln (a CVE hitting several packages
		// collapses to one panel row; prefer the occurrence that shows
		// a fix), on-path first, then KEV, then EPSS descending — the
		// same order the tier rules weigh them. The 0.1 EPSS cutoff is
		// assetrisk.EPSSElevated.
		vulnQ := `
			WITH canonical AS (
				SELECT DISTINCT ON (COALESCE(vm.canonical_id, v.vuln_id))
					v.vuln_id,
					COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
					v.severity,
					v.pkg_name,
					v.installed_version,
					v.fixed_version
				FROM view_unified_image_vulnerabilities v
				LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
				WHERE v.image_id = ?
				  AND ` + triageImageVEXFilter + `
				ORDER BY COALESCE(vm.canonical_id, v.vuln_id),
				         (v.fixed_version <> '') DESC,
				         v.vuln_id
			)
			SELECT
				c.vuln_id,
				c.canonical_id,
				c.severity,
				c.pkg_name,
				c.installed_version,
				c.fixed_version,
				COALESCE(e.score, 0)::real      AS epss,
				COALESCE(e.percentile, 0)::real AS epss_percentile,
				(k.cve_id IS NOT NULL)          AS kev,
				k.due_date                      AS kev_due_date,
				COALESCE(k.known_ransomware, false) AS kev_ransomware,
				(k.cve_id IS NOT NULL
				 OR COALESCE(e.score, 0) >= 0.1
				 OR (c.severity = 'CRITICAL' AND ?)) AS on_path
			FROM canonical c
			LEFT JOIN epss_entries e    ON e.cve_id = c.canonical_id
			LEFT JOIN cisa_kev_entries k ON k.cve_id = c.canonical_id
			ORDER BY (k.cve_id IS NOT NULL
			          OR COALESCE(e.score, 0) >= 0.1
			          OR (c.severity = 'CRITICAL' AND ?)) DESC,
			         (k.cve_id IS NOT NULL) DESC,
			         e.score DESC NULLS LAST,
			         CASE c.severity
			             WHEN 'CRITICAL' THEN 1
			             WHEN 'HIGH'     THEN 2
			             WHEN 'MEDIUM'   THEN 3
			             WHEN 'LOW'      THEN 4
			             ELSE 5
			         END,
			         c.canonical_id
			LIMIT ?
		`
		if err := db.WithContext(ctx).Raw(vulnQ, img.ID, imgExposed, imgExposed, triageImageVulnLimit).
			Scan(&resp.Vulns).Error; err != nil {
			http.Error(w, "failed to load image vulnerabilities", http.StatusInternalServerError)
			return
		}

		countQ := `
			SELECT COUNT(DISTINCT COALESCE(vm.canonical_id, v.vuln_id))
			FROM view_unified_image_vulnerabilities v
			LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
			WHERE v.image_id = ?
			  AND ` + triageImageVEXFilter
		if err := db.WithContext(ctx).Raw(countQ, img.ID).
			Scan(&resp.VulnTotal).Error; err != nil {
			http.Error(w, "failed to count image vulnerabilities", http.StatusInternalServerError)
			return
		}

		// Exposed domains serving this digest, via the same
		// exposed_digests projection the tier's exposure signals use.
		hostQ := `
			SELECT DISTINCT
				ed.host,
				COALESCE(he.cluster, '') AS cluster,
				ed.cluster_id,
				ed.namespace,
				COALESCE(he.tls, false)  AS tls
			FROM exposed_digests ed
			LEFT JOIN host_exposure he
			  ON he.cluster_id = ed.cluster_id
			 AND he.namespace  = ed.namespace
			 AND he.host       = ed.host
			 AND he.kind       = ed.exposure_kind
			 AND he.name       = ed.exposure_name
			WHERE ed.digest = ?
			ORDER BY ed.host, ed.cluster_id, ed.namespace
		`
		if err := db.WithContext(ctx).Raw(hostQ, img.Digest).
			Scan(&resp.Hosts).Error; err != nil {
			http.Error(w, "failed to load exposed hosts", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, resp)
	}
}
