package uiapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/cache"
	"gorm.io/gorm"

	"golang.org/x/sync/singleflight"
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

// TriageImageCluster is one cluster currently running the digest.
type TriageImageCluster struct {
	ClusterID string `json:"cluster_id" gorm:"column:cluster_id"`
	Name      string `json:"name"       gorm:"column:name"`
	// Namespaces is a comma-separated, sorted list of namespaces the
	// digest runs in within this cluster (same shape as the advisory
	// payload's runs_in).
	Namespaces string `json:"namespaces" gorm:"column:namespaces"`
	Exposed    bool   `json:"exposed"    gorm:"column:exposed"`
}

type triageImageDetailResponse struct {
	Vulns     []TriageImageVuln `json:"vulns"`
	VulnTotal int               `json:"vuln_total"`
	Hosts     []TriageImageHost `json:"hosts"`

	// Clusters lists only the clusters the caller can read;
	// ClusterTotal is the true count, so the UI can say "+N outside
	// your access" without naming them.
	Clusters     []TriageImageCluster `json:"clusters"`
	ClusterTotal int                  `json:"cluster_total"`
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

// triageImageDetailCacheTTL bounds how long a computed panel payload is
// served from cache. The underlying data (the vuln view, cluster
// records, exposure projections) refreshes on the scan/MV cadence, so a
// few minutes of staleness is invisible while sparing the DB the
// six-query scan on every row expand.
const triageImageDetailCacheTTL = 10 * time.Minute

// triageImageDetailSF collapses concurrent cold computes for the same
// image into one DB pass per replica. A 504 at the gateway tends to
// trigger client retries; without this, each retry would launch its own
// copy of the (already slow) six-query scan.
var triageImageDetailSF singleflight.Group

// triageImageDetailPayload is the ACL-independent slice of the panel:
// everything the six queries produce *before* per-caller cluster
// trimming. It's what we cache; AllClusters is the full, untrimmed set
// so ClusterTotal stays truthful for every caller.
type triageImageDetailPayload struct {
	Vulns       []TriageImageVuln    `json:"vulns"`
	VulnTotal   int                  `json:"vuln_total"`
	Hosts       []TriageImageHost    `json:"hosts"`
	AllClusters []TriageImageCluster `json:"all_clusters"`
}

// TriageImageDetailHandler serves the lazy expansion data for an image
// triage row: the top KEV/EPSS-ranked CVEs and the exposed hosts that
// serve the digest. Fetched on row expand so /api/triage itself stays
// one MV scan.
//
// The six-query scan is expensive enough to time out at the gateway
// (504), so the result is cached for triageImageDetailCacheTTL. On a
// miss the scan runs on a context detached from the request — a gateway
// timeout can't abort it mid-flight, so the cache still warms and the
// caller's retry is instant.
//
// GET /api/triage/image/{id} — {id} is image_digests.id, which triage
// rows already carry as asset_id. ACL-gated by canReadImageByID, 404
// on both missing and forbidden so IDs aren't probeable.
func TriageImageDetailHandler(db *gorm.DB, _ *auth.Service, c cache.Store) http.HandlerFunc {
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

		// Warm path: serve the cached, ACL-independent payload and apply
		// the caller's cluster trim (a cheap in-memory set intersection).
		cacheKey := "triage:image:detail:" + img.ID
		if payload, ok, _ := cache.GetJSON[triageImageDetailPayload](ctx, c, cacheKey); ok {
			writeTriageImageResponse(w, r, db, payload)
			return
		}

		// Cold path: compute on a context detached from the request so a
		// gateway timeout (the 504 this endpoint is prone to) can't abort
		// the scan mid-flight — the result still lands in the cache and
		// the caller's retry is instant.
		res := triageImageDetailSF.DoChan(cacheKey, func() (any, error) {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			defer cancel()
			payload, err := computeTriageImageDetail(cctx, db, img.ID, img.Digest)
			if err != nil {
				return nil, err
			}
			_ = cache.SetJSON(cctx, c, cacheKey, payload, triageImageDetailCacheTTL)
			return payload, nil
		})

		select {
		case <-ctx.Done():
			// Caller (or the gateway) gave up. The compute above keeps
			// running on its detached context and will warm the cache,
			// so there's nothing left to write here.
			return
		case out := <-res:
			if out.Err != nil {
				http.Error(w, "failed to load attack-path details", http.StatusInternalServerError)
				return
			}
			payload, _ := out.Val.(triageImageDetailPayload)
			writeTriageImageResponse(w, r, db, payload)
		}
	}
}

// writeTriageImageResponse applies the caller's cluster ACL to a cached
// payload and writes the panel response. ClusterTotal reflects the full
// set so the UI can say "+N outside your access" without naming them.
func writeTriageImageResponse(w http.ResponseWriter, r *http.Request, db *gorm.DB, payload triageImageDetailPayload) {
	resp := triageImageDetailResponse{
		Vulns:        payload.Vulns,
		VulnTotal:    payload.VulnTotal,
		Hosts:        payload.Hosts,
		Clusters:     []TriageImageCluster{},
		ClusterTotal: len(payload.AllClusters),
	}
	if resp.Vulns == nil {
		resp.Vulns = []TriageImageVuln{}
	}
	if resp.Hosts == nil {
		resp.Hosts = []TriageImageHost{}
	}

	readable, unrestricted, aclErr := readableClusterIDSet(r, db)
	if aclErr != nil {
		http.Error(w, "failed to scope results", http.StatusInternalServerError)
		return
	}
	for _, cl := range payload.AllClusters {
		if unrestricted {
			resp.Clusters = append(resp.Clusters, cl)
			continue
		}
		if _, ok := readable[cl.ClusterID]; ok {
			resp.Clusters = append(resp.Clusters, cl)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// computeTriageImageDetail runs the six-query panel scan: the full
// (untrimmed) cluster list, the digest's internet-exposure flag, the
// top KEV/EPSS-ranked CVEs, the total vuln count, and the exposed hosts
// serving the digest. It performs no ACL trimming — that's per caller.
func computeTriageImageDetail(ctx context.Context, db *gorm.DB, imageID, digest string) (triageImageDetailPayload, error) {
	payload := triageImageDetailPayload{
		Vulns:       []TriageImageVuln{},
		Hosts:       []TriageImageHost{},
		AllClusters: []TriageImageCluster{},
	}

	// Clusters currently running the digest, with per-cluster exposure.
	// The friendly name is read straight from the cluster_record JSONB
	// (ror_metadata.cluster_name, then the env-injected `cluster` label,
	// then the ROR slug) — the same source the image profile page uses.
	// The clusters-table join is only a secondary source for an admin
	// display_name override: cluster_record.cluster_id is the
	// kube-system UID, whereas clusters.cluster_id is the ROR slug, so
	// that join misses for most clusters and can't be relied on for the
	// name (which is why this panel used to show the raw UID).
	clusterQ := `
		SELECT
			cd.cluster_id,
			COALESCE(
				NULLIF(c.display_name, ''),
				NULLIF(cd.ror_cluster_name, ''),
				NULLIF(cd.cluster_label, ''),
				NULLIF(cd.ror_slug, ''),
				cd.cluster_id
			) AS name,
			cd.namespaces,
			EXISTS (
				SELECT 1 FROM publicly_exposed_digests ed
				WHERE ed.digest = ? AND ed.cluster_id = cd.cluster_id
			) AS exposed
		FROM (
			SELECT cr.data->>'cluster_id' AS cluster_id,
			       NULLIF(MAX(cr.data->'ror_metadata'->>'cluster_name'), '')        AS ror_cluster_name,
			       NULLIF(MAX(cr.data->'ror_metadata'->>'cluster_id'), '')          AS ror_slug,
			       NULLIF(MAX(NULLIF(cr.data->>'cluster', cr.data->>'cluster_id')), '') AS cluster_label,
			       string_agg(DISTINCT cr.data->>'namespace', ', ' ORDER BY cr.data->>'namespace') AS namespaces
			FROM cluster_record cr
			WHERE cr.data->>'kind' = 'Container'
			  AND cr.data->>'digest' = ?
			  AND COALESCE(cr.data->>'msg', '') <> 'DELETE'
			GROUP BY cr.data->>'cluster_id'
		) cd
		LEFT JOIN clusters c ON c.cluster_id = cd.cluster_id
		ORDER BY exposed DESC, name
	`
	if err := db.WithContext(ctx).Raw(clusterQ, digest, digest).
		Scan(&payload.AllClusters).Error; err != nil {
		return payload, err
	}

	// Whether the digest is internet-reachable — feeds the on_path
	// projection below (an exposed critical is on the path even without
	// KEV/EPSS signal, mirroring the F4/W4 tier rules).
	// publicly_exposed_digests gates on the host_resolution DNS verdict,
	// matching the asset_risk exposure signals.
	var imgExposed bool
	if err := db.WithContext(ctx).Raw(
		"SELECT EXISTS (SELECT 1 FROM publicly_exposed_digests WHERE digest = ?)", digest,
	).Scan(&imgExposed).Error; err != nil {
		return payload, err
	}

	// One row per canonical vuln (a CVE hitting several packages
	// collapses to one panel row; prefer the occurrence that shows a
	// fix), on-path first, then KEV, then EPSS descending — the same
	// order the tier rules weigh them. The 0.1 EPSS cutoff is
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
	if err := db.WithContext(ctx).Raw(vulnQ, imageID, imgExposed, imgExposed, triageImageVulnLimit).
		Scan(&payload.Vulns).Error; err != nil {
		return payload, err
	}

	countQ := `
		SELECT COUNT(DISTINCT COALESCE(vm.canonical_id, v.vuln_id))
		FROM view_unified_image_vulnerabilities v
		LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
		WHERE v.image_id = ?
		  AND ` + triageImageVEXFilter
	if err := db.WithContext(ctx).Raw(countQ, imageID).
		Scan(&payload.VulnTotal).Error; err != nil {
		return payload, err
	}

	// Exposed domains serving this digest, via the same exposed_digests
	// projection the tier's exposure signals use.
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
	if err := db.WithContext(ctx).Raw(hostQ, digest).
		Scan(&payload.Hosts).Error; err != nil {
		return payload, err
	}

	return payload, nil
}
