package scam

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"
)

// ClusterDetailHandler serves GET /api/cluster/{id} — the single-cluster
// detail surface, the cluster-scope analogue of /api/images/{id} and the
// repo detail endpoints. It bundles everything a Kubernetes viewer shows
// for one cluster into a single payload so the SPA renders the page from
// one round-trip:
//
//   - identity (cluster_id, env-var label, ROR binding, environment)
//   - headline counts (containers, images, namespaces, ingresses) sourced
//     from the cluster_summary MV so they match the /clusters list page
//   - a security severity breakdown (critical/high/medium/low/unknown)
//     summed over the latest scan of every running image in the cluster
//   - per-namespace rollups (workloads, pods, services, hosts)
//   - the running workload groups (owner-grouped containers)
//   - the exposed hosts (Ingress / Gateway-API / Traefik routes), read
//     live from cluster_record so they share the workloads' cluster key
//     and liveness window rather than the refresh-lagged host_exposure MV
//
// {id} accepts any of the cluster's identifiers — kube-system UID
// (cluster_id), ROR slug, ROR cluster name, or the admin display name —
// resolved through the clusters table before the ACL gate runs.
func ClusterDetailHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident := strings.TrimSpace(chi.URLParam(r, "id"))
		if ident == "" {
			http.Error(w, "missing cluster id", http.StatusBadRequest)
			return
		}
		ctx := r.Context()

		// 1. Resolve the {id|name} path param to the canonical cluster_id
		// (kube-system UID) used as the join key everywhere else. An exact
		// cluster_id match wins over a name/slug match.
		var resolved struct {
			ClusterID      string
			DisplayName    string
			RorSlug        string
			RorClusterName string
			RorEnv         string
		}
		_ = db.WithContext(ctx).Raw(`
			SELECT cluster_id, display_name, ror_slug, ror_cluster_name, ror_env
			FROM clusters
			WHERE cluster_id = ? OR ror_slug = ? OR ror_cluster_name = ? OR display_name = ?
			ORDER BY (cluster_id = ?) DESC
			LIMIT 1
		`, ident, ident, ident, ident, ident).Scan(&resolved).Error

		// Fall back to treating the raw param as a cluster_id so a kube UID
		// that predates its clusters-table row still resolves via the live
		// queries below.
		clusterID := resolved.ClusterID
		foundCluster := resolved.ClusterID != ""
		if clusterID == "" {
			clusterID = ident
		}

		// 2. ACL gate. Mirror the chain handler: never leak existence via a
		// differential error — an unreadable or unknown cluster is a 404.
		if ok, err := canReadCluster(r, db, clusterID); err != nil || !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// 3. Headline identity + counts from cluster_summary (matches the
		// numbers the /clusters list page shows). Absent on a cold MV — we
		// degrade to the live-derived counts assembled further down.
		var summary struct {
			ClusterName    string
			RorSlug        string
			RorClusterName string
			RorEnv         string
			Environment    string
			Containers     int64
			Images         int64
			Namespaces     int64
			IngressCount   int64
			LastSeen       *time.Time
		}
		if err := db.WithContext(ctx).Raw(`
			SELECT cluster_name, ror_slug, ror_cluster_name, ror_env, environment,
			       containers, images, namespaces, ingress_count, last_seen
			FROM cluster_summary
			WHERE cluster_id = ?
			LIMIT 1
		`, clusterID).Scan(&summary).Error; err == nil && summary.LastSeen != nil {
			foundCluster = true
		}

		// 4. Running workload groups — one row per (namespace, owner,
		// owner_kind), the same projection /api/clusters/chain uses.
		type podRow struct {
			Namespace      string `gorm:"column:namespace"`
			Owner          string `gorm:"column:owner"`
			OwnerKind      string `gorm:"column:owner_kind"`
			PodCount       int64  `gorm:"column:pod_count"`
			Phase          string `gorm:"column:phase"`
			ContainersJSON string `gorm:"column:containers_json"`
		}
		var podRows []podRow
		_ = db.WithContext(ctx).Raw(liveCTEForCluster+`
			SELECT
				data->>'namespace' AS namespace,
				data->>'owner' AS owner,
				data->>'owner_kind' AS owner_kind,
				COUNT(DISTINCT data->>'pod_uid') AS pod_count,
				MAX(data->>'pod_phase') AS phase,
				jsonb_agg(DISTINCT jsonb_build_object(
					'name', data->>'container',
					'image', data->>'image',
					'tag', data->>'tag',
					'digest', data->>'digest',
					'registry', data->>'registry'
				)) AS containers_json
			FROM live
			WHERE data->>'kind' = 'Container'
			  AND data->>'pod_phase' = 'Running'
			GROUP BY data->>'namespace', data->>'owner', data->>'owner_kind'
			ORDER BY data->>'namespace', data->>'owner'
		`, clusterID).Scan(&podRows).Error

		// 5. Services per namespace.
		type nsCount struct {
			Namespace string `gorm:"column:namespace"`
			Cnt       int64  `gorm:"column:cnt"`
		}
		var svcRows []nsCount
		_ = db.WithContext(ctx).Raw(liveCTEForCluster+`
			SELECT data->>'namespace' AS namespace, COUNT(DISTINCT data->>'name') AS cnt
			FROM live
			WHERE data->>'kind' = 'Service'
			GROUP BY data->>'namespace'
		`, clusterID).Scan(&svcRows).Error

		// 6. Exposed hosts (one row per host/route). Sourced from the same
		// live cluster_record CTE as the workload/service queries above —
		// NOT the host_exposure MV. The MV derives its cluster_id column by
		// preferring the ror_metadata-stamped variant across the rolling
		// cutover merge, so that id does not reliably equal the raw
		// cluster_id this page resolves and filters on everywhere else; the
		// MV is also refresh-lagged and carries no liveness filter. Reading
		// live (the projection HostChainHandler uses) keeps hosts on the
		// same cluster key — and the same liveness window — as the rest of
		// the payload, so the Hosts tab and the per-namespace exposure
		// counts populate in lockstep with the workloads they sit beside.
		type hostRow struct {
			Namespace    string `gorm:"column:namespace" json:"namespace"`
			Host         string `gorm:"column:host" json:"host"`
			Kind         string `gorm:"column:kind" json:"kind"`
			TLS          bool   `gorm:"column:tls" json:"tls"`
			IngressClass string `gorm:"column:ingress_class" json:"ingress_class,omitempty"`
			// hostresolve worker verdict: internal / external /
			// unresolvable, or pending when the worker hasn't reached
			// this host yet. Drives the Hosts-tab exposure filter.
			Classification string `gorm:"column:classification" json:"classification,omitempty"`
		}
		var hostRows []hostRow
		// Collapse to one row per (namespace, host, kind): the same host can
		// surface from several Ingress objects (e.g. an HTTP→HTTPS redirect
		// with tls=false alongside the real tls=true rule, or differing
		// ingress_class), which a plain DISTINCT would keep as separate rows
		// — duplicate host cards, and a duplicate {#each} key that crashes
		// the client. bool_or(tls) means "TLS if any record terminates it";
		// MAX picks a representative non-empty ingress_class.
		_ = db.WithContext(ctx).Raw(liveCTEForCluster+`
			SELECT
				g.namespace, g.host, g.kind, g.tls, g.ingress_class,
				COALESCE(hr.classification, 'pending') AS classification
			FROM (
			SELECT
				namespace, host, kind,
				bool_or(tls) AS tls,
				COALESCE(MAX(NULLIF(ingress_class, '')), '') AS ingress_class
			FROM (
				-- k8s Ingress: one row per rule.host.
				SELECT
					data->>'namespace' AS namespace,
					r->>'host' AS host,
					'Ingress' AS kind,
					jsonb_typeof(data->'tls') = 'array'
						AND jsonb_array_length(COALESCE(data->'tls','[]'::jsonb)) > 0 AS tls,
					COALESCE(data->>'ingress_class','') AS ingress_class
				FROM live
				CROSS JOIN LATERAL jsonb_array_elements(
					CASE jsonb_typeof(data->'rules') WHEN 'array' THEN data->'rules' ELSE '[]'::jsonb END
				) AS r
				WHERE data->>'kind' = 'Ingress'
				  AND NULLIF(r->>'host','') IS NOT NULL

				UNION ALL

				-- Gateway API: HTTPRoute / GRPCRoute / TLSRoute (hostnames[]).
				SELECT
					data->>'namespace',
					h,
					data->>'kind',
					FALSE,
					''
				FROM live
				CROSS JOIN LATERAL jsonb_array_elements_text(
					CASE jsonb_typeof(data->'hostnames') WHEN 'array' THEN data->'hostnames' ELSE '[]'::jsonb END
				) AS h
				WHERE data->>'kind' IN ('HTTPRoute','GRPCRoute','TLSRoute')
				  AND NULLIF(h,'') IS NOT NULL

				UNION ALL

				-- Traefik IngressRoute / IngressRouteTCP (hosts[]); tls
				-- implied by a non-empty tls_secret.
				SELECT
					data->>'namespace',
					h,
					data->>'kind',
					COALESCE(data->>'tls_secret','') <> '',
					''
				FROM live
				CROSS JOIN LATERAL jsonb_array_elements_text(
					CASE jsonb_typeof(data->'hosts') WHEN 'array' THEN data->'hosts' ELSE '[]'::jsonb END
				) AS h
				WHERE data->>'kind' IN ('IngressRoute','IngressRouteTCP')
				  AND NULLIF(h,'') IS NOT NULL
			) sub
			GROUP BY namespace, host, kind
			) g
			LEFT JOIN host_resolution hr ON hr.host = g.host
			ORDER BY g.namespace, g.host
		`, clusterID).Scan(&hostRows).Error

		// 7. Security severity breakdown. Walk the running images in the
		// cluster (cluster_image_inventory) to their image_digests row, take
		// the latest finished scan per digest, and sum the findings by
		// severity. This counts findings across running images — the same
		// per-image counting the Images tab uses, summed cluster-wide (a CVE
		// in two images counts twice).
		var sec struct {
			Critical int64
			High     int64
			Medium   int64
			Low      int64
			Unknown  int64
		}
		_ = db.WithContext(ctx).Raw(`
			WITH inv AS (
				SELECT DISTINCT cii.raw_registry, cii.image, cii.digest
				FROM cluster_image_inventory cii
				WHERE cii.cluster_id = ?
			),
			digests AS (
				SELECT id.id AS digest_id
				FROM inv
				JOIN image_digests id
				  ON id.registry   = inv.raw_registry
				 AND id.repository = inv.image
				 AND id.digest     = inv.digest
			),
			latest_scan AS (
				SELECT DISTINCT ON (isr.image_digest_id)
				       isr.id AS scan_run_id
				FROM image_scan_runs isr
				WHERE isr.finished_at IS NOT NULL
				  AND isr.image_digest_id IN (SELECT digest_id FROM digests)
				ORDER BY isr.image_digest_id, isr.finished_at DESC
			)
			SELECT
				COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL')            AS critical,
				COUNT(*) FILTER (WHERE UPPER(severity) = 'HIGH')                AS high,
				COUNT(*) FILTER (WHERE UPPER(severity) = 'MEDIUM')              AS medium,
				COUNT(*) FILTER (WHERE UPPER(severity) IN ('LOW','NEGLIGIBLE')) AS low,
				COUNT(*) FILTER (WHERE UPPER(severity) NOT IN ('CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE')) AS unknown
			FROM image_vuln_findings f
			JOIN latest_scan ls ON ls.scan_run_id = f.scan_run_id
		`, clusterID).Scan(&sec).Error

		// 7b. Per-image security stats keyed by digest, so each container in
		// the workload list can carry its own vuln counts / KEV / EPSS. Same
		// inventory → digest → latest-scan walk as the cluster-wide sum
		// above, but GROUPed per digest and joined to the CISA-KEV and EPSS
		// feeds. Findings collapse to their canonical CVE via vuln_metadata
		// so an alias set (CVE ⇿ GHSA ⇿ …) counts once for KEV/EPSS.
		type digestVulnRow struct {
			Digest   string  `gorm:"column:digest"`
			Critical int64   `gorm:"column:critical"`
			High     int64   `gorm:"column:high"`
			Medium   int64   `gorm:"column:medium"`
			Low      int64   `gorm:"column:low"`
			Total    int64   `gorm:"column:total"`
			KEV      int64   `gorm:"column:kev"`
			EPSSMax  float64 `gorm:"column:epss_max"`
		}
		var digestVulns []digestVulnRow
		_ = db.WithContext(ctx).Raw(`
			WITH inv AS (
				SELECT DISTINCT cii.raw_registry, cii.image, cii.digest
				FROM cluster_image_inventory cii
				WHERE cii.cluster_id = ?
			),
			digests AS (
				SELECT id.id AS digest_id, id.digest AS digest
				FROM inv
				JOIN image_digests id
				  ON id.registry   = inv.raw_registry
				 AND id.repository = inv.image
				 AND id.digest     = inv.digest
			),
			latest_scan AS (
				SELECT DISTINCT ON (isr.image_digest_id)
				       isr.image_digest_id, isr.id AS scan_run_id
				FROM image_scan_runs isr
				WHERE isr.finished_at IS NOT NULL
				  AND isr.image_digest_id IN (SELECT digest_id FROM digests)
				ORDER BY isr.image_digest_id, isr.finished_at DESC
			),
			findings AS (
				SELECT
					ls.image_digest_id,
					f.severity,
					COALESCE(NULLIF(vm.canonical_id, ''), f.vuln_id) AS canonical_id
				FROM latest_scan ls
				JOIN image_vuln_findings f ON f.scan_run_id = ls.scan_run_id
				LEFT JOIN vuln_metadata vm ON vm.vuln_id = f.vuln_id
				WHERE f.vuln_id <> '' AND f.vuln_id <> '_none'
			)
			SELECT
				d.digest AS digest,
				COUNT(*) FILTER (WHERE UPPER(fd.severity) = 'CRITICAL')            AS critical,
				COUNT(*) FILTER (WHERE UPPER(fd.severity) = 'HIGH')                AS high,
				COUNT(*) FILTER (WHERE UPPER(fd.severity) = 'MEDIUM')              AS medium,
				COUNT(*) FILTER (WHERE UPPER(fd.severity) IN ('LOW','NEGLIGIBLE')) AS low,
				COUNT(*)                                                           AS total,
				COUNT(DISTINCT fd.canonical_id) FILTER (
					WHERE EXISTS (SELECT 1 FROM cisa_kev_entries k WHERE k.cve_id = fd.canonical_id)
				)                                                                  AS kev,
				COALESCE(MAX(e.score), 0)                                          AS epss_max
			FROM digests d
			JOIN findings fd ON fd.image_digest_id = d.digest_id
			LEFT JOIN epss_entries e ON e.cve_id = fd.canonical_id
			GROUP BY d.digest
		`, clusterID).Scan(&digestVulns).Error

		vulnByDigest := make(map[string]digestVulnRow, len(digestVulns))
		for _, dv := range digestVulns {
			vulnByDigest[dv.Digest] = dv
		}

		// ---- assemble ----
		type containerVuln struct {
			Critical int64   `json:"critical"`
			High     int64   `json:"high"`
			Medium   int64   `json:"medium"`
			Low      int64   `json:"low"`
			Total    int64   `json:"total"`
			KEV      int64   `json:"kev"`
			EPSS     float64 `json:"epss"`
		}
		type container struct {
			Name     string         `json:"name"`
			Image    string         `json:"image"`
			Tag      string         `json:"tag"`
			Digest   string         `json:"digest,omitempty"`
			Registry string         `json:"registry"`
			Vuln     *containerVuln `json:"vuln,omitempty"`
		}
		type workloadGroup struct {
			Namespace  string      `json:"namespace"`
			Owner      string      `json:"owner"`
			OwnerKind  string      `json:"owner_kind"`
			PodCount   int64       `json:"pod_count"`
			Phase      string      `json:"phase"`
			Containers []container `json:"containers"`
		}
		type namespaceSummary struct {
			Namespace string `json:"namespace"`
			Workloads int    `json:"workloads"`
			Pods      int64  `json:"pods"`
			Services  int64  `json:"services"`
			Hosts     int    `json:"hosts"`
		}

		// Hide admin-curated namespaces (nhn-scam, nhn-ror, …) from
		// non-admin callers, matching /api/clusters/chain. Applied to the
		// per-namespace rollups, workloads, and hosts below so a regular
		// user's cluster view stays focused on their own namespaces.
		// Admin/global_reader get an always-false matcher (no filtering).
		isNamespaceHidden := hiddenNamespaceMatch(r, db)
		hidAnyNamespace := false

		workloads := make([]workloadGroup, 0, len(podRows))
		nsAgg := map[string]*namespaceSummary{}
		getNS := func(ns string) *namespaceSummary {
			if c, ok := nsAgg[ns]; ok {
				return c
			}
			c := &namespaceSummary{Namespace: ns}
			nsAgg[ns] = c
			return c
		}

		for _, p := range podRows {
			if isNamespaceHidden(p.Namespace) {
				hidAnyNamespace = true
				continue
			}
			cs := []container{}
			if p.ContainersJSON != "" {
				_ = json.Unmarshal([]byte(p.ContainersJSON), &cs)
			}
			// Attach per-digest vuln stats. Keyed on the same digest string
			// the live container projection emits, which matches
			// cluster_image_inventory.digest / image_digests.digest.
			for i := range cs {
				if cs[i].Digest == "" {
					continue
				}
				if dv, ok := vulnByDigest[cs[i].Digest]; ok {
					cs[i].Vuln = &containerVuln{
						Critical: dv.Critical, High: dv.High, Medium: dv.Medium,
						Low: dv.Low, Total: dv.Total, KEV: dv.KEV, EPSS: dv.EPSSMax,
					}
				}
			}
			workloads = append(workloads, workloadGroup{
				Namespace: p.Namespace, Owner: p.Owner, OwnerKind: p.OwnerKind,
				PodCount: p.PodCount, Phase: p.Phase, Containers: cs,
			})
			n := getNS(p.Namespace)
			n.Workloads++
			n.Pods += p.PodCount
		}
		visibleServiceNS := 0
		for _, s := range svcRows {
			if isNamespaceHidden(s.Namespace) {
				hidAnyNamespace = true
				continue
			}
			getNS(s.Namespace).Services = s.Cnt
			visibleServiceNS++
		}
		hosts := make([]hostRow, 0, len(hostRows))
		for _, h := range hostRows {
			if isNamespaceHidden(h.Namespace) {
				hidAnyNamespace = true
				continue
			}
			hosts = append(hosts, h)
			getNS(h.Namespace).Hosts++
		}
		if len(podRows) > 0 || len(svcRows) > 0 || len(hostRows) > 0 {
			foundCluster = true
		}

		// Admins can hit any id; everyone else is grant-gated above. If the
		// id matched nothing at all, it's a 404 (consistent with chain).
		if !foundCluster {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		namespaces := make([]namespaceSummary, 0, len(nsAgg))
		for _, n := range nsAgg {
			namespaces = append(namespaces, *n)
		}
		sort.Slice(namespaces, func(i, j int) bool {
			return namespaces[i].Namespace < namespaces[j].Namespace
		})

		// Identity: prefer the MV values (env-var label / ROR binding) and
		// fall back to the clusters-table row resolved up top.
		clusterName := firstNonEmpty(summary.ClusterName)
		rorSlug := firstNonEmpty(summary.RorSlug, resolved.RorSlug)
		rorName := firstNonEmpty(summary.RorClusterName, resolved.RorClusterName)
		rorEnv := firstNonEmpty(summary.RorEnv, resolved.RorEnv)
		displayName := firstNonEmpty(rorName, clusterName, rorSlug, resolved.DisplayName, clusterID)

		ror := newRorMetadata(rorSlug, rorName, rorEnv)

		// Pod total derived from workload groups (cluster_summary doesn't
		// carry a pod count, only containers).
		var podTotal int64
		for _, w := range workloads {
			podTotal += w.PodCount
		}

		resp := struct {
			ClusterID   string          `json:"cluster_id"`
			DisplayName string          `json:"display_name"`
			ClusterName string          `json:"cluster_name,omitempty"`
			RorMetadata *rorMetadataDTO `json:"ror_metadata,omitempty"`
			Environment string          `json:"environment,omitempty"`
			LastSeen    *time.Time      `json:"last_seen,omitempty"`
			Counts      struct {
				Containers int64 `json:"containers"`
				Images     int64 `json:"images"`
				Namespaces int   `json:"namespaces"`
				Ingresses  int64 `json:"ingresses"`
				Workloads  int   `json:"workloads"`
				Pods       int64 `json:"pods"`
				Services   int   `json:"services"`
				Hosts      int   `json:"hosts"`
			} `json:"counts"`
			Security struct {
				Critical int64 `json:"critical"`
				High     int64 `json:"high"`
				Medium   int64 `json:"medium"`
				Low      int64 `json:"low"`
				Unknown  int64 `json:"unknown"`
				Total    int64 `json:"total"`
			} `json:"security"`
			Namespaces []namespaceSummary `json:"namespaces"`
			Workloads  []workloadGroup    `json:"workloads"`
			Hosts      []hostRow          `json:"hosts"`
		}{
			ClusterID:   clusterID,
			DisplayName: displayName,
			ClusterName: clusterName,
			RorMetadata: ror,
			Environment: summary.Environment,
			LastSeen:    summary.LastSeen,
			Namespaces:  namespaces,
			Workloads:   workloads,
			Hosts:       hosts,
		}
		resp.Counts.Containers = summary.Containers
		resp.Counts.Images = summary.Images
		// Namespace card uses the MV count when present (matches the list
		// page) and the live-derived namespace set otherwise. When hidden
		// namespaces were filtered out, the MV count over-counts, so fall
		// back to the filtered live set so the card matches the list shown.
		if summary.Namespaces > 0 && !hidAnyNamespace {
			resp.Counts.Namespaces = int(summary.Namespaces)
		} else {
			resp.Counts.Namespaces = len(namespaces)
		}
		resp.Counts.Ingresses = summary.IngressCount
		resp.Counts.Workloads = len(workloads)
		resp.Counts.Pods = podTotal
		resp.Counts.Services = visibleServiceNS
		resp.Counts.Hosts = len(hosts)

		resp.Security.Critical = sec.Critical
		resp.Security.High = sec.High
		resp.Security.Medium = sec.Medium
		resp.Security.Low = sec.Low
		resp.Security.Unknown = sec.Unknown
		resp.Security.Total = sec.Critical + sec.High + sec.Medium + sec.Low + sec.Unknown

		writeJSON(w, http.StatusOK, resp)
	}
}

// firstNonEmpty returns the first non-empty string in vs, or "".
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ClusterVulnerabilitiesHandler serves GET /api/cluster/{id}/vulnerabilities
// — the advisory list for one cluster, the lazy companion to the cluster
// detail surface. It walks the cluster's running images
// (cluster_image_inventory) to the latest finished scan per digest and
// groups every finding by its canonical CVE (collapsing alias sets via
// vuln_metadata), so the cluster page can show a /vulnerabilities-style
// findings list scoped to what's actually running here.
//
// Per advisory it returns: the worst severity seen, advisory title +
// description (from vuln_metadata), whether any affected image has a fix,
// the count of affected running images + packages, KEV membership, and the
// max EPSS. Sorted severity → KEV → EPSS, capped so a pathological cluster
// can't ship an unbounded payload (truncated flips true at the cap).
func ClusterVulnerabilitiesHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ident := strings.TrimSpace(chi.URLParam(r, "id"))
		if ident == "" {
			http.Error(w, "missing cluster id", http.StatusBadRequest)
			return
		}
		ctx := r.Context()

		// Resolve {id|name} → canonical cluster_id, mirroring
		// ClusterDetailHandler so both endpoints accept the same params.
		var resolved struct{ ClusterID string }
		_ = db.WithContext(ctx).Raw(`
			SELECT cluster_id FROM clusters
			WHERE cluster_id = ? OR ror_slug = ? OR ror_cluster_name = ? OR display_name = ?
			ORDER BY (cluster_id = ?) DESC
			LIMIT 1
		`, ident, ident, ident, ident, ident).Scan(&resolved).Error
		clusterID := resolved.ClusterID
		if clusterID == "" {
			clusterID = ident
		}

		if ok, err := canReadCluster(r, db, clusterID); err != nil || !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		const vulnLimit = 750

		type vulnRow struct {
			VulnID       string  `gorm:"column:vuln_id"`
			Severity     string  `gorm:"column:severity"`
			Title        string  `gorm:"column:title"`
			Description  string  `gorm:"column:description"`
			HasFix       bool    `gorm:"column:has_fix"`
			ImageCount   int64   `gorm:"column:image_count"`
			PackageCount int64   `gorm:"column:package_count"`
			KEV          bool    `gorm:"column:kev"`
			EPSS         float64 `gorm:"column:epss"`
		}
		var rows []vulnRow
		_ = db.WithContext(ctx).Raw(`
			WITH inv AS (
				SELECT DISTINCT cii.raw_registry, cii.image, cii.digest
				FROM cluster_image_inventory cii
				WHERE cii.cluster_id = ?
			),
			digests AS (
				SELECT id.id AS digest_id
				FROM inv
				JOIN image_digests id
				  ON id.registry   = inv.raw_registry
				 AND id.repository = inv.image
				 AND id.digest     = inv.digest
			),
			latest_scan AS (
				SELECT DISTINCT ON (isr.image_digest_id)
				       isr.image_digest_id, isr.id AS scan_run_id
				FROM image_scan_runs isr
				WHERE isr.finished_at IS NOT NULL
				  AND isr.image_digest_id IN (SELECT digest_id FROM digests)
				ORDER BY isr.image_digest_id, isr.finished_at DESC
			),
			findings AS (
				SELECT
					ls.image_digest_id,
					COALESCE(NULLIF(vm.canonical_id, ''), f.vuln_id) AS canonical_id,
					f.severity AS severity,
					f.pkg_name AS pkg_name,
					COALESCE(f.fixed_version, '') AS fixed_version,
					NULLIF(vm.title, '')       AS title,
					NULLIF(vm.description, '') AS description
				FROM latest_scan ls
				JOIN image_vuln_findings f ON f.scan_run_id = ls.scan_run_id
				LEFT JOIN vuln_metadata vm ON vm.vuln_id = f.vuln_id
				WHERE f.vuln_id <> '' AND f.vuln_id <> '_none'
			),
			grouped AS (
				SELECT
					fd.canonical_id AS vuln_id,
					CASE
						WHEN bool_or(UPPER(fd.severity) = 'CRITICAL')              THEN 'CRITICAL'
						WHEN bool_or(UPPER(fd.severity) = 'HIGH')                  THEN 'HIGH'
						WHEN bool_or(UPPER(fd.severity) = 'MEDIUM')                THEN 'MEDIUM'
						WHEN bool_or(UPPER(fd.severity) IN ('LOW','NEGLIGIBLE'))   THEN 'LOW'
						ELSE 'UNKNOWN'
					END AS severity,
					MAX(fd.title)       AS title,
					MAX(fd.description) AS description,
					bool_or(fd.fixed_version <> '')        AS has_fix,
					COUNT(DISTINCT fd.image_digest_id)     AS image_count,
					COUNT(DISTINCT fd.pkg_name)            AS package_count,
					EXISTS (SELECT 1 FROM cisa_kev_entries k WHERE k.cve_id = fd.canonical_id) AS kev,
					COALESCE((SELECT MAX(e.score) FROM epss_entries e WHERE e.cve_id = fd.canonical_id), 0) AS epss
				FROM findings fd
				GROUP BY fd.canonical_id
			)
			SELECT vuln_id, severity, title, description, has_fix, image_count, package_count, kev, epss
			FROM grouped
			ORDER BY
				CASE severity
					WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
					WHEN 'LOW' THEN 3 ELSE 4
				END,
				kev DESC,
				epss DESC,
				vuln_id
			LIMIT ?
		`, clusterID, vulnLimit+1).Scan(&rows).Error

		truncated := false
		if len(rows) > vulnLimit {
			rows = rows[:vulnLimit]
			truncated = true
		}

		type clusterVuln struct {
			VulnID       string  `json:"vuln_id"`
			Severity     string  `json:"severity"`
			Title        string  `json:"title,omitempty"`
			Description  string  `json:"description,omitempty"`
			HasFix       bool    `json:"has_fix"`
			ImageCount   int64   `json:"image_count"`
			PackageCount int64   `json:"package_count"`
			KEV          bool    `json:"kev"`
			EPSS         float64 `json:"epss"`
		}
		items := make([]clusterVuln, 0, len(rows))
		for _, v := range rows {
			// Trim long advisory text rune-safely so the payload stays
			// lean — the detail page (/vuln/{id}) has the full text.
			desc := strings.TrimSpace(v.Description)
			if r := []rune(desc); len(r) > 300 {
				desc = strings.TrimSpace(string(r[:300])) + "…"
			}
			items = append(items, clusterVuln{
				VulnID: v.VulnID, Severity: v.Severity, Title: strings.TrimSpace(v.Title),
				Description: desc, HasFix: v.HasFix, ImageCount: v.ImageCount,
				PackageCount: v.PackageCount, KEV: v.KEV, EPSS: v.EPSS,
			})
		}

		writeJSON(w, http.StatusOK, struct {
			Total     int           `json:"total"`
			Truncated bool          `json:"truncated"`
			Items     []clusterVuln `json:"items"`
		}{Total: len(items), Truncated: truncated, Items: items})
	}
}
