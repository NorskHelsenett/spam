package uiapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/scam"
	"github.com/NorskHelsenett/spam/internal/vulnmeta"
	"gorm.io/gorm"
)

// writeImageScanRunResponse fills a RunResponse for an IMAGE_SCAN job. The
// struct parameter comes from RunGetHandler's local select so we reuse the
// row without re-querying.
func writeImageScanRunResponse(w http.ResponseWriter, r *http.Request, db *gorm.DB, job struct {
	ID              string
	Type            string
	Status          string
	Payload         []byte
	Error           string
	CommitHash      string
	CreatedAt       time.Time
	LockedAt        *time.Time
	LastAttemptedAt *time.Time
	FinishedAt      *time.Time
	K8sJobName      string `gorm:"column:k8s_job_name"`
	Result          []byte
}, runID string) {
	var payload jobs.ImageScanPayload
	if len(job.Payload) > 0 {
		_ = json.Unmarshal(job.Payload, &payload)
	}

	response := RunResponse{
		ID:              job.ID,
		Type:            job.Type,
		Status:          job.Status,
		RepoPath:        imageRefShortDisplay(payload.Registry, payload.Repository, payload.Digest),
		Error:           job.Error,
		CreatedAt:       job.CreatedAt,
		StartedAt:       pickStartedAt(job.LastAttemptedAt, job.LockedAt),
		FinishedAt:      job.FinishedAt,
		ImageRegistry:   payload.Registry,
		ImageRepository: payload.Repository,
		ImageDigest:     payload.Digest,
		ImageDigestID:   payload.ImageDigestID,
		ImageScanners:   payload.Scanners,
	}

	// Surface per-category scanner failures recorded on the job so the UI
	// can flag runs where SBOM/vuln/etc. silently skipped even though the
	// overall status is SUCCEEDED.
	if len(job.Result) > 0 {
		var rm struct {
			PartialFailures map[string]string `json:"partial_failures"`
		}
		if err := json.Unmarshal(job.Result, &rm); err == nil && len(rm.PartialFailures) > 0 {
			response.PartialFailures = rm.PartialFailures
		}
	}

	// Artifact summaries. Content is served on demand via
	// /api/image-scans/:id/artifacts/:artifact_id/download.
	var rows []imagescan.ImageScanArtifact
	if err := db.WithContext(r.Context()).
		Where("scan_run_id = ?", runID).
		Order("created_at ASC").
		Select("id, category, scanner, filename, size, created_at").
		Find(&rows).Error; err != nil {
		log.Printf("image scan artifacts for %s: %v", runID, err)
	} else {
		response.ImageArtifacts = make([]ImageArtifactSummary, 0, len(rows))
		for _, a := range rows {
			response.ImageArtifacts = append(response.ImageArtifacts, ImageArtifactSummary{
				ID:        a.ID,
				Category:  a.Category,
				Scanner:   a.Scanner,
				Filename:  a.Filename,
				Size:      a.Size,
				CreatedAt: a.CreatedAt,
			})
		}
	}

	// Link the image's latest SBOM (stored via existing artifacts pipeline)
	// so the detail page can offer the same "view components" action as
	// repo runs.
	if payload.ImageDigestID != "" {
		var binding struct {
			SBOMID string `gorm:"column:sbom_id"`
		}
		if err := db.WithContext(r.Context()).Table("sbom_bindings").
			Where("asset_type = ? AND asset_ref_id = ?", "IMAGE_DIGEST", payload.ImageDigestID).
			Order("created_at DESC").
			Select("sbom_id").First(&binding).Error; err == nil {
			response.SBOMID = binding.SBOMID
		}
	}

	// Severity summary from the grype parser output. Keyed by
	// image_digest_id rather than scan_run_id: the nightly sbom-scanner
	// revuln deletes prior grype findings and re-inserts under a fresh
	// scan_run_id (uuid.NewString() disjoint from the original job.id —
	// see runner/sbom_scan_handlers.grypeImageResultHandler). A query
	// scoped to scan_run_id=job.id silently misses every revunned row,
	// surfacing as "No vulnerabilities found." even on actively scanned
	// images. The parser deletes per (image_digest_id, scanner), so the
	// table only ever holds the latest findings for the image — exactly
	// what this view should display.
	if payload.ImageDigestID != "" {
		var severityRows []struct {
			Severity string
			Count    int
		}
		if err := db.WithContext(r.Context()).
			Table("image_vuln_findings").
			Select("severity, COUNT(*) AS count").
			Where("image_digest_id = ?", payload.ImageDigestID).
			Group("severity").
			Find(&severityRows).Error; err == nil && len(severityRows) > 0 {
			counts := &ImageVulnSeverityCount{}
			for _, row := range severityRows {
				counts.Total += row.Count
				// Normalize — grype uppercases, trivy lowercases, NEGLIGIBLE
				// is grype's info tier and rolls into Low.
				switch strings.ToUpper(row.Severity) {
				case "CRITICAL":
					counts.Critical += row.Count
				case "HIGH":
					counts.High += row.Count
				case "MEDIUM":
					counts.Medium += row.Count
				case "LOW", "NEGLIGIBLE":
					counts.Low += row.Count
				default:
					counts.Unknown += row.Count
				}
			}
			response.ImageVulnCounts = counts
		}

		// Full vuln list (capped at 1000 rows, severity-sorted). For larger
		// findings the UI offers the raw artifact download. Same
		// image_digest_id keying as the severity summary above.
		var findings []imagescan.ImageVulnFinding
		if err := db.WithContext(r.Context()).
			Where("image_digest_id = ?", payload.ImageDigestID).
			Order(`
				CASE UPPER(severity)
					WHEN 'CRITICAL' THEN 0
					WHEN 'HIGH'     THEN 1
					WHEN 'MEDIUM'   THEN 2
					WHEN 'LOW'      THEN 3
					ELSE 4
				END,
				vuln_id ASC
			`).
			Limit(1000).
			Find(&findings).Error; err == nil {
			// Load metadata for every distinct vuln_id so we can override
			// the scanner-reported fix_version per row with the OSV-
			// derived applicable fix. Cache miss keeps the scanner value.
			ids := make([]string, 0, len(findings))
			seen := map[string]struct{}{}
			for _, f := range findings {
				if _, ok := seen[f.VulnID]; ok {
					continue
				}
				seen[f.VulnID] = struct{}{}
				ids = append(ids, f.VulnID)
			}
			metas, _ := vulnmeta.MetadataForMany(r.Context(), db, ids)

			response.ImageVulns = make([]ImageVulnListRow, 0, len(findings))
			for _, f := range findings {
				fix := f.FixedVersion
				if m := metas[f.VulnID]; m != nil {
					if applicable := vulnmeta.ApplicableFix(
						vulnmeta.ExtractOSVAffected(m), f.PkgName, f.InstalledVersion,
					); applicable != "" {
						fix = applicable
					}
				}
				response.ImageVulns = append(response.ImageVulns, ImageVulnListRow{
					VulnID:           f.VulnID,
					Severity:         f.Severity,
					PkgName:          f.PkgName,
					InstalledVersion: f.InstalledVersion,
					FixedVersion:     fix,
					Title:            f.Title,
					Target:           f.Target,
					Scanner:          f.Scanner,
				})
			}
		}
	}

	// Load raw artifact blobs in one round-trip and parse in-process.
	// Small responses (labels, cosign) are fully inlined; secrets are
	// capped at 500 rows (pathological images can have thousands).
	var blobs []imagescan.ImageScanArtifact
	_ = db.WithContext(r.Context()).
		Select("category, scanner, content").
		Where("scan_run_id = ?", runID).
		Find(&blobs).Error

	for _, b := range blobs {
		switch b.Category {
		case "labels":
			response.ImageLabels, response.ImageLabelsMetadata = parseLabelsArtifact(b.Content)
		case "signature":
			response.ImageSignature = parseSignatureArtifact(b.Content)
		case "secrets":
			if b.Scanner == "betterleaks" {
				response.ImageSecrets = parseBetterleaksArtifact(b.Content, 500)
			}
		}
	}

	// If the image has a cached source_repo_id (populated on scan upload
	// from the OCI image.source label), resolve it into a client-facing
	// summary. Self-attested — the UI frames it as a claim.
	if payload.ImageDigestID != "" {
		if linked := loadLinkedRepo(r.Context(), db, payload.ImageDigestID); linked != nil {
			if response.ImageLabels != nil {
				linked.Source = response.ImageLabels["org.opencontainers.image.source"]
				linked.Revision = response.ImageLabels["org.opencontainers.image.revision"]
			}
			response.ImageLinkedRepo = linked
		}
	}

	// SBOM component count. Use the helper so newly-created SBOMs have a
	// non-zero count before the materialized view is next refreshed —
	// sbomComponentCount falls back to parsing the raw SBOM content when
	// sbom_component_view has no rows for this id yet.
	if response.SBOMID != "" {
		var sbom struct {
			Format       string
			ContentBytes []byte
		}
		if err := db.WithContext(r.Context()).Table("sboms").
			Select("format, content_bytes").
			Where("id = ?", response.SBOMID).
			First(&sbom).Error; err == nil {
			response.SBOMComponentCount = int(sbomComponentCount(r.Context(), db, response.SBOMID, sbom.Format, sbom.ContentBytes))
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// parseLabelsArtifact extracts labels + OCI metadata from a raw
// `crane config` JSON blob. Returns (nil, nil) when the blob can't be
// parsed — we never want a bad artifact to sink the whole detail page.
func parseLabelsArtifact(raw []byte) (map[string]string, *ImageOCIMetadata) {
	if len(raw) == 0 {
		return nil, nil
	}
	var config struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Created      string `json:"created"`
		Author       string `json:"author"`
		Config       struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, nil
	}
	meta := &ImageOCIMetadata{
		Created:      config.Created,
		Architecture: config.Architecture,
		OS:           config.OS,
		Author:       config.Author,
	}
	return config.Config.Labels, meta
}

// parseSignatureArtifact reads the JSON our runner writes for the cosign
// category (see runner/imagescan/imagescan.go::runSignature).
func parseSignatureArtifact(raw []byte) *ImageSignatureInfo {
	if len(raw) == 0 {
		return nil
	}
	var payload struct {
		Signed   bool   `json:"signed"`
		Verified bool   `json:"verified"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return &ImageSignatureInfo{
		Signed:   payload.Signed,
		Verified: payload.Verified,
		Error:    payload.Error,
	}
}

// parseBetterleaksArtifact decodes the betterleaks JSON report, truncates
// matches so one big payload doesn't balloon the response, and caps the
// total returned row count. Field names follow betterleaks' gitleaks-
// compatible schema.
func parseBetterleaksArtifact(raw []byte, maxRows int) []ImageSecretListRow {
	if len(raw) == 0 {
		return nil
	}
	var entries []struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
		StartLine   int    `json:"StartLine"`
		Match       string `json:"Match"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil
	}
	if len(entries) == 0 {
		return nil
	}
	if maxRows > 0 && len(entries) > maxRows {
		entries = entries[:maxRows]
	}
	out := make([]ImageSecretListRow, 0, len(entries))
	for _, e := range entries {
		match := e.Match
		if len(match) > 160 {
			match = match[:160] + "…"
		}
		out = append(out, ImageSecretListRow{
			RuleID:      e.RuleID,
			Description: e.Description,
			File:        e.File,
			StartLine:   e.StartLine,
			Match:       match,
		})
	}
	return out
}

// ImageDetailResponse aggregates everything the /app/images/{digest} page
// needs in one round-trip: image identity, the claimed source repo,
// where the image is running in your clusters, and a scan-history
// list. The latest successful scan's full findings live under its
// dedicated run_id — the client follows that with a separate
// /api/runs/{id} fetch so the existing RunResponse decoding (and
// ImageScanDetail component) is reused as-is.
type ImageDetailResponse struct {
	ID         string    `json:"id"`
	Registry   string    `json:"registry"`
	Repository string    `json:"repository"`
	Digest     string    `json:"digest"`
	CreatedAt  time.Time `json:"created_at"`

	LinkedRepo             *LinkedRepoSummary       `json:"linked_repo,omitempty"`
	LinkedRepoContributors []ImageRepoContributor   `json:"linked_repo_contributors,omitempty"`

	ScanHistory  []ImageScanHistoryRow `json:"scan_history,omitempty"`
	LatestScanID string                `json:"latest_scan_id,omitempty"`

	// Severity breakdown for the latest successful scan's findings. Lets the
	// drawer show a quick "critical / high / medium / low" badge row without
	// pulling every finding.
	VulnSeverity *ImageVulnSeverityCount `json:"vuln_severity,omitempty"`

	// SecretCount is the number of findings in the most recent betterleaks
	// artifact for this digest. Drives the "secrets" chip on the image
	// drawer + cmd+k preview without pulling the full JSON blob.
	SecretCount int64 `json:"secret_count"`

	ClusterUsage []ImageClusterUsageRow `json:"cluster_usage,omitempty"`
}

// ImageRepoContributor is a trimmed contributor entry pulled from the linked
// repo's cached /providers/details response. Drives the "recent committers"
// strip in the image drawer so operators can eyeball who's been touching the
// source of a vulnerable image without navigating to the repo page.
type ImageRepoContributor struct {
	Login         string `json:"login,omitempty"`
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	AvatarURL     string `json:"avatar_url,omitempty"`
	ProfileURL    string `json:"profile_url,omitempty"`
	Contributions int    `json:"contributions,omitempty"`
}

// ImageScanHistoryRow is one row in the per-image scan history.
type ImageScanHistoryRow struct {
	JobID      string     `json:"job_id"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	VulnCount  int        `json:"vuln_count"`
}

// ImageClusterUsageRow aggregates pod observations of a digest per
// (cluster, namespace). Pulled from cluster_record so the page shows
// *where* an image is actually deployed without needing a fresh K8s
// query.
type ImageClusterUsageRow struct {
	Cluster   string    `json:"cluster"`
	Namespace string    `json:"namespace"`
	PodCount  int       `json:"pod_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ImageDetailHandler returns the image-profile payload.
// GET /api/images/{id}
func ImageDetailHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "image reference required", http.StatusBadRequest)
			return
		}

		var img struct {
			ID             string
			Registry       string
			Repository     string
			Digest         string
			CreatedAt      time.Time
			SourceRepoID   string
			VerifiedSource bool
		}
		ctx := r.Context()
		if err := db.WithContext(ctx).
			Table("image_digests").
			Select("id, registry, repository, digest, created_at, source_repo_id, verified_source").
			Where("digest = ?", id).
			Order("created_at DESC, id DESC").
			First(&img).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				notFoundOrForbidden(w)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Per-resource ACL gate honoring every branch of
		// acl.ReadableImageClause: explicit image grant, verified-
		// source repo inheritance, OR the image is currently running
		// in a cluster the caller has cluster grants on (the path
		// that lets ROR cluster-only users land on an image profile
		// for one of their cluster's containers). 404 hides
		// existence — same convention as repos.
		if ok, err := canReadImageByID(r, db, id); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		resp := ImageDetailResponse{
			ID:         img.ID,
			Registry:   img.Registry,
			Repository: img.Repository,
			Digest:     img.Digest,
			CreatedAt:  img.CreatedAt,
		}

		// Linked source repo (cached at scan upload time).
		resp.LinkedRepo = loadLinkedRepo(ctx, db, img.ID)
		if resp.LinkedRepo != nil {
			resp.LinkedRepoContributors = loadLinkedRepoContributors(ctx, db, resp.LinkedRepo.RepoID, 8)
		}

		// Scan history — every IMAGE_SCAN job whose payload referenced
		// this digest_id, newest first, with per-scan vuln counts.
		type historyRow struct {
			JobID      string     `gorm:"column:job_id"`
			Status     string
			CreatedAt  time.Time  `gorm:"column:created_at"`
			FinishedAt *time.Time `gorm:"column:finished_at"`
			VulnCount  int        `gorm:"column:vuln_count"`
		}
		var history []historyRow
		_ = db.WithContext(ctx).Raw(`
			SELECT j.id AS job_id, j.status, j.created_at, j.finished_at,
			       COALESCE((
			         SELECT COUNT(*) FROM image_vuln_findings f
			         WHERE f.scan_run_id = j.id
			       ), 0) AS vuln_count
			FROM jobs j
			WHERE j.type = 'IMAGE_SCAN'
			  AND j.payload->>'image_digest_id' = ?
			ORDER BY j.created_at DESC
			LIMIT 50
		`, id).Scan(&history).Error
		resp.ScanHistory = make([]ImageScanHistoryRow, 0, len(history))
		for _, h := range history {
			resp.ScanHistory = append(resp.ScanHistory, ImageScanHistoryRow{
				JobID:      h.JobID,
				Status:     h.Status,
				CreatedAt:  h.CreatedAt,
				FinishedAt: h.FinishedAt,
				VulnCount:  h.VulnCount,
			})
			if resp.LatestScanID == "" && h.Status == "SUCCEEDED" {
				resp.LatestScanID = h.JobID
			}
		}

		// Severity breakdown for the latest scan — drives the drawer's
		// "critical/high/…" chip row without requiring the client to hit
		// /api/runs/{id} and parse the full finding list. Sourced from
		// image_scan_runs rather than jobs because the nightly sbom-scanner
		// revuln creates scan_run rows with uuid.NewString() that are
		// disjoint from jobs.id — so the findings it stores are invisible
		// to a jobs-tied query. image_scan_runs is the single source of
		// truth the findings actually FK against.
		var sev struct {
			Critical int
			High     int
			Medium   int
			Low      int
			Unknown  int
		}
		_ = db.WithContext(ctx).Raw(`
			WITH latest_scan AS (
				SELECT id FROM image_scan_runs
				WHERE image_digest_id = ? AND finished_at IS NOT NULL
				ORDER BY finished_at DESC
				LIMIT 1
			)
			SELECT
			  -- grype stores severities Titlecase; normalize with UPPER()
			  -- so case inconsistencies don't quietly dump everything
			  -- into the "Unknown" bucket.
			  COUNT(*) FILTER (WHERE UPPER(severity) = 'CRITICAL') AS critical,
			  COUNT(*) FILTER (WHERE UPPER(severity) = 'HIGH')     AS high,
			  COUNT(*) FILTER (WHERE UPPER(severity) = 'MEDIUM')   AS medium,
			  -- grype emits NEGLIGIBLE for info-grade findings (not a CVSS
			  -- severity per se) — roll it into Low for the chip row.
			  COUNT(*) FILTER (WHERE UPPER(severity) IN ('LOW','NEGLIGIBLE')) AS low,
			  COUNT(*) FILTER (WHERE UPPER(severity) NOT IN ('CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE')) AS unknown
			FROM image_vuln_findings f
			JOIN latest_scan ls ON ls.id = f.scan_run_id
		`, id).Scan(&sev).Error
		{
			total := sev.Critical + sev.High + sev.Medium + sev.Low + sev.Unknown
			if total > 0 {
				resp.VulnSeverity = &ImageVulnSeverityCount{
					Critical: sev.Critical, High: sev.High, Medium: sev.Medium,
					Low: sev.Low, Unknown: sev.Unknown, Total: total,
				}
			}
		}

		// Secret-finding count from the most recent betterleaks artifact
		// for this digest. Same query shape as /api/secrets/images but
		// scoped to one image_digest_id. Non-fatal if the artifact JSON
		// can't be parsed — we default to 0 rather than fail the page.
		_ = db.WithContext(ctx).Raw(`
			WITH latest AS (
				SELECT isa.content
				FROM image_scan_runs isr
				JOIN image_scan_artifacts isa ON isa.scan_run_id = isr.id
				WHERE isr.image_digest_id = ?
				  AND isa.category = 'secrets'
				  AND isa.scanner  = 'betterleaks'
				ORDER BY isr.finished_at DESC NULLS LAST
				LIMIT 1
			)
			SELECT COALESCE((
				SELECT jsonb_array_length(convert_from(l.content, 'utf8')::jsonb)
				FROM latest l
				WHERE octet_length(l.content) > 2
				  AND jsonb_typeof(convert_from(l.content, 'utf8')::jsonb) = 'array'
			), 0)
		`, id).Scan(&resp.SecretCount).Error

		// Cluster usage from the live cluster_record feed.
		type usageRow struct {
			Cluster   string    `gorm:"column:cluster"`
			Namespace string    `gorm:"column:namespace"`
			PodCount  int       `gorm:"column:pod_count"`
			FirstSeen time.Time `gorm:"column:first_seen"`
			LastSeen  time.Time `gorm:"column:last_seen"`
		}
		var usage []usageRow
		_ = db.WithContext(ctx).Raw(`
			SELECT
			  COALESCE(data->>'cluster', '') AS cluster,
			  COALESCE(data->>'namespace', '') AS namespace,
			  COUNT(DISTINCT data->>'pod_uid') AS pod_count,
			  MIN(received_at) AS first_seen,
			  MAX(received_at) AS last_seen
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'`+scam.LiveRecordFilter+`
			  AND data->>'digest' = ?
			GROUP BY 1, 2
			ORDER BY last_seen DESC
		`, img.Digest).Scan(&usage).Error
		resp.ClusterUsage = make([]ImageClusterUsageRow, 0, len(usage))
		for _, u := range usage {
			resp.ClusterUsage = append(resp.ClusterUsage, ImageClusterUsageRow(u))
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// RepoImagesHandler lists image_digests whose cached source_repo_id
// points at the given repo — the reverse of the image-scan→repo link.
// GET /api/repos/{repo_id}/images
func RepoImagesHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}
		repoID := r.PathValue("repo_id")
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}
		if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		type row struct {
			ID         string    `json:"id"`
			Registry   string    `json:"registry"`
			Repository string    `json:"repository"`
			Digest     string    `json:"digest"`
			CreatedAt  time.Time `json:"created_at" gorm:"column:created_at"`
			LatestScan *time.Time `json:"latest_scan_at,omitempty" gorm:"column:latest_scan_at"`
			VulnCount  int        `json:"vuln_count" gorm:"column:vuln_count"`
		}
		var rows []row
		if err := db.WithContext(r.Context()).Raw(`
			SELECT id.id, id.registry, id.repository, id.digest, id.created_at,
			       (SELECT MAX(finished_at) FROM image_scan_runs r
			          WHERE r.image_digest_id = id.id) AS latest_scan_at,
			       COALESCE((SELECT COUNT(*) FROM image_vuln_findings f
			          WHERE f.image_digest_id = id.id), 0) AS vuln_count
			FROM image_digests id
			WHERE id.source_repo_id = ?
			ORDER BY id.created_at DESC
		`, repoID).Scan(&rows).Error; err != nil {
			log.Printf("repo images handler: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"images": rows})
	}
}

// RepoWorkloadsHandler returns the live "where is this repo running"
// view for /app/providers/repo's Workloads tab. For every image_digests
// row whose source_repo_id points at this repo we attach the clusters +
// per-namespace workloads currently running that digest, aggregated from
// cluster_record. Empty `images` means no OCI image.source label on any
// built image has matched a known repo — the UI uses that signal to show
// the onboarding guide for the OCI label stack.
//
// `vms` is always [] today; reserved for when agents start shipping VM
// records. Keeping it in the response shape now means the UI doesn't
// need a breaking change later.
//
// GET /api/repos/{repo_id}/workloads
func RepoWorkloadsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}
		repoID := r.PathValue("repo_id")
		if repoID == "" {
			http.Error(w, "repo_id required", http.StatusBadRequest)
			return
		}
		if ok, err := canReadRepoByID(r, db, repoID); err != nil || !ok {
			notFoundOrForbidden(w)
			return
		}

		type imageHeader struct {
			ID         string     `gorm:"column:id"`
			Registry   string     `gorm:"column:registry"`
			Repository string     `gorm:"column:repository"`
			Digest     string     `gorm:"column:digest"`
			CreatedAt  time.Time  `gorm:"column:created_at"`
			LatestScan *time.Time `gorm:"column:latest_scan_at"`
			VulnCount  int        `gorm:"column:vuln_count"`
			HasSBOM    bool       `gorm:"column:has_sbom"`
			SBOMID     string     `gorm:"column:sbom_id"`
		}
		var headers []imageHeader
		if err := db.WithContext(r.Context()).Raw(`
			SELECT id.id, id.registry, id.repository, id.digest, id.created_at,
			       (SELECT MAX(finished_at) FROM image_scan_runs r
			          WHERE r.image_digest_id = id.id) AS latest_scan_at,
			       COALESCE((SELECT COUNT(*) FROM image_vuln_findings f
			          WHERE f.image_digest_id = id.id), 0) AS vuln_count,
			       EXISTS (SELECT 1 FROM sbom_bindings b
			          WHERE b.asset_type = 'IMAGE_DIGEST'
			            AND b.asset_ref_id = id.id) AS has_sbom,
			       COALESCE((SELECT b.sbom_id FROM sbom_bindings b
			          WHERE b.asset_type = 'IMAGE_DIGEST'
			            AND b.asset_ref_id = id.id
			          LIMIT 1), '') AS sbom_id
			FROM image_digests id
			WHERE id.source_repo_id = ?
			ORDER BY id.created_at DESC
		`, repoID).Scan(&headers).Error; err != nil {
			log.Printf("repo workloads handler (images): %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Per-image cluster / namespace / owner aggregation, pulled in a
		// single grouped query so the UI doesn't fan out N requests. Joined
		// back in Go to avoid a JSONB build in SQL that'd be awkward under
		// cluster_record's loose schema.
		type workloadRow struct {
			Digest    string `gorm:"column:digest"`
			ClusterID string `gorm:"column:cluster_id"`
			Cluster   string `gorm:"column:cluster"`
			Namespace string `gorm:"column:namespace"`
			Owner     string `gorm:"column:owner"`
			OwnerKind string `gorm:"column:owner_kind"`
			Pods      int    `gorm:"column:pods"`
		}
		type WorkloadJSON struct {
			Namespace string `json:"namespace"`
			Owner     string `json:"owner"`
			OwnerKind string `json:"owner_kind"`
			Pods      int    `json:"pods"`
		}
		type ClusterJSON struct {
			ClusterID string         `json:"cluster_id"`
			Cluster   string         `json:"cluster"`
			Workloads []WorkloadJSON `json:"workloads"`
		}
		type ImageJSON struct {
			ID         string        `json:"id"`
			Registry   string        `json:"registry"`
			Repository string        `json:"repository"`
			Digest     string        `json:"digest"`
			CreatedAt  time.Time     `json:"created_at"`
			LatestScan *time.Time    `json:"latest_scan_at,omitempty"`
			VulnCount  int           `json:"vuln_count"`
			HasSBOM    bool          `json:"has_sbom"`
			SBOMID     string        `json:"sbom_id,omitempty"`
			Clusters   []ClusterJSON `json:"clusters"`
		}

		resp := struct {
			Images []ImageJSON `json:"images"`
			VMs    []any       `json:"vms"`
		}{
			Images: make([]ImageJSON, 0, len(headers)),
			VMs:    []any{},
		}

		if len(headers) == 0 {
			writeJSON(w, http.StatusOK, resp)
			return
		}

		digests := make([]string, 0, len(headers))
		for _, h := range headers {
			digests = append(digests, h.Digest)
		}

		var wlRows []workloadRow
		if err := db.WithContext(r.Context()).Raw(`
			SELECT data->>'digest'     AS digest,
			       data->>'cluster_id' AS cluster_id,
			       COALESCE(data->>'cluster','')     AS cluster,
			       COALESCE(data->>'namespace','')   AS namespace,
			       COALESCE(data->>'owner','')       AS owner,
			       COALESCE(data->>'owner_kind','')  AS owner_kind,
			       COUNT(DISTINCT data->>'pod_uid')  AS pods
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'`+scam.LiveRecordFilter+`
			  AND data->>'pod_phase' = 'Running'
			  AND data->>'digest' IN ?
			GROUP BY 1, 2, 3, 4, 5, 6
			ORDER BY cluster, namespace, owner
		`, digests).Scan(&wlRows).Error; err != nil {
			log.Printf("repo workloads handler (cluster usage): %v", err)
			// Non-fatal — fall through with empty clusters[] so the list
			// still shows the images themselves.
		}

		// Group workloads by (digest, cluster_id) in one pass.
		type clusterKey struct{ digest, clusterID string }
		byDigest := make(map[string]map[string]*ClusterJSON, len(headers))
		for _, h := range headers {
			byDigest[h.Digest] = make(map[string]*ClusterJSON)
		}
		for _, w := range wlRows {
			clusters, ok := byDigest[w.Digest]
			if !ok {
				continue
			}
			c, ok := clusters[w.ClusterID]
			if !ok {
				c = &ClusterJSON{
					ClusterID: w.ClusterID,
					Cluster:   w.Cluster,
					Workloads: []WorkloadJSON{},
				}
				clusters[w.ClusterID] = c
			}
			c.Workloads = append(c.Workloads, WorkloadJSON{
				Namespace: w.Namespace,
				Owner:     w.Owner,
				OwnerKind: w.OwnerKind,
				Pods:      w.Pods,
			})
			_ = clusterKey{}
		}

		for _, h := range headers {
			clustersMap := byDigest[h.Digest]
			clusters := make([]ClusterJSON, 0, len(clustersMap))
			for _, c := range clustersMap {
				clusters = append(clusters, *c)
			}
			resp.Images = append(resp.Images, ImageJSON{
				ID:         h.ID,
				Registry:   h.Registry,
				Repository: h.Repository,
				Digest:     h.Digest,
				CreatedAt:  h.CreatedAt,
				LatestScan: h.LatestScan,
				VulnCount:  h.VulnCount,
				HasSBOM:    h.HasSBOM,
				SBOMID:     h.SBOMID,
				Clusters:   clusters,
			})
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// ImageScanArtifactDownloadHandler streams the raw bytes of a single
// image-scan artifact by ID. The job ID path component is validated so a
// guessed artifact UUID from another scan isn't accessible here.
// GET /api/image-scans/{job_id}/artifacts/{artifact_id}/download
func ImageScanArtifactDownloadHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}
		jobID := r.PathValue("job_id")
		artifactID := r.PathValue("artifact_id")
		if jobID == "" || artifactID == "" {
			http.Error(w, "job_id and artifact_id required", http.StatusBadRequest)
			return
		}

		var art imagescan.ImageScanArtifact
		if err := db.WithContext(r.Context()).
			Where("id = ? AND scan_run_id = ?", artifactID, jobID).
			First(&art).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				notFoundOrForbidden(w)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Gate by source-repo ACL with the verified_source rule: an
		// admin or a reader of the source repo can fetch the artifact
		// only when the image's claimed repo binding is signed.
		var img struct {
			SourceRepoID   string
			VerifiedSource bool
		}
		if err := db.WithContext(r.Context()).Raw(`
			SELECT d.source_repo_id, d.verified_source
			FROM image_digests d
			JOIN jobs j ON j.payload->>'image_digest_id' = d.id
			WHERE j.id = ?
			LIMIT 1
		`, jobID).Scan(&img).Error; err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if img.VerifiedSource && img.SourceRepoID != "" {
			if ok, err := canReadRepoByID(r, db, img.SourceRepoID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
		} else if !acl.SubjectFromRequest(r).IsAdmin {
			notFoundOrForbidden(w)
			return
		}

		filename := art.Filename
		if filename == "" {
			filename = art.Category + "-" + art.Scanner + ".json"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		_, _ = w.Write(art.Content)
	}
}

// loadLinkedRepoContributors pulls the top-N committers from the cached
// /providers/details payload stashed in repo_caches. Returns nil when the
// cache is empty or malformed — the drawer just hides the contributors
// strip instead of blocking. Limit is applied in Go to keep the SQL simple.
func loadLinkedRepoContributors(ctx context.Context, db *gorm.DB, repoID string, limit int) []ImageRepoContributor {
	if repoID == "" || limit <= 0 {
		return nil
	}
	var raw string
	if err := db.WithContext(ctx).Raw(
		`SELECT contributors_json FROM repo_caches WHERE repo_id = ? LIMIT 1`, repoID,
	).Scan(&raw).Error; err != nil || raw == "" {
		return nil
	}
	var parsed []ImageRepoContributor
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	if len(parsed) > limit {
		parsed = parsed[:limit]
	}
	return parsed
}

// loadLinkedRepo reads the cached image_digests.source_repo_id +
// associated repo row and composes a LinkedRepoSummary. Returns nil
// when the image has no cached link (either no source label was set,
// or no matching repo in our providers).
func loadLinkedRepo(ctx context.Context, db *gorm.DB, imageDigestID string) *LinkedRepoSummary {
	var row struct {
		SourceRepoID string `gorm:"column:source_repo_id"`
		RepoID       string `gorm:"column:repo_id"`
		Provider     string
		Org          string
		Slug         string
		BaseURL      string `gorm:"column:base_url"`
		ProviderID   string `gorm:"column:provider_id"`
	}
	err := db.WithContext(ctx).Raw(`
		SELECT id.source_repo_id AS source_repo_id,
		       r.id AS repo_id, r.provider, r.org, r.slug,
		       COALESCE(pi.base_url, '') AS base_url,
		       r.provider_instance_id AS provider_id
		FROM image_digests id
		JOIN repos r ON r.id = id.source_repo_id
		LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
		WHERE id.id = ?
		LIMIT 1
	`, imageDigestID).Scan(&row).Error
	if err != nil || row.RepoID == "" {
		return nil
	}
	return &LinkedRepoSummary{
		RepoID: row.RepoID, Provider: row.Provider,
		Org: row.Org, Slug: row.Slug,
		BaseURL: row.BaseURL, ProviderID: row.ProviderID,
	}
}
