package uiapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/imagescan"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// writeImageScanRunResponse fills a RunResponse for an IMAGE_SCAN job. The
// struct parameter comes from RunGetHandler's local select so we reuse the
// row without re-querying.
func writeImageScanRunResponse(w http.ResponseWriter, r *http.Request, db *gorm.DB, job struct {
	ID         string
	Type       string
	Status     string
	Payload    []byte
	Error      string
	CommitHash string
	CreatedAt  time.Time
	LockedAt   *time.Time
	FinishedAt *time.Time
	K8sJobName string `gorm:"column:k8s_job_name"`
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
		StartedAt:       job.LockedAt,
		FinishedAt:      job.FinishedAt,
		ImageRegistry:   payload.Registry,
		ImageRepository: payload.Repository,
		ImageDigest:     payload.Digest,
		ImageDigestID:   payload.ImageDigestID,
		ImageScanners:   payload.Scanners,
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

	// Severity summary from the grype parser output.
	var severityRows []struct {
		Severity string
		Count    int
	}
	if err := db.WithContext(r.Context()).
		Table("image_vuln_findings").
		Select("severity, COUNT(*) AS count").
		Where("scan_run_id = ?", runID).
		Group("severity").
		Find(&severityRows).Error; err == nil && len(severityRows) > 0 {
		counts := &ImageVulnSeverityCount{}
		for _, row := range severityRows {
			counts.Total += row.Count
			switch row.Severity {
			case "CRITICAL":
				counts.Critical = row.Count
			case "HIGH":
				counts.High = row.Count
			case "MEDIUM":
				counts.Medium = row.Count
			case "LOW":
				counts.Low = row.Count
			default:
				counts.Unknown += row.Count
			}
		}
		response.ImageVulnCounts = counts
	}

	// Full vuln list (capped at 1000 rows, severity-sorted). For larger
	// findings the UI offers the raw artifact download.
	var findings []imagescan.ImageVulnFinding
	if err := db.WithContext(r.Context()).
		Where("scan_run_id = ?", runID).
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
		response.ImageVulns = make([]ImageVulnListRow, 0, len(findings))
		for _, f := range findings {
			response.ImageVulns = append(response.ImageVulns, ImageVulnListRow{
				VulnID:           f.VulnID,
				Severity:         f.Severity,
				PkgName:          f.PkgName,
				InstalledVersion: f.InstalledVersion,
				FixedVersion:     f.FixedVersion,
				Title:            f.Title,
				Target:           f.Target,
				Scanner:          f.Scanner,
			})
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

	// SBOM component count (cheap lookup; frontend can hit /api/sboms/{id}
	// for the full list if the operator wants to drill in).
	if response.SBOMID != "" {
		var componentCount int64
		if err := db.WithContext(r.Context()).
			Table("sbom_component_view").
			Where("sbom_id = ? AND is_root = false", response.SBOMID).
			Count(&componentCount).Error; err == nil {
			response.SBOMComponentCount = int(componentCount)
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

// ImageDetailResponse aggregates everything the /app/images/{id} page
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

	LinkedRepo *LinkedRepoSummary `json:"linked_repo,omitempty"`

	ScanHistory  []ImageScanHistoryRow `json:"scan_history,omitempty"`
	LatestScanID string                `json:"latest_scan_id,omitempty"`

	ClusterUsage []ImageClusterUsageRow `json:"cluster_usage,omitempty"`
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
func ImageDetailHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "image id required", http.StatusBadRequest)
			return
		}

		var img struct {
			ID         string
			Registry   string
			Repository string
			Digest     string
			CreatedAt  time.Time
		}
		if err := db.WithContext(r.Context()).
			Table("image_digests").
			Select("id, registry, repository, digest, created_at").
			Where("id = ?", id).
			First(&img).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "image not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
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
		resp.LinkedRepo = loadLinkedRepo(r.Context(), db, img.ID)

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
		_ = db.WithContext(r.Context()).Raw(`
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

		// Cluster usage from the live cluster_record feed.
		type usageRow struct {
			Cluster   string    `gorm:"column:cluster"`
			Namespace string    `gorm:"column:namespace"`
			PodCount  int       `gorm:"column:pod_count"`
			FirstSeen time.Time `gorm:"column:first_seen"`
			LastSeen  time.Time `gorm:"column:last_seen"`
		}
		var usage []usageRow
		_ = db.WithContext(r.Context()).Raw(`
			SELECT
			  COALESCE(data->>'cluster', '') AS cluster,
			  COALESCE(data->>'namespace', '') AS namespace,
			  COUNT(DISTINCT data->>'pod_uid') AS pod_count,
			  MIN(received_at) AS first_seen,
			  MAX(received_at) AS last_seen
			FROM cluster_record
			WHERE data->>'kind' = 'Container'
			  AND data->>'msg' != 'DELETE'
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
			       (SELECT MAX(finished_at) FROM jobs j
			          WHERE j.type = 'IMAGE_SCAN'
			            AND j.payload->>'image_digest_id' = id.id) AS latest_scan_at,
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
				http.Error(w, "artifact not found", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
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

