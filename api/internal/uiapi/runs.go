package uiapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/assets"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/NorskHelsenett/spam/internal/runner"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunResponse represents a run in the API response.
type RunResponse struct {
	ID   string `json:"id"`
	Type string `json:"type"` // "CREATE_RUN" (repo) or "IMAGE_SCAN" (image)

	Status     string     `json:"status"`
	CloneURL   string     `json:"clone_url,omitempty"`
	Provider   string     `json:"provider,omitempty"`
	ProviderID string     `json:"provider_id,omitempty"`
	RepoID     string     `json:"repo_id,omitempty"`
	BaseURL    string     `json:"base_url,omitempty"`
	RepoPath   string     `json:"repo_path"`
	Ref        string     `json:"ref,omitempty"`
	CommitSHA  string     `json:"commit_sha,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	RetryAt    *time.Time `json:"retry_at,omitempty"`
	K8sJobName string     `json:"k8s_job_name,omitempty"`
	SBOMID     string     `json:"sbom_id,omitempty"`
	SecretID   string     `json:"secret_id,omitempty"`

	// Image-scan specific. Empty for CREATE_RUN rows.
	ImageRegistry   string                  `json:"image_registry,omitempty"`
	ImageRepository string                  `json:"image_repository,omitempty"`
	ImageDigest     string                  `json:"image_digest,omitempty"`
	ImageDigestID   string                  `json:"image_digest_id,omitempty"`
	ImageArtifacts  []ImageArtifactSummary  `json:"image_artifacts,omitempty"`
	ImageScanners   map[string]string       `json:"image_scanners,omitempty"`
	ImageVulnCounts *ImageVulnSeverityCount `json:"image_vuln_counts,omitempty"`

	// PartialFailures maps a scan category ("sbom","vuln","secrets",…) to the
	// scanner error text when that category exited non-zero during an
	// otherwise-successful run. Present only on IMAGE_SCAN rows where some
	// categories failed; absent means clean run or categories simply weren't
	// configured.
	PartialFailures map[string]string `json:"partial_failures,omitempty"`

	// Rich inline payloads — parsed once server-side so the detail page
	// renders without follow-up fetches or file downloads.
	ImageVulns          []ImageVulnListRow   `json:"image_vulns,omitempty"`
	ImageLabels         map[string]string    `json:"image_labels,omitempty"`
	ImageLabelsMetadata *ImageOCIMetadata    `json:"image_oci_metadata,omitempty"`
	ImageSecrets        []ImageSecretListRow `json:"image_secrets,omitempty"`
	ImageSignature      *ImageSignatureInfo  `json:"image_signature,omitempty"`
	ImageLinkedRepo     *LinkedRepoSummary   `json:"image_linked_repo,omitempty"`
	SBOMComponentCount  int                  `json:"sbom_component_count,omitempty"`
}

// ImageVulnListRow is a client-facing view of a grype/trivy finding.
type ImageVulnListRow struct {
	VulnID           string `json:"vuln_id"`
	Severity         string `json:"severity"`
	PkgName          string `json:"pkg_name"`
	InstalledVersion string `json:"installed_version,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
	Title            string `json:"title,omitempty"`
	Target           string `json:"target,omitempty"`
	Scanner          string `json:"scanner"`
}

// ImageOCIMetadata surfaces the high-signal fields from the OCI config —
// created timestamp, architecture, os, and the raw JSON for operators who
// want everything without downloading the artifact.
type ImageOCIMetadata struct {
	Created      string `json:"created,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	OS           string `json:"os,omitempty"`
	Author       string `json:"author,omitempty"`
}

// ImageSecretListRow is one betterleaks finding.
type ImageSecretListRow struct {
	RuleID      string `json:"rule_id"`
	Description string `json:"description,omitempty"`
	File        string `json:"file,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	Match       string `json:"match,omitempty"`
}

// ImageSignatureInfo is a client-facing view of cosign's verdict.
type ImageSignatureInfo struct {
	Signed   bool   `json:"signed"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// LinkedRepoSummary connects an image scan to the source repository the
// image claims to be built from, based on the OCI `image.source` label.
// Labels are self-attested — the "claimed" wording in the UI reflects
// that until cosign attestations give us provenance-grade proof.
type LinkedRepoSummary struct {
	RepoID     string `json:"repo_id"`
	Provider   string `json:"provider"`
	Org        string `json:"org"`
	Slug       string `json:"slug"`
	BaseURL    string `json:"base_url,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
	Source     string `json:"source"`             // raw label value
	Revision   string `json:"revision,omitempty"` // org.opencontainers.image.revision
}

// ImageVulnSeverityCount aggregates CVE counts by severity for an image
// scan, so the detail view can render severity-colored chips without
// having to stream the full finding list.
type ImageVulnSeverityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// pickStartedAt returns the first non-nil pointer. Used to prefer
// last_attempted_at (preserved across completion) over locked_at (cleared
// when the job transitions to SUCCEEDED/FAILED) when reporting run start.
func pickStartedAt(a, b *time.Time) *time.Time {
	if a != nil {
		return a
	}
	return b
}

// ImageArtifactSummary is the lightweight descriptor of one scanner output
// produced by an image scan. Clients render these as cards linking to the
// raw download; the heavy blob lives in image_scan_artifacts.content and is
// fetched on demand.
type ImageArtifactSummary struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	Scanner   string    `json:"scanner"`
	Filename  string    `json:"filename,omitempty"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// RunsListResponse is the response for listing runs.
type RunsListResponse struct {
	Runs       []RunResponse `json:"runs"`
	TotalCount int64         `json:"total_count"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
}

// CreateRunRequest is the request to create a new run.
type CreateRunRequest struct {
	Provider     string `json:"provider"`           // github, gitlab, gitea
	RepoPath     string `json:"repo_path"`          // owner/repo or group/project
	Ref          string `json:"ref,omitempty"`      // branch or tag
	BaseURL      string `json:"base_url,omitempty"` // for gitlab/gitea custom instances
	ProviderID   string `json:"provider_id,omitempty"`
	RepoDisabled bool   `json:"repo_disabled,omitempty"`
}

// CreateRunResponse is the response after creating a run.
type CreateRunResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// RunsListHandler lists all runs with pagination.
// GET /api/runs
func RunsListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		page, pageSize := parsePagination(r)
		statuses := parseStatusFilters(r.URL.Query().Get("status"))
		repoPath := r.URL.Query().Get("repo_path")
		repoID := r.URL.Query().Get("repo_id")
		// type filter: "all" (default), "repo", or "image"
		typeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))
		if typeFilter == "" {
			typeFilter = "all"
		}

		sortBy := r.URL.Query().Get("sort_by")
		sortDir := r.URL.Query().Get("sort_dir")
		if sortDir != "asc" && sortDir != "desc" {
			sortDir = "desc"
		}
		var orderClause string
		switch sortBy {
		case "status":
			orderClause = fmt.Sprintf(
				"CASE status WHEN 'RUNNING' THEN 0 WHEN 'QUEUED' THEN 1 WHEN 'FAILED' THEN 2 ELSE 3 END %s, created_at DESC",
				strings.ToUpper(sortDir),
			)
		case "provider":
			orderClause = fmt.Sprintf("payload->>'provider' %s, created_at DESC", strings.ToUpper(sortDir))
		case "duration":
			orderClause = fmt.Sprintf("(COALESCE(finished_at, NOW()) - COALESCE(locked_at, created_at)) %s", strings.ToUpper(sortDir))
		default: // "created" or empty
			orderClause = fmt.Sprintf("created_at %s", strings.ToUpper(sortDir))
		}

		var total int64
		query := db.WithContext(r.Context()).Table("jobs")
		switch typeFilter {
		case "image":
			query = query.Where("type = ?", jobs.JobTypeImageScan)
		case "all":
			query = query.Where("type IN ?", []string{jobs.JobTypeCreateRun, jobs.JobTypeImageScan})
		default: // "repo"
			query = query.Where("type = ?", jobs.JobTypeCreateRun)
		}
		if len(statuses) == 1 {
			query = query.Where("status = ?", statuses[0])
		} else if len(statuses) > 1 {
			query = query.Where("status IN ?", statuses)
		}
		if repoID != "" {
			query = query.Where("payload->>'repo_id' = ?", repoID)
		} else if repoPath != "" {
			// Search in payload JSON for matching repo path
			query = query.Where("payload::text LIKE ?", "%"+repoPath+"%")
		}
		query.Count(&total)

		var jobRecords []struct {
			ID         string
			Type       string
			Status     string
			Payload    []byte
			Error      string
			CommitHash string
			CreatedAt  time.Time
			LockedAt   *time.Time
			FinishedAt *time.Time
			RunAt      time.Time `gorm:"column:run_at"`
			K8sJobName string    `gorm:"column:k8s_job_name"`
			Result     []byte
		}

		offset := (page - 1) * pageSize
		if err := query.Select("id, type, status, payload, error, commit_hash, created_at, locked_at, finished_at, run_at, k8s_job_name, result").
			Order(orderClause).
			Offset(offset).
			Limit(pageSize).
			Find(&jobRecords).Error; err != nil {
			log.Printf("failed to list runs: %v", err)
			http.Error(w, "failed to list runs", http.StatusInternalServerError)
			return
		}

		// Payloads differ by job type. We decode both shapes lazily in the
		// render loop below; here we only collect provider IDs from
		// CREATE_RUN rows so we can batch-resolve display names.
		parsedPayloads := make([]jobs.CreateRunPayload, len(jobRecords))
		imagePayloads := make([]jobs.ImageScanPayload, len(jobRecords))
		providerIDs := make([]string, 0, len(jobRecords))
		seenProviderIDs := make(map[string]struct{}, len(jobRecords))
		for i, job := range jobRecords {
			if job.Type == jobs.JobTypeImageScan {
				var p jobs.ImageScanPayload
				if len(job.Payload) > 0 {
					_ = json.Unmarshal(job.Payload, &p)
				}
				imagePayloads[i] = p
				continue
			}
			var payload jobs.CreateRunPayload
			if len(job.Payload) > 0 {
				_ = json.Unmarshal(job.Payload, &payload)
			}
			parsedPayloads[i] = payload
			if payload.ProviderID == "" {
				continue
			}
			if _, ok := seenProviderIDs[payload.ProviderID]; ok {
				continue
			}
			seenProviderIDs[payload.ProviderID] = struct{}{}
			providerIDs = append(providerIDs, payload.ProviderID)
		}

		providerNames := make(map[string]string, len(providerIDs))
		providerBaseURLs := make(map[string]string, len(providerIDs))
		if len(providerIDs) > 0 {
			var providers []struct {
				ID          string `gorm:"column:id"`
				DisplayName string `gorm:"column:display_name"`
				BaseURL     string `gorm:"column:base_url"`
			}
			if err := db.WithContext(r.Context()).
				Table("provider_instances").
				Select("id, display_name, base_url").
				Where("id IN ?", providerIDs).
				Find(&providers).Error; err == nil {
				for _, provider := range providers {
					if provider.DisplayName != "" {
						providerNames[provider.ID] = provider.DisplayName
					}
					if provider.BaseURL != "" {
						providerBaseURLs[provider.ID] = provider.BaseURL
					}
				}
			}
		}

		runs := make([]RunResponse, 0, len(jobRecords))
		for i, job := range jobRecords {
			status := job.Status
			errorText := job.Error
			var retryAt *time.Time
			if status == string(jobs.JobStatusRetry) && job.RunAt.After(time.Now()) {
				t := job.RunAt
				retryAt = &t
			}
			// K8s-failure inference is CREATE_RUN-specific (the result JSON
			// layout is different for image scans).
			if job.Type == jobs.JobTypeCreateRun &&
				(status == string(jobs.JobStatusSucceeded) || status == string(jobs.JobStatusRunning) || status == string(jobs.JobStatusQueued)) {
				if resultMap, err := parseRunResultMap(job.Result); err == nil {
					events, podStatus, ok, _ := loadPersistedK8sSnapshotFromResult(resultMap)
					if ok {
						if failed, message := inferK8sFailure(events, podStatus); failed {
							status = string(jobs.JobStatusFailed)
							errorText = message
							if errorText == "" {
								errorText = "k8s runner failed to start"
							}
						}
					}
				}
			}

			if job.Type == jobs.JobTypeImageScan {
				p := imagePayloads[i]
				runs = append(runs, RunResponse{
					ID:              job.ID,
					Type:            job.Type,
					Status:          status,
					RepoPath:        imageRefShortDisplay(p.Registry, p.Repository, p.Digest),
					Error:           errorText,
					CreatedAt:       job.CreatedAt,
					StartedAt:       job.LockedAt,
					FinishedAt:      job.FinishedAt,
					RetryAt:         retryAt,
					ImageRegistry:   p.Registry,
					ImageRepository: p.Repository,
					ImageDigest:     p.Digest,
					ImageDigestID:   p.ImageDigestID,
				})
				continue
			}

			payload := parsedPayloads[i]
			runs = append(runs, RunResponse{
				ID:         job.ID,
				Type:       job.Type,
				Status:     status,
				CloneURL:   payload.CloneURL,
				Provider:   displayProviderName(payload.Provider, payload.ProviderID, providerNames),
				ProviderID: payload.ProviderID,
				RepoID:     payload.RepoID,
				BaseURL:    providerBaseURLs[payload.ProviderID],
				RepoPath:   extractRepoPath(payload.CloneURL),
				Ref:        payload.Ref,
				CommitSHA:  job.CommitHash,
				Error:      errorText,
				CreatedAt:  job.CreatedAt,
				StartedAt:  job.LockedAt,
				FinishedAt: job.FinishedAt,
				RetryAt:    retryAt,
				K8sJobName: job.K8sJobName,
			})
		}

		writeJSON(w, http.StatusOK, RunsListResponse{
			Runs:       runs,
			TotalCount: total,
			Page:       page,
			PageSize:   pageSize,
		})
	}
}

// imageRefShortDisplay renders a compact label for an image scan's RepoPath
// field so the runs table shows something readable like
// "docker.io/library/alpine@sha256:0123abcd" rather than a full 64-char
// digest. The full digest is available via ImageDigest on the row.
func imageRefShortDisplay(registry, repository, digest string) string {
	ref := ""
	switch {
	case registry != "" && repository != "":
		ref = registry + "/" + repository
	case repository != "":
		ref = repository
	case registry != "":
		ref = registry
	}
	if digest == "" {
		return ref
	}
	short := digest
	// "sha256:abcd..." → first 8 hex chars is enough to disambiguate in a list
	if idx := strings.IndexByte(digest, ':'); idx > 0 && idx+9 <= len(digest) {
		short = digest[:idx+9]
	}
	if ref == "" {
		return short
	}
	return ref + "@" + short
}

func displayProviderName(providerType string, providerID string, providerNames map[string]string) string {
	if providerID != "" {
		if providerName, ok := providerNames[providerID]; ok && providerName != "" {
			return providerName
		}
	}
	return providerType
}

func parseStatusFilters(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	validStatuses := map[string]struct{}{
		string(jobs.JobStatusQueued):      {},
		string(jobs.JobStatusRunning):     {},
		string(jobs.JobStatusSucceeded):   {},
		string(jobs.JobStatusFailed):      {},
		string(jobs.JobStatusRetry):       {},
		string(runner.RunStatusCancelled): {},
	}

	parts := strings.Split(raw, ",")
	statuses := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		status := strings.ToUpper(strings.TrimSpace(part))
		if status == "" {
			continue
		}
		if _, ok := validStatuses[status]; !ok {
			continue
		}
		if _, ok := seen[status]; ok {
			continue
		}
		seen[status] = struct{}{}
		statuses = append(statuses, status)
	}
	return statuses
}

// RunsCreateHandler creates a new run.
// POST /api/runs
func RunsCreateHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var req CreateRunRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Provider == "" || req.RepoPath == "" {
			http.Error(w, "provider and repo_path are required", http.StatusBadRequest)
			return
		}

		// Resolve provider and its stored base URL from the database.
		// Never trust req.BaseURL from the client — it could be an attacker-
		// controlled URL that would receive the provider token (SSRF).
		providerID := strings.TrimSpace(req.ProviderID)
		var storedBaseURL string
		if providerID != "" {
			var pi struct{ BaseURL string }
			if err := db.WithContext(r.Context()).
				Table("provider_instances").
				Select("base_url").
				Where("id = ? AND enabled = true", providerID).
				Scan(&pi).Error; err != nil || pi.BaseURL == "" {
				http.Error(w, "provider not found or has no base URL", http.StatusBadRequest)
				return
			}
			storedBaseURL = pi.BaseURL
		} else {
			match, err := providerconfig.FindProviderMatch(r.Context(), db, req.Provider, "", req.RepoPath)
			if err != nil || match == nil || match.BaseURL == "" {
				http.Error(w, "no configured provider found for this repo", http.StatusBadRequest)
				return
			}
			providerID = match.ID
			storedBaseURL = match.BaseURL
		}

		// Build clone URL using only the server-side base URL, never the client-supplied one.
		cloneURL := buildCloneURL(req.Provider, req.RepoPath, storedBaseURL)
		if cloneURL == "" {
			http.Error(w, "could not build clone URL", http.StatusBadRequest)
			return
		}

		fullPath := strings.Trim(req.RepoPath, "/")
		org := ""
		slug := fullPath
		if lastSlash := strings.LastIndex(fullPath, "/"); lastSlash >= 0 {
			org = fullPath[:lastSlash]
			slug = fullPath[lastSlash+1:]
		}

		repo, err := assets.UpsertRepo(r.Context(), db, assets.RepoInput{
			Provider:           req.Provider,
			Org:                org,
			Slug:               slug,
			ProviderInstanceID: providerID,
		})
		if err != nil {
			log.Printf("failed to upsert repo: %v", err)
			http.Error(w, "failed to create run", http.StatusInternalServerError)
			return
		}

		// Prevent duplicate queuing: reject if there's already a QUEUED or RUNNING job for this repo
		var pendingCount int64
		db.WithContext(r.Context()).Table("jobs").
			Where("type = ?", jobs.JobTypeCreateRun).
			Where("status IN ?", []string{"QUEUED", "RUNNING"}).
			Where("payload->>'repo_id' = ?", repo.ID).
			Count(&pendingCount)
		if pendingCount > 0 {
			http.Error(w, "a scan is already queued or running for this repository", http.StatusConflict)
			return
		}

		// Create job payload
		payload := jobs.CreateRunPayload{
			RepoID:       repo.ID,
			ProviderID:   providerID,
			Provider:     req.Provider,
			CloneURL:     cloneURL,
			Ref:          req.Ref,
			RepoDisabled: req.RepoDisabled,
		}

		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			http.Error(w, "failed to create run", http.StatusInternalServerError)
			return
		}

		// Create job record
		jobID := uuid.New().String()
		now := time.Now()
		job := map[string]interface{}{
			"id":           jobID,
			"type":         jobs.JobTypeCreateRun,
			"status":       "QUEUED",
			"payload":      payloadBytes,
			"attempts":     0,
			"max_attempts": 3,
			"run_at":       now,
			"created_at":   now,
			"updated_at":   now,
		}

		if err := db.WithContext(r.Context()).Table("jobs").Create(job).Error; err != nil {
			log.Printf("failed to create run: %v", err)
			http.Error(w, "failed to create run", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusCreated, CreateRunResponse{
			ID:     jobID,
			Status: "QUEUED",
		})
	}
}

// RunGetHandler gets a single run by ID.
// GET /api/runs/{id}
func RunGetHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		var job struct {
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
		}

		if err := db.WithContext(r.Context()).Table("jobs").
			Where("id = ? AND type IN ?", runID, []string{jobs.JobTypeCreateRun, jobs.JobTypeImageScan}).
			First(&job).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		// Image scans short-circuit the repo-specific branches below. Their
		// detail payload is assembled from image_scan_artifacts + SBOM
		// binding on the image digest.
		if job.Type == jobs.JobTypeImageScan {
			writeImageScanRunResponse(w, r, db, job, runID)
			return
		}

		var payload jobs.CreateRunPayload
		if len(job.Payload) > 0 {
			json.Unmarshal(job.Payload, &payload)
		}

		// If we already know K8s failed, correct status before responding
		if job.Status == string(jobs.JobStatusSucceeded) || job.Status == string(jobs.JobStatusRunning) || job.Status == string(jobs.JobStatusQueued) {
			events, podStatus, ok, err := loadPersistedK8sSnapshot(r.Context(), db, runID)
			if err == nil && ok {
				if failed, message := inferK8sFailure(events, podStatus); failed {
					now := time.Now()
					errorText := message
					if errorText == "" {
						errorText = "k8s runner failed to start"
					}
					if updateErr := db.WithContext(r.Context()).Table("jobs").
						Where("id = ?", runID).
						Updates(map[string]interface{}{
							"status":      jobs.JobStatusFailed,
							"error":       errorText,
							"finished_at": now,
							"updated_at":  now,
						}).Error; updateErr == nil {
						job.Status = string(jobs.JobStatusFailed)
						job.Error = errorText
						job.FinishedAt = &now
					}
				}
			}
		}

		response := RunResponse{
			ID:         job.ID,
			Type:       job.Type,
			Status:     job.Status,
			CloneURL:   payload.CloneURL,
			Provider:   payload.Provider,
			ProviderID: payload.ProviderID,
			RepoID:     payload.RepoID,
			RepoPath:   extractRepoPath(payload.CloneURL),
			Ref:        payload.Ref,
			CommitSHA:  job.CommitHash,
			Error:      job.Error,
			CreatedAt:  job.CreatedAt,
			// locked_at is cleared when the job completes, so prefer
			// last_attempted_at which is preserved across the SUCCEEDED/FAILED
			// transition and matches when the worker picked up the job.
			StartedAt:  pickStartedAt(job.LastAttemptedAt, job.LockedAt),
			FinishedAt: job.FinishedAt,
			K8sJobName: job.K8sJobName,
		}

		// Look up provider base URL
		if payload.ProviderID != "" {
			var pi struct {
				BaseURL string
			}
			if err := db.WithContext(r.Context()).Table("provider_instances").
				Where("id = ?", payload.ProviderID).
				Select("base_url").First(&pi).Error; err == nil {
				response.BaseURL = pi.BaseURL
			}
		}

		// Look up associated SBOM via repo commit
		if payload.RepoID != "" && job.CommitHash != "" {
			var repoCommit struct {
				ID string
			}
			if err := db.WithContext(r.Context()).Table("repo_commits").
				Where("repo_id = ? AND commit_sha = ?", payload.RepoID, job.CommitHash).
				Select("id").First(&repoCommit).Error; err == nil {
				var sbomBinding struct {
					SBOMID string
				}
				if err := db.WithContext(r.Context()).Table("sbom_bindings").
					Where("asset_type = ? AND asset_ref_id = ?", "REPO_COMMIT", repoCommit.ID).
					Select("sbom_id").First(&sbomBinding).Error; err == nil {
					response.SBOMID = sbomBinding.SBOMID
				}
			}
		}

		// Look up associated secrets
		var secret struct {
			ID string
		}
		if err := db.WithContext(r.Context()).Table("run_secrets").
			Where("run_id = ?", runID).
			Select("id").First(&secret).Error; err == nil {
			response.SecretID = secret.ID
		}

		writeJSON(w, http.StatusOK, response)
	}
}

// ActiveRunStatus is the minimal status payload streamed to clients.
type ActiveRunStatus struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// RunsActiveStreamHandler streams the status of all active (QUEUED/RUNNING) runs via SSE.
// A single connection from the list page replaces per-run SSE streams.
// GET /api/runs/active/stream
func RunsActiveStreamHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		send := func() bool {
			var active []ActiveRunStatus
			if err := db.WithContext(r.Context()).Table("jobs").
				Where("type = ? AND status IN ?", jobs.JobTypeCreateRun, []string{
					string(jobs.JobStatusQueued),
					string(jobs.JobStatusRunning),
				}).
				Select("id, status, error").
				Order("created_at DESC").
				Find(&active).Error; err != nil {
				return r.Context().Err() == nil
			}
			data, _ := json.Marshal(active)
			fmt.Fprintf(w, "event: active_runs\ndata: %s\n\n", data)
			flusher.Flush()
			return true
		}

		if !send() {
			return
		}

		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if !send() {
					return
				}
			}
		}
	}
}

// buildCloneURL constructs a clone URL based on provider and repo path.
func buildCloneURL(provider, repoPath, baseURL string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	repoPath = strings.Trim(repoPath, "/")
	if baseURL == "" || repoPath == "" {
		return ""
	}
	switch provider {
	case "github", "gitlab", "gitea", "forgejo":
		return baseURL + "/" + repoPath + ".git"
	default:
		return ""
	}
}

// extractRepoPath extracts the repo path from a clone URL.
func extractRepoPath(cloneURL string) string {
	// Remove protocol
	path := cloneURL
	for _, prefix := range []string{"https://", "http://", "git@"} {
		if len(path) > len(prefix) && path[:len(prefix)] == prefix {
			path = path[len(prefix):]
			break
		}
	}

	// Remove host
	if idx := indexByte(path, '/'); idx != -1 {
		path = path[idx+1:]
	}

	// Remove .git suffix
	if len(path) > 4 && path[len(path)-4:] == ".git" {
		path = path[:len(path)-4]
	}

	return path
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// RunLogsHandler retrieves logs from a run's Kubernetes pod.
// GET /api/runs/:id/k8s-logs?tail=100
func RunLogsHandler(db *gorm.DB, authService *auth.Service, k8sClient *runner.K8sClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		// Get run from database
		var run runner.Run
		if err := db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		if run.K8sJobName == "" || run.K8sNamespace == "" {
			http.Error(w, "run has no associated Kubernetes job", http.StatusBadRequest)
			return
		}

		// Parse tail parameter
		var tailLines *int64
		if tailStr := r.URL.Query().Get("tail"); tailStr != "" {
			if tail, err := strconv.ParseInt(tailStr, 10, 64); err == nil && tail > 0 {
				tailLines = &tail
			}
		}

		// Get logs from Kubernetes
		logs, err := k8sClient.GetPodLogs(r.Context(), run.K8sJobName, run.K8sNamespace, tailLines)
		if err != nil {
			log.Printf("failed to get pod logs: %v", err)
			http.Error(w, "failed to retrieve logs from Kubernetes", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(logs))
	}
}

// RunCancelHandler cancels a running job via Kubernetes API.
// POST /api/runs/:id/cancel
func RunCancelHandler(db *gorm.DB, authService *auth.Service, executor *runner.RunExecutor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		// Get run from database
		var run runner.Run
		if err := db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		// Check if run is cancellable
		if run.Status != runner.RunStatusQueued && run.Status != runner.RunStatusRunning {
			http.Error(w, "run cannot be cancelled in current state", http.StatusBadRequest)
			return
		}

		// Cancel the run
		if err := executor.CancelRun(r.Context(), runID, run.K8sJobName, run.K8sNamespace); err != nil {
			log.Printf("failed to cancel run: %v", err)
			http.Error(w, "failed to cancel run", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"message": "run cancelled successfully",
		})
	}
}

// RunJobStatusHandler gets the Kubernetes job status for a run.
// GET /api/runs/:id/k8s-status
func RunJobStatusHandler(db *gorm.DB, authService *auth.Service, k8sClient *runner.K8sClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		// Get run from database
		var run runner.Run
		if err := db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		if run.K8sJobName == "" || run.K8sNamespace == "" {
			http.Error(w, "run has no associated Kubernetes job", http.StatusBadRequest)
			return
		}

		// Get job status from Kubernetes
		job, err := k8sClient.GetJobStatus(r.Context(), run.K8sJobName, run.K8sNamespace)
		if err != nil {
			log.Printf("failed to get job status: %v", err)
			http.Error(w, "failed to retrieve job status from Kubernetes", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"job_name":        job.Name,
			"namespace":       job.Namespace,
			"active":          job.Status.Active,
			"succeeded":       job.Status.Succeeded,
			"failed":          job.Status.Failed,
			"start_time":      job.Status.StartTime,
			"completion_time": job.Status.CompletionTime,
			"conditions":      job.Status.Conditions,
		})
	}
}

// RunEventsHandler retrieves Kubernetes events for a run.
// GET /api/runs/{id}/events
func RunEventsHandler(db *gorm.DB, authService *auth.Service, k8sClient *runner.K8sClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		// Get run from database
		var run runner.Run
		if err := db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to get run", http.StatusInternalServerError)
			return
		}

		var (
			events    []runner.K8sEvent
			podStatus *runner.PodStatus
			err       error
		)

		if k8sClient != nil && run.K8sJobName != "" && run.K8sNamespace != "" {
			events, err = k8sClient.GetJobEvents(r.Context(), run.K8sJobName, run.K8sNamespace)
			if err != nil {
				log.Printf("failed to get job events: %v", err)
			} else {
				podStatus, _ = k8sClient.GetPodStatus(r.Context(), run.K8sJobName, run.K8sNamespace)
				if err := persistK8sSnapshot(r.Context(), db, runID, events, podStatus); err != nil {
					log.Printf("failed to store events: %v", err)
				}
			}
		}

		if len(events) == 0 && podStatus == nil {
			var ok bool
			events, podStatus, ok, err = loadPersistedK8sSnapshot(r.Context(), db, runID)
			if err != nil {
				log.Printf("failed to load stored events: %v", err)
				http.Error(w, "failed to retrieve events", http.StatusInternalServerError)
				return
			}
			if !ok {
				events = []runner.K8sEvent{}
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"events":     events,
			"pod_status": podStatus,
		})
	}
}

// RunSecretsHandler retrieves secret scanner findings for a run.
// GET /api/runs/{id}/secrets
func RunSecretsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}

		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID required", http.StatusBadRequest)
			return
		}

		var secret runner.RunSecret
		if err := db.WithContext(r.Context()).Where("run_id = ?", runID).First(&secret).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				// Return empty array if no secrets found
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"id":            "",
					"run_id":        runID,
					"findings":      []interface{}{},
					"finding_count": 0,
				})
				return
			}
			http.Error(w, "failed to fetch secrets", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, secret)
	}
}

// RunsRescheduleFailedHandler resets failed runs to QUEUED. Covers both
// CREATE_RUN (repo) and IMAGE_SCAN jobs; the "skip if a newer run exists"
// dedup is keyed on the job type's identity field (repo_id for CREATE_RUN,
// image_digest_id for IMAGE_SCAN) so re-running doesn't double-queue work
// that the system already has a fresher copy of.
// POST /api/runs/failed/reschedule
func RunsRescheduleFailedHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var totalFailed int64
		db.WithContext(r.Context()).Table("jobs").
			Where("type IN ? AND status = ?",
				[]string{jobs.JobTypeCreateRun, jobs.JobTypeImageScan},
				jobs.JobStatusFailed).
			Count(&totalFailed)

		// CREATE_RUN branch — dedup on repo_id.
		createRunResult := db.WithContext(r.Context()).Exec(`
			UPDATE jobs
			SET status = 'QUEUED', attempts = 0, error = '',
			    locked_at = NULL, locked_by = '', finished_at = NULL,
			    last_attempted_at = NULL, k8s_job_name = '', k8s_namespace = '',
			    updated_at = NOW(), run_at = NOW()
			WHERE type = ? AND status = ?
			  AND payload->>'repo_id' != ''
			  AND NOT EXISTS (
			      SELECT 1 FROM jobs j2
			      WHERE j2.type = ?
			        AND j2.status IN ('QUEUED', 'RUNNING', 'SUCCEEDED')
			        AND j2.payload->>'repo_id' = jobs.payload->>'repo_id'
			        AND j2.created_at > jobs.created_at
			  )`,
			jobs.JobTypeCreateRun, jobs.JobStatusFailed, jobs.JobTypeCreateRun,
		)
		if createRunResult.Error != nil {
			log.Printf("failed to reschedule CREATE_RUN runs: %v", createRunResult.Error)
			http.Error(w, "failed to reschedule failed runs", http.StatusInternalServerError)
			return
		}

		// IMAGE_SCAN branch — dedup on image_digest_id.
		imageScanResult := db.WithContext(r.Context()).Exec(`
			UPDATE jobs
			SET status = 'QUEUED', attempts = 0, error = '',
			    locked_at = NULL, locked_by = '', finished_at = NULL,
			    last_attempted_at = NULL, k8s_job_name = '', k8s_namespace = '',
			    updated_at = NOW(), run_at = NOW()
			WHERE type = ? AND status = ?
			  AND payload->>'image_digest_id' != ''
			  AND NOT EXISTS (
			      SELECT 1 FROM jobs j2
			      WHERE j2.type = ?
			        AND j2.status IN ('QUEUED', 'RUNNING', 'SUCCEEDED')
			        AND j2.payload->>'image_digest_id' = jobs.payload->>'image_digest_id'
			        AND j2.created_at > jobs.created_at
			  )`,
			jobs.JobTypeImageScan, jobs.JobStatusFailed, jobs.JobTypeImageScan,
		)
		if imageScanResult.Error != nil {
			log.Printf("failed to reschedule IMAGE_SCAN runs: %v", imageScanResult.Error)
			http.Error(w, "failed to reschedule failed runs", http.StatusInternalServerError)
			return
		}

		rescheduled := createRunResult.RowsAffected + imageScanResult.RowsAffected
		writeJSON(w, http.StatusOK, map[string]int64{
			"rescheduled": rescheduled,
			"skipped":     totalFailed - rescheduled,
		})
	}
}

// RunRetryHandler re-queues a single failed (or cancelled) job by ID.
// Unlike the bulk handler this skips the "newer run exists" check —
// when the user explicitly clicks "Run again" on a specific run, they
// want that run to fire again regardless of what's happened since.
// Works for both CREATE_RUN and IMAGE_SCAN.
// POST /api/runs/{id}/retry
func RunRetryHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAuth(w, r, authService) == nil {
			return
		}
		runID := r.PathValue("id")
		if runID == "" {
			http.Error(w, "run ID is required", http.StatusBadRequest)
			return
		}

		var job struct {
			ID     string
			Type   string
			Status string
		}
		if err := db.WithContext(r.Context()).Table("jobs").
			Where("id = ?", runID).
			First(&job).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			http.Error(w, "failed to read run", http.StatusInternalServerError)
			return
		}
		if job.Type != jobs.JobTypeCreateRun && job.Type != jobs.JobTypeImageScan {
			http.Error(w, "run type cannot be retried", http.StatusBadRequest)
			return
		}
		// Don't re-queue a run that already succeeded, is currently
		// running, or is already sitting in the queue. Anything else —
		// FAILED, RETRY (backoff), cancelled-but-not-reaped — is fair
		// game; the user explicitly asked for it to fire again.
		switch jobs.JobStatus(job.Status) {
		case jobs.JobStatusSucceeded, jobs.JobStatusRunning, jobs.JobStatusQueued:
			http.Error(w, "run is already "+strings.ToLower(job.Status)+"; not re-queueing", http.StatusBadRequest)
			return
		}

		result := db.WithContext(r.Context()).Exec(`
			UPDATE jobs
			SET status = 'QUEUED', attempts = 0, error = '',
			    locked_at = NULL, locked_by = '', finished_at = NULL,
			    last_attempted_at = NULL, k8s_job_name = '', k8s_namespace = '',
			    cancelled_at = NULL, cancelled_by = '',
			    updated_at = NOW(), run_at = NOW()
			WHERE id = ?
		`, runID)
		if result.Error != nil {
			log.Printf("retry run %s: %v", runID, result.Error)
			http.Error(w, "failed to re-queue run", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "QUEUED",
			"id":       runID,
			"requeued": result.RowsAffected,
		})
	}
}

// RunsDeleteFailedHandler deletes all failed runs.
// DELETE /api/runs/failed
func RunsDeleteFailedHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		result := db.WithContext(r.Context()).Exec(
			"DELETE FROM jobs WHERE type = ? AND status = ?",
			jobs.JobTypeCreateRun, jobs.JobStatusFailed,
		)
		if result.Error != nil {
			log.Printf("failed to delete failed runs: %v", result.Error)
			http.Error(w, "failed to delete failed runs", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, map[string]int64{
			"deleted": result.RowsAffected,
		})
	}
}
