package uiapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/secretprobe"
	"gorm.io/gorm"
)

// AdminSecretProbeScanHandler queues a PROBE_SECRETS job.
// Accepts optional JSON body: {"rule_ids": ["github-pat", "slack-webhook-url"]}
//
// POST /api/admin/secrets/probe
func AdminSecretProbeScanHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		// Parse optional filter.
		var body struct {
			RuleIDs []string `json:"rule_ids"`
			Force   bool     `json:"force"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}

		// Check if a probe job is already queued or running.
		var count int64
		db.WithContext(r.Context()).
			Model(&jobs.Job{}).
			Where("type = ? AND status IN ?", jobs.JobTypeProbeSecrets, []string{"QUEUED", "RUNNING"}).
			Count(&count)
		if count > 0 {
			writeJSON(w, http.StatusConflict, map[string]string{
				"error":   "already_running",
				"message": "A secret probe job is already queued or running.",
			})
			return
		}

		// Store options in job payload.
		var payload json.RawMessage
		if len(body.RuleIDs) > 0 || body.Force {
			payload, _ = json.Marshal(map[string]any{"rule_ids": body.RuleIDs, "force": body.Force})
		}

		job, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type:        jobs.JobTypeProbeSecrets,
			MaxAttempts: 2,
			Payload:     payload,
		})
		if err != nil {
			http.Error(w, "failed to create probe job", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]string{
			"job_id": job.ID,
			"status": "queued",
		})
	}
}

// AdminSecretProbeStatusHandler returns the status of the latest PROBE_SECRETS job
// and aggregate probe statistics.
//
// GET /api/admin/secrets/probe/status
func AdminSecretProbeStatusHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var job jobs.Job
		jobFound := db.WithContext(r.Context()).
			Where("type = ?", jobs.JobTypeProbeSecrets).
			Order("created_at DESC").
			First(&job).Error == nil

		counts, total, _ := secretprobe.Stats(r.Context(), db)

		// List registered rule IDs so the admin UI can show which types are probeable.
		registered := secretprobe.RegisteredRuleIDs()

		type jobInfo struct {
			ID         string         `json:"id,omitempty"`
			Status     jobs.JobStatus `json:"status,omitempty"`
			CreatedAt  string         `json:"created_at,omitempty"`
			FinishedAt string         `json:"finished_at,omitempty"`
			Error      string         `json:"error,omitempty"`
			Result     any            `json:"result,omitempty"`
		}

		resp := struct {
			Job            *jobInfo       `json:"job,omitempty"`
			Stats          map[string]any `json:"stats"`
			RegisteredRules []string      `json:"registered_rules"`
		}{
			Stats: map[string]any{
				"total":          total,
				"valid":          counts[secretprobe.StatusValid],
				"invalid":        counts[secretprobe.StatusInvalid],
				"revoked":        counts[secretprobe.StatusRevoked],
				"expired":        counts[secretprobe.StatusExpired],
				"false_positive": counts[secretprobe.StatusFalsePositive],
				"unknown":        counts[secretprobe.StatusUnknown],
				"error":          counts[secretprobe.StatusError],
			},
			RegisteredRules: registered,
		}

		if jobFound {
			ji := &jobInfo{
				ID:        job.ID,
				Status:    job.Status,
				CreatedAt: job.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
				Error:     job.Error,
			}
			if job.FinishedAt != nil {
				ji.FinishedAt = job.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
			}
			if len(job.Result) > 0 {
				ji.Result = job.Result
			}
			resp.Job = ji
		}

		writeJSON(w, http.StatusOK, resp)
	}
}

// AdminSecretProbeOneHandler probes a single secret finding.
//
// POST /api/admin/secrets/probe/one?repo_id=...&fingerprint=...
func AdminSecretProbeOneHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
		fingerprint := strings.TrimSpace(r.URL.Query().Get("fingerprint"))
		if repoID == "" || fingerprint == "" {
			http.Error(w, "repo_id and fingerprint are required", http.StatusBadRequest)
			return
		}

		runner := secretprobe.NewRunner(db)
		probe, err := runner.ProbeOne(r.Context(), repoID, fingerprint)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "finding not found", http.StatusNotFound)
				return
			}
			http.Error(w, "probe failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, probe)
	}
}

// AdminSecretProbePreviewHandler returns a preview of what will be probed,
// grouped by rule type. No actual probing is performed.
//
// GET /api/admin/secrets/probe/preview
func AdminSecretProbePreviewHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		includeProbed := r.URL.Query().Get("include_probed") == "true"
		runner := secretprobe.NewRunner(db)
		preview, err := runner.Preview(r.Context(), secretprobe.PreviewOptions{
			IncludeProbed: includeProbed,
		})
		if err != nil {
			http.Error(w, "failed to build preview", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, preview)
	}
}

// ProbeListItem is a rich view of a probed secret including where it was found.
type ProbeListItem struct {
	SecretHash string               `json:"secret_hash"`
	RuleID     string               `json:"rule_id"`
	Status     secretprobe.Status   `json:"status"`
	Reason     string               `json:"reason,omitempty"`
	Metadata   string               `json:"metadata,omitempty"`
	ProbedAt   string               `json:"probed_at"`
	Locations  []ProbeListLocation  `json:"locations"`
}

type ProbeListLocation struct {
	RepoID   string `json:"repo_id"`
	RepoName string `json:"repo_name"`
	RepoURL  string `json:"repo_url"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Secret   string `json:"secret,omitempty"`
	SubType  string `json:"sub_type,omitempty"`
}

// AdminSecretProbeListHandler returns probed secrets with locations, filtered by status.
//
// GET /api/admin/secrets/probe/list?status=valid&status=revoked
func AdminSecretProbeListHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		statuses := r.URL.Query()["status"]

		q := db.WithContext(r.Context()).
			Model(&secretprobe.SecretProbe{}).
			Order("CASE status WHEN 'valid' THEN 0 WHEN 'revoked' THEN 1 WHEN 'expired' THEN 2 WHEN 'invalid' THEN 3 WHEN 'false_positive' THEN 4 WHEN 'unknown' THEN 5 WHEN 'error' THEN 6 ELSE 7 END, probed_at DESC").
			Limit(200)

		if len(statuses) > 0 {
			q = q.Where("status IN ?", statuses)
		}

		var probes []secretprobe.SecretProbe
		if err := q.Find(&probes).Error; err != nil {
			http.Error(w, "failed to load probes", http.StatusInternalServerError)
			return
		}

		// Collect hashes for location lookup.
		hashes := make([]string, len(probes))
		for i, p := range probes {
			hashes[i] = p.SecretHash
		}

		// Find locations: scan latest findings per repo and match by hash.
		locations := map[string][]ProbeListLocation{}
		if len(hashes) > 0 {
			type findingRow struct {
				RepoID   string
				RepoName string
				RepoURL  string
				Findings json.RawMessage
			}
			var rows []findingRow
			db.WithContext(r.Context()).Raw(`
				SELECT rs.repo_id,
				       r.org || '/' || r.slug AS repo_name,
				       RTRIM(COALESCE(pi.base_url,
				         CASE r.provider WHEN 'github' THEN 'https://github.com' WHEN 'gitlab' THEN 'https://gitlab.com' ELSE '' END
				       ), '/') || '/' || r.org || '/' || r.slug AS repo_url,
				       rs.findings
				FROM (
				  SELECT DISTINCT ON (repo_id) repo_id, findings
				  FROM run_secrets
				  WHERE repo_id IS NOT NULL AND repo_id <> ''
				  ORDER BY repo_id, created_at DESC
				) rs
				JOIN repos r ON r.id = rs.repo_id
				LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
			`).Scan(&rows)

			hashSet := map[string]bool{}
			for _, h := range hashes {
				hashSet[h] = true
			}

			for _, row := range rows {
				var findings []struct {
					RuleID    string `json:"RuleID"`
					File      string `json:"File"`
					StartLine int    `json:"StartLine"`
					Match     string `json:"Match"`
					Secret    string `json:"Secret"`
				}
				if json.Unmarshal(row.Findings, &findings) != nil {
					continue
				}
				for _, f := range findings {
					secret := secretprobe.ExtractSecret(f.Match)
					if f.Secret != "" {
						secret = secretprobe.ExtractSecret(f.Secret)
					}
					hash := secretprobe.SecretHash(secret)
					if !hashSet[hash] {
						continue
					}
					locations[hash] = append(locations[hash], ProbeListLocation{
						RepoID:   row.RepoID,
						RepoName: row.RepoName,
						RepoURL:  row.RepoURL,
						File:     f.File,
						Line:     f.StartLine,
						Secret:   secret,
						SubType:  secretprobe.ExtractKeyName(f.Match),
					})
				}
			}
		}

		// Build response.
		result := make([]ProbeListItem, 0, len(probes))
		for _, p := range probes {
			locs := locations[p.SecretHash]
			if locs == nil {
				locs = []ProbeListLocation{}
			}
			result = append(result, ProbeListItem{
				SecretHash: p.SecretHash,
				RuleID:     p.RuleID,
				Status:     p.Status,
				Reason:     p.Reason,
				Metadata:   p.Metadata,
				ProbedAt:   p.ProbedAt.UTC().Format("2006-01-02T15:04:05Z"),
				Locations:  locs,
			})
		}

		writeJSON(w, http.StatusOK, result)
	}
}

// AdminSecretProbeExportHandler exports probed secrets as CSV.
//
// GET /api/admin/secrets/probe/export?status=valid
func AdminSecretProbeExportHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		// Reuse the list handler logic to get enriched data.
		statuses := r.URL.Query()["status"]
		q := db.WithContext(r.Context()).
			Model(&secretprobe.SecretProbe{}).
			Order("CASE status WHEN 'valid' THEN 0 WHEN 'revoked' THEN 1 WHEN 'expired' THEN 2 WHEN 'invalid' THEN 3 WHEN 'false_positive' THEN 4 WHEN 'unknown' THEN 5 WHEN 'error' THEN 6 ELSE 7 END, probed_at DESC")
		if len(statuses) > 0 {
			q = q.Where("status IN ?", statuses)
		}
		var probes []secretprobe.SecretProbe
		if err := q.Find(&probes).Error; err != nil {
			http.Error(w, "failed to load probes", http.StatusInternalServerError)
			return
		}

		// Scan findings for locations (same as list handler).
		hashes := make([]string, len(probes))
		for i, p := range probes {
			hashes[i] = p.SecretHash
		}
		type loc struct {
			repoName, repoURL, file, secret string
			line                            int
		}
		locations := map[string][]loc{}
		if len(hashes) > 0 {
			type row struct {
				RepoID   string
				RepoName string
				RepoURL  string
				Findings json.RawMessage
			}
			var rows []row
			db.WithContext(r.Context()).Raw(`
				SELECT rs.repo_id,
				       r.org || '/' || r.slug AS repo_name,
				       RTRIM(COALESCE(pi.base_url,
				         CASE r.provider WHEN 'github' THEN 'https://github.com' WHEN 'gitlab' THEN 'https://gitlab.com' ELSE '' END
				       ), '/') || '/' || r.org || '/' || r.slug AS repo_url,
				       rs.findings
				FROM (
				  SELECT DISTINCT ON (repo_id) repo_id, findings
				  FROM run_secrets WHERE repo_id IS NOT NULL AND repo_id <> ''
				  ORDER BY repo_id, created_at DESC
				) rs
				JOIN repos r ON r.id = rs.repo_id
				LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
			`).Scan(&rows)
			hashSet := map[string]bool{}
			for _, h := range hashes {
				hashSet[h] = true
			}
			for _, row := range rows {
				var findings []struct {
					RuleID    string `json:"RuleID"`
					File      string `json:"File"`
					StartLine int    `json:"StartLine"`
					Match     string `json:"Match"`
					Secret    string `json:"Secret"`
				}
				if json.Unmarshal(row.Findings, &findings) != nil {
					continue
				}
				for _, f := range findings {
					secret := secretprobe.ExtractSecret(f.Match)
					if f.Secret != "" {
						secret = secretprobe.ExtractSecret(f.Secret)
					}
					hash := secretprobe.SecretHash(secret)
					if !hashSet[hash] {
						continue
					}
					locations[hash] = append(locations[hash], loc{
						repoName: row.RepoName, repoURL: row.RepoURL, file: f.File, secret: secret, line: f.StartLine,
					})
				}
			}
		}

		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=secret-probe-export.csv")
		_, _ = fmt.Fprintln(w, "status,rule_id,reason,secret,repo,repo_url,file,line,probed_at")
		for _, p := range probes {
			locs := locations[p.SecretHash]
			if len(locs) == 0 {
				_, _ = fmt.Fprintf(w, "%s,%s,%s,,,%s,,,%s\n",
					csvEscape(string(p.Status)), csvEscape(p.RuleID), csvEscape(p.Reason), csvEscape(p.SecretHash), p.ProbedAt.UTC().Format("2006-01-02T15:04:05Z"))
			}
			for _, l := range locs {
				_, _ = fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s,%d,%s\n",
					csvEscape(string(p.Status)), csvEscape(p.RuleID), csvEscape(p.Reason),
					csvEscape(l.secret), csvEscape(l.repoName), csvEscape(l.repoURL), csvEscape(l.file), l.line,
					p.ProbedAt.UTC().Format("2006-01-02T15:04:05Z"))
			}
		}
	}
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// AdminSecretProbeAuditHandler returns recent audit log entries.
//
// GET /api/admin/secrets/probe/audit?limit=50&secret_hash=...
func AdminSecretProbeAuditHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		q := db.WithContext(r.Context()).
			Model(&secretprobe.ProbeAuditLog{}).
			Order("created_at DESC").
			Limit(50)

		if hash := r.URL.Query().Get("secret_hash"); hash != "" {
			q = q.Where("secret_hash = ?", hash)
		}
		if ruleID := r.URL.Query().Get("rule_id"); ruleID != "" {
			q = q.Where("rule_id = ?", ruleID)
		}

		var logs []secretprobe.ProbeAuditLog
		if err := q.Find(&logs).Error; err != nil {
			http.Error(w, "failed to load audit logs", http.StatusInternalServerError)
			return
		}
		if logs == nil {
			logs = []secretprobe.ProbeAuditLog{}
		}
		writeJSON(w, http.StatusOK, logs)
	}
}
