package uiapi

import (
	"net/http"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// Admin jobs view. Groups every job type into the worker pool that
// claims it so an operator can answer "what's running right now"
// without joining the docs to the queue layout.
//
//   GET /api/admin/jobs
//
// The pools are deliberately defined here (not in the worker) because
// this is a UI-side concept: the worker only knows that VULN_META_FETCH
// is excluded from the main claim and that IMAGE_SCAN is leased over
// HTTP. The admin view re-frames that as three pools so the layout
// matches how operators reason about throughput.

type adminPoolDef struct {
	Name        string
	Label       string
	Description string
	Types       []string
}

// jobPoolDefs is the source of truth for pool grouping in the admin
// view. Keep in sync with:
//   - cmd/worker/main.go:           main loop's exclude list (IMAGE_SCAN + VULN_META_FETCH)
//   - cmd/worker/main.go:           runVulnMetaPool (claims VULN_META_FETCH)
//   - runner/cmd/image-scanner:     dedicated pod that leases IMAGE_SCAN
var jobPoolDefs = []adminPoolDef{
	{
		Name:        "main",
		Label:       "Main worker pool",
		Description: "In-process worker for CREATE_RUN dispatches plus the light scheduled job types (KEV/EPSS feeds, OSV scans, secret probes). REFRESH_SBOM_VIEWS is drain-only — new SBOM-view refreshes run as in-process goroutines now (see Materialised views panel).",
		Types: []string{
			jobs.JobTypeCreateRun,
			jobs.JobTypeRefreshSBOMViews,
			jobs.JobTypeOSVScan,
			jobs.JobTypeSBOMAdhocScan,
			jobs.JobTypeProbeSecrets,
			jobs.JobTypeFetchKEV,
			jobs.JobTypeFetchEPSS,
			jobs.JobTypeDBMaintenance,
			jobs.JobTypeAdvisoryBackfill,
		},
	},
	{
		Name:        "vuln-meta",
		Label:       "Vuln-meta pool",
		Description: "Dedicated goroutine pool inside the worker that drains VULN_META_FETCH (OSV/EUVD enrichment) so a large backfill cannot starve user-facing dispatches in the main pool.",
		Types:       []string{jobs.JobTypeVulnMetaFetch},
	},
	{
		Name:        "image-scan",
		Label:       "Image scanner pool",
		Description: "Dedicated spam-image-scanner pod that leases IMAGE_SCAN jobs over HTTP, keeping the grype/trivy DB warm across many digests.",
		Types:       []string{jobs.JobTypeImageScan},
	},
}

type adminJobCount struct {
	Type      string `json:"type"`
	Running   int    `json:"running"`
	Queued    int    `json:"queued"`
	Retry     int    `json:"retry"`
	Failed    int    `json:"failed"`
	Succeeded int    `json:"succeeded"`
}

type adminRunningJob struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Attempts    int        `json:"attempts"`
	MaxAttempts int        `json:"max_attempts"`
	LockedAt    *time.Time `json:"locked_at"`
	LockedBy    string     `json:"locked_by"`
	AgeSeconds  int        `json:"age_seconds"`
}

type adminPoolView struct {
	Name        string            `json:"name"`
	Label       string            `json:"label"`
	Description string            `json:"description"`
	Types       []string          `json:"types"`
	Counts      []adminJobCount   `json:"counts"`
	Running     []adminRunningJob `json:"running"`
}

type adminJobsResponse struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Pools     []adminPoolView `json:"pools"`
}

// AdminJobsHandler — GET /api/admin/jobs
//
// Two queries:
//   - status counts grouped by (type, status), unbounded — the result
//     set is bounded by len(JobType) * len(JobStatus) ≈ 50 rows.
//   - currently RUNNING jobs, capped at 200 rows. Across all three
//     pools we expect <30 in steady state; the cap is a guardrail
//     against a stuck reaper accidentally stalling thousands.
func AdminJobsHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}
		ctx := r.Context()

		type countRow struct {
			Type   string `gorm:"column:type"`
			Status string `gorm:"column:status"`
			Count  int    `gorm:"column:count"`
		}
		var countRows []countRow
		if err := db.WithContext(ctx).Raw(`
			SELECT type, status, COUNT(*)::int AS count
			FROM jobs
			GROUP BY type, status
		`).Scan(&countRows).Error; err != nil {
			http.Error(w, "failed to load job counts", http.StatusInternalServerError)
			return
		}

		// Index counts by (type, status) for quick per-pool lookup.
		// Map[type]map[status]int.
		byType := make(map[string]map[string]int, len(countRows))
		for _, row := range countRows {
			if byType[row.Type] == nil {
				byType[row.Type] = make(map[string]int, 5)
			}
			byType[row.Type][row.Status] = row.Count
		}

		var runningRows []jobs.Job
		if err := db.WithContext(ctx).
			Select("id", "type", "attempts", "max_attempts", "locked_at", "locked_by").
			Where("status = ?", jobs.JobStatusRunning).
			Order("locked_at ASC NULLS LAST").
			Limit(200).
			Find(&runningRows).Error; err != nil {
			http.Error(w, "failed to load running jobs", http.StatusInternalServerError)
			return
		}

		now := time.Now()
		runningByType := make(map[string][]adminRunningJob, len(runningRows))
		for _, j := range runningRows {
			age := 0
			if j.LockedAt != nil {
				if delta := now.Sub(*j.LockedAt).Seconds(); delta > 0 {
					age = int(delta)
				}
			}
			runningByType[j.Type] = append(runningByType[j.Type], adminRunningJob{
				ID:          j.ID,
				Type:        j.Type,
				Attempts:    j.Attempts,
				MaxAttempts: j.MaxAttempts,
				LockedAt:    j.LockedAt,
				LockedBy:    j.LockedBy,
				AgeSeconds:  age,
			})
		}

		pools := make([]adminPoolView, 0, len(jobPoolDefs))
		for _, def := range jobPoolDefs {
			counts := make([]adminJobCount, 0, len(def.Types))
			running := []adminRunningJob{}
			for _, t := range def.Types {
				m := byType[t]
				counts = append(counts, adminJobCount{
					Type:      t,
					Running:   m[string(jobs.JobStatusRunning)],
					Queued:    m[string(jobs.JobStatusQueued)],
					Retry:     m[string(jobs.JobStatusRetry)],
					Failed:    m[string(jobs.JobStatusFailed)],
					Succeeded: m[string(jobs.JobStatusSucceeded)],
				})
				if list, ok := runningByType[t]; ok {
					running = append(running, list...)
				}
			}
			pools = append(pools, adminPoolView{
				Name:        def.Name,
				Label:       def.Label,
				Description: def.Description,
				Types:       def.Types,
				Counts:      counts,
				Running:     running,
			})
		}

		writeJSON(w, http.StatusOK, adminJobsResponse{
			FetchedAt: now,
			Pools:     pools,
		})
	}
}
