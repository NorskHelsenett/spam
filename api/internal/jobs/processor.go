package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	// Embed IANA tzdata so time.LoadLocation works in the scratch
	// runtime image. ~450 KB; required for the EPSS daily-fetch
	// schedule pinned to Europe/Oslo.
	_ "time/tzdata"

	dbviews "github.com/NorskHelsenett/spam/internal/db"
	"github.com/NorskHelsenett/spam/internal/secretprobe"
	"github.com/NorskHelsenett/spam/internal/vulnerabilities"
	"github.com/NorskHelsenett/spam/internal/vulnmeta"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

// SBOMAdhocJobCreator is implemented by the runner when K8s is available.
// It allows the worker to create an ad-hoc SBOM scanner K8s job by
// cloning the deployed sbom-scanner CronJob's pod template.
type SBOMAdhocJobCreator interface {
	CreateSBOMAdhocJob(ctx context.Context, cronJobName string) error
}

// retryableError wraps an error to signal the worker to retry without counting
// the attempt against the job's max attempts.
type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

// IsRetryableWithoutCount reports whether the error should be retried without
// incrementing the attempt counter.
func IsRetryableWithoutCount(err error) bool {
	var t retryableError
	return errors.As(err, &t)
}

// RunExecutor is the interface for executing runs.
type RunExecutor interface {
	ExecuteRun(ctx context.Context, runID string, payload interface{}) error
}

// RunReconciler reconciles RUNNING jobs against their K8s job state.
type RunReconciler interface {
	ReconcileRunningJobs(ctx context.Context, db *gorm.DB, minAge time.Duration) (int, error)
}

// ProcessJob executes job-specific handlers.
func ProcessJob(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	switch job.Type {
	case JobTypeCreateRun:
		return processCreateRun(ctx, db, job, runExecutor)
	case JobTypeRefreshSBOMViews:
		return processRefreshSBOMViews(ctx, db)
	case JobTypeOSVScan:
		return processOSVScan(ctx, db, job.ID)
	case JobTypeSBOMAdhocScan:
		return processSBOMAdhocScan(ctx, job, runExecutor)
	case JobTypeProbeSecrets:
		return processProbeSecrets(ctx, db, job)
	case JobTypeVulnMetaFetch:
		return processVulnMetaFetch(ctx, db, job)
	case JobTypeFetchKEV:
		return processFetchKEV(ctx, db)
	case JobTypeFetchEPSS:
		return processFetchEPSS(ctx, db, job.ID)
	default:
		// IMAGE_SCAN jobs fall into "unknown" here on purpose: the worker
		// excludes them in ClaimNextJob, so reaching this branch would mean
		// the exclusion was removed without a replacement runtime. Fail
		// non-retryable so operators see the misconfiguration immediately.
		return nil, fmt.Errorf("unknown job type: %s", job.Type)
	}
}

func processRefreshSBOMViews(ctx context.Context, db *gorm.DB) (interface{}, error) {
	if err := dbviews.RefreshMaterializedViews(ctx, db); err != nil {
		if errors.Is(err, dbviews.ErrRefreshLockHeld) {
			// Another process holds the refresh lock. Retry without counting
			// the attempt so this job runs again once the lock is released.
			return nil, retryableError{err}
		}
		return nil, err
	}
	return map[string]string{"status": "refreshed"}, nil
}

func processOSVScan(ctx context.Context, db *gorm.DB, jobID string) (interface{}, error) {
	result, err := vulnerabilities.RunBatchScan(ctx, db, func(progress vulnerabilities.BatchScanResult) {
		if data, jsonErr := json.Marshal(progress); jsonErr == nil {
			db.WithContext(ctx).Model(&Job{}).Where("id = ?", jobID).Update("result", data)
		}
	})
	if err != nil {
		return result, err
	}
	// Coalesced background refresh — a batch scan can complete while
	// other scan events are also firing; TriggerRefresh ensures we
	// run at most one recompute per burst instead of serialising the
	// job on the expensive summary+repos query.
	vulnmetrics.TriggerRefresh(db)
	// Any new vuln_ids from this batch need advisory metadata
	// fetched from OSV/EUVD. Bounded per-call; successive calls
	// drain the backlog.
	EnqueueMissingVulnMeta(ctx, db)
	return result, nil
}

func processSBOMAdhocScan(ctx context.Context, job *Job, runExecutor RunExecutor) (interface{}, error) {
	creator, ok := runExecutor.(SBOMAdhocJobCreator)
	if !ok {
		return nil, NonRetryable(errors.New("sbom scan job creation not available: runner not enabled"))
	}

	// CronJob name comes from the worker's own environment — the worker owns K8s config.
	cronJobName := strings.TrimSpace(os.Getenv("SBOM_SCANNER_CRONJOB_NAME"))
	if cronJobName == "" {
		// Fall back to payload for backwards compatibility.
		var payload SBOMAdhocPayload
		if len(job.Payload) > 0 {
			_ = json.Unmarshal(job.Payload, &payload)
		}
		cronJobName = payload.CronJobName
	}
	if cronJobName == "" {
		return nil, NonRetryable(errors.New("SBOM_SCANNER_CRONJOB_NAME not configured on worker"))
	}

	if err := creator.CreateSBOMAdhocJob(ctx, cronJobName); err != nil {
		if isAlreadyRunning(err) {
			return nil, NonRetryable(err)
		}
		return nil, err
	}

	return map[string]string{"status": "created", "cronjob": cronJobName}, nil
}

// processVulnMetaFetch pulls advisory metadata for a single vuln_id
// from OSV (primary) and EUVD (CVE-prefix supplement) and caches the
// merged record in vuln_metadata. Emitted by enqueueVulnMetaFetches
// after new vuln_ids land from an OSV / Grype scan.
//
// Errors from the external APIs are non-retryable — a transient 5xx
// means "try later", not "try again right now." We return nil with a
// logged error; a follow-up scan pass will re-enqueue if the row is
// still missing.
func processVulnMetaFetch(ctx context.Context, db *gorm.DB, job *Job) (interface{}, error) {
	var payload VulnMetaFetchPayload
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &payload); err != nil {
			return nil, NonRetryable(fmt.Errorf("invalid VULN_META_FETCH payload: %w", err))
		}
	}
	if payload.VulnID == "" {
		return nil, NonRetryable(errors.New("VULN_META_FETCH missing vuln_id"))
	}
	meta, err := vulnmeta.Enrich(ctx, db, payload.VulnID)
	if errors.Is(err, vulnmeta.ErrUpstreamTransient) {
		// Transient upstream failure (403/429/5xx, decode mismatch, timeout).
		// Don't retry now — a follow-up scan pass will re-enqueue if the row
		// is still missing. Recording "not_found_upstream" here would be a
		// lie: we don't actually know whether the vuln exists upstream.
		return map[string]string{"vuln_id": payload.VulnID, "status": "upstream_error"}, nil
	}
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return map[string]string{"vuln_id": payload.VulnID, "status": "not_found_upstream"}, nil
	}
	return map[string]string{"vuln_id": payload.VulnID, "status": "enriched"}, nil
}

// vulnMetaEnqueueCap bounds how many VULN_META_FETCH jobs a single
// scan-complete hook will create per call. Backfills after a cold
// start can otherwise enqueue thousands of jobs at once, starving
// the worker's other queues. At the cap, any remaining missing IDs
// are picked up on the next scan-complete hook — steady state
// converges within a few ingest cycles.
const vulnMetaEnqueueCap = 1000

// EnqueueVulnMetaFetches creates one VULN_META_FETCH job per vuln_id
// that doesn't already have a cached metadata row. Best-effort — a
// failure to enqueue is logged but does not fail the calling scan.
// Safe to call with duplicates or unknown IDs; the store dedupes.
func EnqueueVulnMetaFetches(ctx context.Context, db *gorm.DB, vulnIDs []string) {
	missing, err := vulnmeta.IDsMissingMetadata(ctx, db, vulnIDs)
	if err != nil {
		log.Printf("vulnmeta: list missing: %v", err)
		return
	}
	for _, id := range missing {
		if _, err := CreateJob(ctx, db, CreateJobInput{
			Type:    JobTypeVulnMetaFetch,
			Payload: VulnMetaFetchPayload{VulnID: id},
		}); err != nil {
			log.Printf("vulnmeta: enqueue %s: %v", id, err)
		}
	}
}

// EnqueueMissingVulnMeta is the bulk variant: walks the union of
// component_vulnerabilities + image_vuln_findings, finds every
// vuln_id without a vuln_metadata row, and enqueues a fetch job
// for each (up to vulnMetaEnqueueCap). Call from every scan-
// completion hook — the LEFT JOIN filter means steady-state is
// cheap; only new vulns actually enqueue.
func EnqueueMissingVulnMeta(ctx context.Context, db *gorm.DB) {
	var ids []string
	if err := db.WithContext(ctx).Raw(`
		SELECT DISTINCT vuln_id FROM (
			SELECT vuln_id FROM component_vulnerabilities
			WHERE vuln_id <> '_none' AND vuln_id <> ''
			UNION ALL
			SELECT vuln_id FROM image_vuln_findings
			WHERE vuln_id <> '_none' AND vuln_id <> ''
		) u
		WHERE vuln_id NOT IN (SELECT vuln_id FROM vuln_metadata)
		LIMIT ?
	`, vulnMetaEnqueueCap).Scan(&ids).Error; err != nil {
		log.Printf("vulnmeta: scan for missing: %v", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	EnqueueVulnMetaFetches(ctx, db, ids)
}

// kevRefreshInterval is how often we re-pull the CISA KEV catalog.
// CISA edits the list a few times per week without pre-announcement,
// so a tighter cadence than EPSS catches a fresh exploited-in-the-wild
// CVE within ~kevRefreshInterval instead of waiting up to a day.
// Bytes are negligible (~1.5k rows JSON).
const kevRefreshInterval = 6 * time.Hour

// epssDailyHourLocal is the local hour-of-day for the EPSS daily
// refresh. FIRST.org publishes a single CSV per UTC day; we pin the
// fetch to early-morning local time so analysts arriving for the day
// see scoring that's at most a few hours behind upstream rather than
// up-to-24h-stale carryover from the previous workday.
const epssDailyHourLocal = 5

// epssLocation is the timezone the EPSS daily-fetch hour is anchored
// to. Picked once at package init so DST transitions are handled
// correctly without re-resolving the zone on every schedule call.
// Falls back to UTC if the zoneinfo data isn't shipped (alpine
// containers without tzdata, etc.) — analysts then see fetches at
// 05:00 UTC, which is still within "before work".
var epssLocation = mustLoadLocation("Europe/Oslo")

func mustLoadLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		log.Printf("vuln-feeds: failed to load timezone %s, falling back to UTC: %v", name, err)
		return time.UTC
	}
	return loc
}

// nextFeedRunAt returns when the given feed type should next refresh
// relative to `from`. KEV uses a fixed 6h interval; EPSS pins to the
// next 05:00 in Europe/Oslo so the daily snapshot lands just before
// the workday starts.
func nextFeedRunAt(jobType JobType, from time.Time) time.Time {
	switch jobType {
	case JobTypeFetchEPSS:
		local := from.In(epssLocation)
		next := time.Date(local.Year(), local.Month(), local.Day(), epssDailyHourLocal, 0, 0, 0, epssLocation)
		if !next.After(from) {
			next = next.Add(24 * time.Hour)
		}
		return next
	case JobTypeFetchKEV:
		return from.Add(kevRefreshInterval)
	default:
		// Unknown feed type — return a safe default; the caller
		// shouldn't reach here, the switch above is exhaustive over
		// the FETCH_* types EnsureFeedRefreshScheduled iterates.
		return from.Add(24 * time.Hour)
	}
}

// processFetchKEV pulls the CISA KEV catalog into cisa_kev_entries
// and enqueues the next refresh +24 h out. The unique index on
// (type, status IN QUEUED|RETRY) makes the re-enqueue idempotent
// across replicas.
func processFetchKEV(ctx context.Context, db *gorm.DB) (interface{}, error) {
	count, err := vulnmeta.IngestKEV(ctx, db)
	if err != nil {
		return nil, err
	}
	scheduleNextFeedRefresh(ctx, db, JobTypeFetchKEV)
	// KEV is the strongest exploitation signal we surface; warm the
	// dashboard cache so the next list view picks up the new boost
	// rather than serving the previous order from cache.
	vulnmetrics.TriggerRefresh(db)
	return map[string]any{"status": "ingested", "rows": count}, nil
}

// processFetchEPSS pulls the FIRST.org EPSS daily snapshot and
// reschedules. Streams progress (rows-written running total) into
// Job.Result every batch so the admin UI can render a live progress
// indicator without polling the upstream feed itself.
func processFetchEPSS(ctx context.Context, db *gorm.DB, jobID string) (interface{}, error) {
	progress := func(written int) {
		if data, jsonErr := json.Marshal(map[string]any{
			"status":       "ingesting",
			"rows_written": written,
		}); jsonErr == nil {
			db.WithContext(ctx).Model(&Job{}).Where("id = ?", jobID).Update("result", data)
		}
	}
	count, err := vulnmeta.IngestEPSS(ctx, db, progress)
	if err != nil {
		return nil, err
	}
	scheduleNextFeedRefresh(ctx, db, JobTypeFetchEPSS)
	vulnmetrics.TriggerRefresh(db)
	return map[string]any{"status": "ingested", "rows": count}, nil
}

// scheduleNextFeedRefresh enqueues a follow-up FETCH_* job at the
// next slot dictated by nextFeedRunAt for the given feed type.
// Failures are logged but not fatal — the EnsureFeedRefreshScheduled
// startup hook covers the case where a follow-up didn't get queued.
func scheduleNextFeedRefresh(ctx context.Context, db *gorm.DB, jobType JobType) {
	runAt := nextFeedRunAt(jobType, time.Now())
	if _, err := CreateJob(ctx, db, CreateJobInput{
		Type:  jobType,
		RunAt: runAt,
	}); err != nil {
		// Duplicate-key collisions just mean another replica already
		// queued the next refresh; treat them as success.
		if !strings.Contains(err.Error(), "duplicate key") &&
			!strings.Contains(err.Error(), "ux_jobs_fetch_") {
			log.Printf("schedule next %s: %v", jobType, err)
		}
	}
}

// EnsureFeedRefreshScheduled queues a FETCH_KEV / FETCH_EPSS job at
// startup if neither is already pending. If the most recent successful
// run is recent enough that the next scheduled slot hasn't yet arrived,
// we enqueue at the upcoming slot; otherwise we fire immediately.
// Idempotent via the partial unique index — duplicate queue attempts
// no-op silently. Call from the worker boot path so a fresh deploy
// picks up feeds without waiting for the previous schedule to fire.
func EnsureFeedRefreshScheduled(ctx context.Context, db *gorm.DB) {
	now := time.Now()
	for _, jobType := range []JobType{JobTypeFetchKEV, JobTypeFetchEPSS} {
		// If a queued/retry job already exists, the unique index
		// would reject a fresh insert anyway — but checking first
		// keeps the log clean.
		var pending int64
		if err := db.WithContext(ctx).Model(&Job{}).
			Where("type = ? AND status IN ?", jobType, []JobStatus{JobStatusQueued, JobStatusRetry}).
			Count(&pending).Error; err == nil && pending > 0 {
			continue
		}

		// If we ran successfully recently enough, the next slot is
		// after now — schedule there so we don't double-fetch on a
		// quick restart cycle. Otherwise fetch immediately.
		var lastSuccess time.Time
		_ = db.WithContext(ctx).Model(&Job{}).
			Select("COALESCE(MAX(finished_at), '1970-01-01')").
			Where("type = ? AND status = ?", jobType, JobStatusSucceeded).
			Scan(&lastSuccess).Error

		runAt := now
		if !lastSuccess.IsZero() {
			if next := nextFeedRunAt(jobType, lastSuccess); next.After(now) {
				runAt = next
			}
		}

		if _, err := CreateJob(ctx, db, CreateJobInput{
			Type:  jobType,
			RunAt: runAt,
		}); err != nil {
			if !strings.Contains(err.Error(), "duplicate key") &&
				!strings.Contains(err.Error(), "ux_jobs_fetch_") {
				log.Printf("ensure %s scheduled: %v", jobType, err)
			}
		}
	}
}

func processProbeSecrets(ctx context.Context, db *gorm.DB, job *Job) (interface{}, error) {
	// Parse optional rule_ids filter from payload.
	var opts secretprobe.RunOptions
	if len(job.Payload) > 0 {
		var payload struct {
			RuleIDs []string `json:"rule_ids"`
			Hashes  []string `json:"hashes"`
		}
		if json.Unmarshal(job.Payload, &payload) == nil {
			opts.RuleIDs = payload.RuleIDs
			opts.Hashes = payload.Hashes
		}
	}

	runner := secretprobe.NewRunner(db)
	result, err := runner.Run(ctx, opts, func(probed, total int) {
		if data, jsonErr := json.Marshal(map[string]int{"probed": probed, "total": total}); jsonErr == nil {
			db.WithContext(ctx).Model(&Job{}).Where("id = ?", job.ID).Update("result", data)
		}
	})
	if err != nil {
		return result, err
	}
	return result, nil
}

func isAlreadyRunning(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "already running") || strings.Contains(err.Error(), "AlreadyExists"))
}

func processCreateRun(ctx context.Context, db *gorm.DB, job *Job, runExecutor RunExecutor) (interface{}, error) {
	if runExecutor == nil {
		return nil, errors.New("runner not enabled")
	}

	var payload CreateRunPayload
	if len(job.Payload) == 0 {
		return nil, errors.New("missing job payload")
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal payload: %w", err)
	}
	if payload.CloneURL == "" {
		return nil, errors.New("missing clone_url in payload")
	}

	if err := runExecutor.ExecuteRun(ctx, job.ID, payload); err != nil {
		return nil, fmt.Errorf("execute run: %w", err)
	}

	return map[string]string{
		"status": "started",
		"run_id": job.ID,
	}, nil
}

func NextRetryTime(attempts, maxAttempts int, now time.Time) time.Time {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	// Exponential backoff: 1min, 2min, 4min, 8min, 16min, capped at 30min
	delay := time.Minute
	for i := 1; i < attempts; i++ {
		delay *= 2
	}
	const maxDelay = 30 * time.Minute
	if delay > maxDelay {
		delay = maxDelay
	}
	return now.Add(delay)
}
