package uiapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"gorm.io/gorm"
)

// Admin database storage view. Surfaces pg_catalog / pg_stat_user_tables
// so an operator can see why the DB is slow without dropping into psql:
// table sizes, row counts, dead-tuple ratios, and last (auto)vacuum
// timestamps. Read-only; no audit wrap (it's a poll-friendly status
// endpoint that does not mutate state).
//
//   GET /api/admin/db/storage

type adminDBTableRow struct {
	Schema             string     `json:"schema"`
	Name               string     `json:"name"`
	TotalBytes         int64      `json:"total_bytes"`
	TableBytes         int64      `json:"table_bytes"`
	IndexesBytes       int64      `json:"indexes_bytes"`
	ToastBytes         int64      `json:"toast_bytes"`
	LiveRows           int64      `json:"live_rows"`
	DeadRows           int64      `json:"dead_rows"`
	DeadRatio          float64    `json:"dead_ratio"`
	LastVacuum         *time.Time `json:"last_vacuum,omitempty"`
	LastAutoVacuum     *time.Time `json:"last_autovacuum,omitempty"`
	LastAnalyze        *time.Time `json:"last_analyze,omitempty"`
	LastAutoAnalyze    *time.Time `json:"last_autoanalyze,omitempty"`
	SeqScan            int64      `json:"seq_scan"`
	IdxScan            int64      `json:"idx_scan"`
}

type adminDBStorageResponse struct {
	FetchedAt      time.Time         `json:"fetched_at"`
	Database       string            `json:"database"`
	DatabaseBytes  int64             `json:"database_bytes"`
	TableCount     int               `json:"table_count"`
	TotalTableBytes int64            `json:"total_table_bytes"`
	Tables         []adminDBTableRow `json:"tables"`
}

// AdminDBStorageHandler — GET /api/admin/db/storage
//
// Two queries, both bounded:
//   - pg_database_size(current_database()) plus current_database() name.
//   - per-table rollup from pg_catalog + pg_stat_user_tables, restricted
//     to user schemas (excludes pg_catalog / information_schema). Includes
//     TOAST size via pg_total_relation_size - pg_relation_size - indexes,
//     and live/dead tuple counts so the UI can flag bloated tables.
func AdminDBStorageHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}
		ctx := r.Context()

		var dbInfo struct {
			Name  string `gorm:"column:name"`
			Bytes int64  `gorm:"column:bytes"`
		}
		if err := db.WithContext(ctx).Raw(`
			SELECT current_database() AS name,
			       pg_database_size(current_database())::bigint AS bytes
		`).Scan(&dbInfo).Error; err != nil {
			http.Error(w, "failed to load database size", http.StatusInternalServerError)
			return
		}

		rows := make([]adminDBTableRow, 0, 64)
		if err := db.WithContext(ctx).Raw(`
			SELECT
			    n.nspname                                         AS schema,
			    c.relname                                         AS name,
			    pg_total_relation_size(c.oid)::bigint             AS total_bytes,
			    pg_relation_size(c.oid)::bigint                   AS table_bytes,
			    pg_indexes_size(c.oid)::bigint                    AS indexes_bytes,
			    (pg_total_relation_size(c.oid)
			        - pg_relation_size(c.oid)
			        - pg_indexes_size(c.oid))::bigint             AS toast_bytes,
			    COALESCE(s.n_live_tup, 0)::bigint                 AS live_rows,
			    COALESCE(s.n_dead_tup, 0)::bigint                 AS dead_rows,
			    s.last_vacuum                                     AS last_vacuum,
			    s.last_autovacuum                                 AS last_auto_vacuum,
			    s.last_analyze                                    AS last_analyze,
			    s.last_autoanalyze                                AS last_auto_analyze,
			    COALESCE(s.seq_scan, 0)::bigint                   AS seq_scan,
			    COALESCE(s.idx_scan, 0)::bigint                   AS idx_scan
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_stat_user_tables s
			    ON s.schemaname = n.nspname AND s.relname = c.relname
			WHERE c.relkind IN ('r', 'p')
			  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			  AND n.nspname NOT LIKE 'pg_toast%'
			ORDER BY pg_total_relation_size(c.oid) DESC
		`).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load table sizes", http.StatusInternalServerError)
			return
		}

		var totalTableBytes int64
		for i := range rows {
			totalTableBytes += rows[i].TotalBytes
			if rows[i].LiveRows+rows[i].DeadRows > 0 {
				rows[i].DeadRatio = float64(rows[i].DeadRows) /
					float64(rows[i].LiveRows+rows[i].DeadRows)
			}
		}

		writeJSON(w, http.StatusOK, adminDBStorageResponse{
			FetchedAt:       time.Now(),
			Database:        dbInfo.Name,
			DatabaseBytes:   dbInfo.Bytes,
			TableCount:      len(rows),
			TotalTableBytes: totalTableBytes,
			Tables:          rows,
		})
	}
}

// AdminDBMaintenanceHandler — POST /api/admin/db/maintenance
//
// Enqueues a DB_MAINTENANCE job (ANALYZE or VACUUM ANALYZE) for a single
// table. Validates the schema+table+operation here so a bad request fails
// fast with 400 instead of becoming a FAILED job an operator has to find
// in /admin/jobs.
//
// We block on an existing QUEUED/RUNNING/RETRY job for the same table so
// double-clicks don't stack three VACUUMs in the queue.
func AdminDBMaintenanceHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	type request struct {
		Schema    string `json:"schema"`
		Table     string `json:"table"`
		Operation string `json:"operation"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		body.Schema = strings.TrimSpace(body.Schema)
		body.Table = strings.TrimSpace(body.Table)
		body.Operation = strings.TrimSpace(body.Operation)
		if body.Schema == "" || body.Table == "" {
			http.Error(w, "schema and table required", http.StatusBadRequest)
			return
		}

		var op jobs.DBMaintenanceOp
		switch jobs.DBMaintenanceOp(body.Operation) {
		case jobs.DBMaintenanceOpAnalyze, jobs.DBMaintenanceOpVacuumAnalyze:
			op = jobs.DBMaintenanceOp(body.Operation)
		default:
			http.Error(w, "operation must be 'analyze' or 'vacuum_analyze'", http.StatusBadRequest)
			return
		}

		// Confirm the table exists before we even enqueue — saves a
		// failed job row for a typo.
		var exists bool
		if err := db.WithContext(r.Context()).Raw(`
			SELECT EXISTS (
				SELECT 1
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				WHERE c.relkind IN ('r', 'p')
				  AND n.nspname = ?
				  AND c.relname = ?
			)
		`, body.Schema, body.Table).Scan(&exists).Error; err != nil {
			http.Error(w, "validate table failed", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "table not found", http.StatusNotFound)
			return
		}

		// Block stacked re-clicks. We match on schema + table inside
		// payload via JSON ops so two different tables can run in
		// parallel but the same table can't double-queue.
		var active int64
		db.WithContext(r.Context()).Model(&jobs.Job{}).
			Where("type = ? AND status IN ?", jobs.JobTypeDBMaintenance,
				[]jobs.JobStatus{jobs.JobStatusQueued, jobs.JobStatusRunning, jobs.JobStatusRetry}).
			Where("payload->>'schema' = ? AND payload->>'table' = ?", body.Schema, body.Table).
			Count(&active)
		if active > 0 {
			http.Error(w, "maintenance already queued or running for this table", http.StatusConflict)
			return
		}

		job, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
			Type: jobs.JobTypeDBMaintenance,
			Payload: jobs.DBMaintenancePayload{
				Schema:    body.Schema,
				Table:     body.Table,
				Operation: op,
			},
			MaxAttempts: 1, // operator-triggered; don't retry on its own
		})
		if err != nil {
			http.Error(w, "failed to enqueue: "+err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusAccepted, map[string]string{
			"job_id":    job.ID,
			"status":    string(job.Status),
			"schema":    body.Schema,
			"table":     body.Table,
			"operation": body.Operation,
		})
	}
}

// AdminDBMaintenanceAllHandler — POST /api/admin/db/maintenance/all
//
// Fans out one DB_MAINTENANCE job per user table. Skips tables with
// zero live tuples (ANALYZE on an empty table is wasted queue work).
// Honours the existing per-table dedupe inside CreateJob's payload
// match? No — CreateJob doesn't dedupe; the per-table block in
// AdminDBMaintenanceHandler does. We replicate that block here so a
// table already mid-maintenance doesn't double-queue.
func AdminDBMaintenanceAllHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	type request struct {
		Operation string `json:"operation"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var body request
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		body.Operation = strings.TrimSpace(body.Operation)
		var op jobs.DBMaintenanceOp
		switch jobs.DBMaintenanceOp(body.Operation) {
		case jobs.DBMaintenanceOpAnalyze, jobs.DBMaintenanceOpVacuumAnalyze:
			op = jobs.DBMaintenanceOp(body.Operation)
		default:
			http.Error(w, "operation must be 'analyze' or 'vacuum_analyze'", http.StatusBadRequest)
			return
		}

		// Enumerate user tables with at least one live row, skipping
		// system schemas. n_live_tup comes from pg_stat_user_tables;
		// freshly-created tables that have never been analyzed report
		// 0, so we OR in a fallback on pg_class.reltuples (planner's
		// estimate) to avoid silently skipping new tables.
		type tableRef struct {
			Schema string `gorm:"column:schema"`
			Name   string `gorm:"column:name"`
		}
		var tables []tableRef
		if err := db.WithContext(r.Context()).Raw(`
			SELECT n.nspname AS schema, c.relname AS name
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_stat_user_tables s
			    ON s.schemaname = n.nspname AND s.relname = c.relname
			WHERE c.relkind IN ('r', 'p')
			  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			  AND n.nspname NOT LIKE 'pg_toast%'
			  AND (COALESCE(s.n_live_tup, 0) > 0 OR c.reltuples > 0)
			ORDER BY n.nspname, c.relname
		`).Scan(&tables).Error; err != nil {
			http.Error(w, "failed to enumerate tables", http.StatusInternalServerError)
			return
		}

		// Pre-load the in-flight set so we skip tables already running
		// or queued without N round-trips to CreateJob.
		type inflightRow struct {
			Schema string `gorm:"column:schema"`
			Name   string `gorm:"column:name"`
		}
		var inflight []inflightRow
		db.WithContext(r.Context()).Raw(`
			SELECT payload->>'schema' AS schema, payload->>'table' AS name
			FROM jobs
			WHERE type = ?
			  AND status IN (?, ?, ?)
		`, jobs.JobTypeDBMaintenance,
			jobs.JobStatusQueued, jobs.JobStatusRunning, jobs.JobStatusRetry,
		).Scan(&inflight)
		inflightSet := make(map[string]struct{}, len(inflight))
		for _, row := range inflight {
			inflightSet[row.Schema+"."+row.Name] = struct{}{}
		}

		enqueued := 0
		skipped := 0
		for _, t := range tables {
			if _, busy := inflightSet[t.Schema+"."+t.Name]; busy {
				skipped++
				continue
			}
			_, err := jobs.CreateJob(r.Context(), db, jobs.CreateJobInput{
				Type: jobs.JobTypeDBMaintenance,
				Payload: jobs.DBMaintenancePayload{
					Schema:    t.Schema,
					Table:     t.Name,
					Operation: op,
				},
				MaxAttempts: 1,
			})
			if err != nil {
				skipped++
				continue
			}
			enqueued++
		}

		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"operation":     body.Operation,
			"enqueued":      enqueued,
			"skipped":       skipped,
			"total_tables":  len(tables),
		})
	}
}

type adminDBMaintenanceJob struct {
	JobID      string      `json:"job_id"`
	Status     string      `json:"status"`
	Schema     string      `json:"schema"`
	Table      string      `json:"table"`
	Operation  string      `json:"operation"`
	CreatedAt  time.Time   `json:"created_at"`
	FinishedAt *time.Time  `json:"finished_at,omitempty"`
	Error      string      `json:"error,omitempty"`
	Result     interface{} `json:"result,omitempty"`
}

// AdminDBMaintenanceRecentHandler — GET /api/admin/db/maintenance/recent
//
// Returns the last 50 DB_MAINTENANCE jobs across all tables so the UI
// can render per-row state (running / queued / last-completed) without
// polling 100+ per-table endpoints. 50 is enough to cover a normal-size
// schema; if you have more, the rest is in /admin/jobs.
func AdminDBMaintenanceRecentHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var rows []jobs.Job
		if err := db.WithContext(r.Context()).
			Where("type = ?", jobs.JobTypeDBMaintenance).
			Order("created_at DESC").
			Limit(50).
			Find(&rows).Error; err != nil {
			http.Error(w, "failed to load maintenance history", http.StatusInternalServerError)
			return
		}

		out := make([]adminDBMaintenanceJob, 0, len(rows))
		for _, j := range rows {
			entry := adminDBMaintenanceJob{
				JobID:     j.ID,
				Status:    string(j.Status),
				CreatedAt: j.CreatedAt,
				Error:     j.Error,
			}
			if j.FinishedAt != nil {
				ts := *j.FinishedAt
				entry.FinishedAt = &ts
			}
			if len(j.Payload) > 0 {
				var p jobs.DBMaintenancePayload
				if err := json.Unmarshal(j.Payload, &p); err == nil {
					entry.Schema = p.Schema
					entry.Table = p.Table
					entry.Operation = string(p.Operation)
				}
			}
			if len(j.Result) > 0 {
				var result interface{}
				if err := json.Unmarshal(j.Result, &result); err == nil {
					entry.Result = result
				}
			}
			out = append(out, entry)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"jobs": out,
		})
	}
}
