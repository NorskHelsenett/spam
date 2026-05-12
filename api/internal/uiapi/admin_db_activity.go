package uiapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/auth"
	"gorm.io/gorm"
)

// Database activity / diagnostics endpoints. Read-only views over
// pg_stat_database, pg_stat_activity, and (when installed) the
// pg_stat_statements extension. Together they answer "is the DB
// healthy right now, what's running, and which queries are slow?"
// without operators having to drop into psql.
//
// Note on what PostgreSQL does NOT aggregate in pg_catalog:
//   - statement_timeout cancellations (live in the server log)
//   - per-query error counts (the log again)
// What we surface instead: deadlocks, conflicts, temp-spill bytes
// (a strong slow-query proxy), checksum failures, and the live
// pg_stat_activity feed where stuck/long queries are visible
// before they hit a timeout.

type adminDBActivityResponse struct {
	FetchedAt          time.Time  `json:"fetched_at"`
	Database           string     `json:"database"`
	NumBackends        int64      `json:"num_backends"`
	XactCommit         int64      `json:"xact_commit"`
	XactRollback       int64      `json:"xact_rollback"`
	BlksRead           int64      `json:"blks_read"`
	BlksHit            int64      `json:"blks_hit"`
	CacheHitRatio      float64    `json:"cache_hit_ratio"`
	TupReturned        int64      `json:"tup_returned"`
	TupFetched         int64      `json:"tup_fetched"`
	TupInserted        int64      `json:"tup_inserted"`
	TupUpdated         int64      `json:"tup_updated"`
	TupDeleted         int64      `json:"tup_deleted"`
	Conflicts          int64      `json:"conflicts"`
	TempFiles          int64      `json:"temp_files"`
	TempBytes          int64      `json:"temp_bytes"`
	Deadlocks          int64      `json:"deadlocks"`
	ChecksumFailures   int64      `json:"checksum_failures"`
	StatsReset         *time.Time `json:"stats_reset,omitempty"`
}

// AdminDBActivityHandler — GET /api/admin/db/activity
//
// Single-row read of pg_stat_database for current_database(). Computes
// cache_hit_ratio inline (blks_hit / (blks_hit + blks_read)) so the UI
// doesn't have to do float math on potentially-huge bigints.
func AdminDBActivityHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		var row struct {
			Datname          string     `gorm:"column:datname"`
			NumBackends      int64      `gorm:"column:numbackends"`
			XactCommit       int64      `gorm:"column:xact_commit"`
			XactRollback     int64      `gorm:"column:xact_rollback"`
			BlksRead         int64      `gorm:"column:blks_read"`
			BlksHit          int64      `gorm:"column:blks_hit"`
			TupReturned      int64      `gorm:"column:tup_returned"`
			TupFetched       int64      `gorm:"column:tup_fetched"`
			TupInserted      int64      `gorm:"column:tup_inserted"`
			TupUpdated       int64      `gorm:"column:tup_updated"`
			TupDeleted       int64      `gorm:"column:tup_deleted"`
			Conflicts        int64      `gorm:"column:conflicts"`
			TempFiles        int64      `gorm:"column:temp_files"`
			TempBytes        int64      `gorm:"column:temp_bytes"`
			Deadlocks        int64      `gorm:"column:deadlocks"`
			ChecksumFailures int64      `gorm:"column:checksum_failures"`
			StatsReset       *time.Time `gorm:"column:stats_reset"`
		}
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
			    datname,
			    numbackends::bigint,
			    xact_commit::bigint,
			    xact_rollback::bigint,
			    blks_read::bigint,
			    blks_hit::bigint,
			    tup_returned::bigint,
			    tup_fetched::bigint,
			    tup_inserted::bigint,
			    tup_updated::bigint,
			    tup_deleted::bigint,
			    conflicts::bigint,
			    temp_files::bigint,
			    temp_bytes::bigint,
			    deadlocks::bigint,
			    COALESCE(checksum_failures, 0)::bigint AS checksum_failures,
			    stats_reset
			FROM pg_stat_database
			WHERE datname = current_database()
		`).Scan(&row).Error; err != nil {
			http.Error(w, "failed to load activity stats", http.StatusInternalServerError)
			return
		}

		var hitRatio float64
		if denom := row.BlksHit + row.BlksRead; denom > 0 {
			hitRatio = float64(row.BlksHit) / float64(denom)
		}

		writeJSON(w, http.StatusOK, adminDBActivityResponse{
			FetchedAt:        time.Now(),
			Database:         row.Datname,
			NumBackends:      row.NumBackends,
			XactCommit:       row.XactCommit,
			XactRollback:     row.XactRollback,
			BlksRead:         row.BlksRead,
			BlksHit:          row.BlksHit,
			CacheHitRatio:    hitRatio,
			TupReturned:      row.TupReturned,
			TupFetched:       row.TupFetched,
			TupInserted:      row.TupInserted,
			TupUpdated:       row.TupUpdated,
			TupDeleted:       row.TupDeleted,
			Conflicts:        row.Conflicts,
			TempFiles:        row.TempFiles,
			TempBytes:        row.TempBytes,
			Deadlocks:        row.Deadlocks,
			ChecksumFailures: row.ChecksumFailures,
			StatsReset:       row.StatsReset,
		})
	}
}

type adminDBLiveQuery struct {
	PID             int        `json:"pid"`
	Username        string     `json:"username,omitempty"`
	ApplicationName string     `json:"application_name,omitempty"`
	ClientAddr      string     `json:"client_addr,omitempty"`
	State           string     `json:"state,omitempty"`
	WaitEventType   string     `json:"wait_event_type,omitempty"`
	WaitEvent       string     `json:"wait_event,omitempty"`
	QueryStart      *time.Time `json:"query_start,omitempty"`
	StateChange     *time.Time `json:"state_change,omitempty"`
	DurationSeconds int        `json:"duration_seconds"`
	Query           string     `json:"query,omitempty"`
}

// AdminDBLiveQueriesHandler — GET /api/admin/db/live-queries
//
// Returns the currently-non-idle backends in this database. Filters
// out our own connection so the panel doesn't show itself. Idle-in-
// transaction is included because it's a connection-leak smell worth
// surfacing — long IIT sessions hold row locks and block VACUUM.
func AdminDBLiveQueriesHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}

		type row struct {
			PID             int        `gorm:"column:pid"`
			Username        string     `gorm:"column:username"`
			ApplicationName string     `gorm:"column:application_name"`
			ClientAddr      *string    `gorm:"column:client_addr"`
			State           string     `gorm:"column:state"`
			WaitEventType   *string    `gorm:"column:wait_event_type"`
			WaitEvent       *string    `gorm:"column:wait_event"`
			QueryStart      *time.Time `gorm:"column:query_start"`
			StateChange     *time.Time `gorm:"column:state_change"`
			Query           string     `gorm:"column:query"`
		}
		var rows []row
		if err := db.WithContext(r.Context()).Raw(`
			SELECT
			    pid,
			    usename                  AS username,
			    application_name,
			    host(client_addr)::text  AS client_addr,
			    state,
			    wait_event_type,
			    wait_event,
			    query_start,
			    state_change,
			    query
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND pid <> pg_backend_pid()
			  AND state IS NOT NULL
			  AND state <> 'idle'
			ORDER BY query_start ASC NULLS LAST
			LIMIT 100
		`).Scan(&rows).Error; err != nil {
			http.Error(w, "failed to load live queries", http.StatusInternalServerError)
			return
		}

		now := time.Now()
		out := make([]adminDBLiveQuery, 0, len(rows))
		for _, r := range rows {
			entry := adminDBLiveQuery{
				PID:             r.PID,
				Username:        r.Username,
				ApplicationName: r.ApplicationName,
				State:           r.State,
				QueryStart:      r.QueryStart,
				StateChange:     r.StateChange,
				Query:           r.Query,
			}
			if r.ClientAddr != nil {
				entry.ClientAddr = *r.ClientAddr
			}
			if r.WaitEventType != nil {
				entry.WaitEventType = *r.WaitEventType
			}
			if r.WaitEvent != nil {
				entry.WaitEvent = *r.WaitEvent
			}
			anchor := r.QueryStart
			if anchor == nil {
				anchor = r.StateChange
			}
			if anchor != nil {
				if d := now.Sub(*anchor).Seconds(); d > 0 {
					entry.DurationSeconds = int(d)
				}
			}
			out = append(out, entry)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"queries": out,
		})
	}
}

type adminDBSlowQuery struct {
	QueryID     string  `json:"query_id"`
	Query       string  `json:"query"`
	Calls       int64   `json:"calls"`
	TotalMS     float64 `json:"total_ms"`
	MeanMS      float64 `json:"mean_ms"`
	MaxMS       float64 `json:"max_ms,omitempty"`
	Rows        int64   `json:"rows"`
	BlksHit     int64   `json:"shared_blks_hit"`
	BlksRead    int64   `json:"shared_blks_read"`
}

type adminDBSlowQueriesResponse struct {
	Installed     bool               `json:"installed"`
	HowToInstall  string             `json:"how_to_install,omitempty"`
	TopByTotal    []adminDBSlowQuery `json:"top_by_total,omitempty"`
	TopByMean     []adminDBSlowQuery `json:"top_by_mean,omitempty"`
}

// AdminDBSlowQueriesHandler — GET /api/admin/db/slow-queries
//
// Returns top 10 queries by total time and by mean time from
// pg_stat_statements. The extension is the single best signal for
// "which queries are eating the DB" — without it, we can only see
// current activity, not the cumulative pattern.
//
// We detect whether pg_stat_statements is installed by checking
// pg_extension; if missing, we return a structured "not installed"
// response with the SQL to enable it, so the UI can guide the
// operator without exploding with a 500.
//
// Column naming changed between PG 12 and 13 (total_time -> total_exec_time,
// mean_time -> mean_exec_time). We prefer the new names and fall back
// to the old ones if the new query fails.
func AdminDBSlowQueriesHandler(db *gorm.DB, authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if requireAdmin(w, r, authService) == nil {
			return
		}
		ctx := r.Context()

		var installed bool
		if err := db.WithContext(ctx).Raw(`
			SELECT EXISTS (
				SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
			)
		`).Scan(&installed).Error; err != nil {
			http.Error(w, "failed to probe extension", http.StatusInternalServerError)
			return
		}
		if !installed {
			writeJSON(w, http.StatusOK, adminDBSlowQueriesResponse{
				Installed: false,
				HowToInstall: strings.TrimSpace(`
shared_preload_libraries = 'pg_stat_statements'   -- postgresql.conf, then restart
CREATE EXTENSION pg_stat_statements;              -- as superuser, in this DB`),
			})
			return
		}

		// PG 13+ exposes total_exec_time / mean_exec_time. Older clusters
		// (12 and below) use total_time / mean_time. Try modern first.
		queryModern := `
			SELECT
			    queryid::text       AS query_id,
			    query,
			    calls,
			    total_exec_time     AS total_ms,
			    mean_exec_time      AS mean_ms,
			    max_exec_time       AS max_ms,
			    rows,
			    shared_blks_hit,
			    shared_blks_read
			FROM pg_stat_statements
			WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
			ORDER BY %s DESC
			LIMIT 10
		`
		queryLegacy := `
			SELECT
			    queryid::text       AS query_id,
			    query,
			    calls,
			    total_time          AS total_ms,
			    mean_time           AS mean_ms,
			    0::float8           AS max_ms,
			    rows,
			    shared_blks_hit,
			    shared_blks_read
			FROM pg_stat_statements
			WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
			ORDER BY %s DESC
			LIMIT 10
		`

		fetch := func(orderCol string) ([]adminDBSlowQuery, error) {
			var rows []adminDBSlowQuery
			modernCol := map[string]string{"total": "total_exec_time", "mean": "mean_exec_time"}[orderCol]
			err := db.WithContext(ctx).Raw(strings.Replace(queryModern, "%s", modernCol, 1)).Scan(&rows).Error
			if err != nil {
				legacyCol := map[string]string{"total": "total_time", "mean": "mean_time"}[orderCol]
				rows = nil
				err = db.WithContext(ctx).Raw(strings.Replace(queryLegacy, "%s", legacyCol, 1)).Scan(&rows).Error
			}
			return rows, err
		}

		byTotal, err := fetch("total")
		if err != nil {
			http.Error(w, "failed to load slow queries", http.StatusInternalServerError)
			return
		}
		byMean, err := fetch("mean")
		if err != nil {
			http.Error(w, "failed to load slow queries", http.StatusInternalServerError)
			return
		}

		writeJSON(w, http.StatusOK, adminDBSlowQueriesResponse{
			Installed:  true,
			TopByTotal: byTotal,
			TopByMean:  byMean,
		})
	}
}
