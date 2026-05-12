package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// processDBMaintenance executes a narrow set of Postgres maintenance
// commands (ANALYZE, VACUUM ANALYZE) on a single named table.
//
// Safety:
//   - Operation is whitelisted to the DBMaintenanceOp constants.
//   - Schema + table are re-validated against pg_catalog inside this
//     handler before the statement is built. That re-check is the only
//     thing standing between the caller and arbitrary SQL via the
//     identifier slot, since PostgreSQL placeholders ($1, $2) bind
//     values — never identifiers. Even with quoting, we never trust
//     an unverified pair.
//   - VACUUM cannot run inside a transaction; GORM's Exec uses
//     ExecContext directly on the connection (no implicit BEGIN), so
//     this is fine. We do NOT wrap in db.Transaction().
//   - Result captures the duration so the UI can show "ran in 12.3s"
//     without having to subtract timestamps on the client.
func processDBMaintenance(ctx context.Context, db *gorm.DB, job *Job) (interface{}, error) {
	if len(job.Payload) == 0 {
		return nil, NonRetryable(errors.New("DB_MAINTENANCE missing payload"))
	}
	var payload DBMaintenancePayload
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, NonRetryable(fmt.Errorf("invalid DB_MAINTENANCE payload: %w", err))
	}

	stmtPrefix, ok := maintenanceStatement(payload.Operation)
	if !ok {
		return nil, NonRetryable(fmt.Errorf("unsupported db maintenance operation: %q", payload.Operation))
	}

	schema := strings.TrimSpace(payload.Schema)
	table := strings.TrimSpace(payload.Table)
	if schema == "" || table == "" {
		return nil, NonRetryable(errors.New("DB_MAINTENANCE payload missing schema or table"))
	}

	// Re-validate against pg_catalog using bound parameters. If the
	// pair doesn't resolve to a real ordinary/partitioned table, refuse
	// to run — this is the gate that lets us interpolate the
	// identifier without arming a SQL-injection foot-gun.
	var exists bool
	if err := db.WithContext(ctx).Raw(`
		SELECT EXISTS (
			SELECT 1
			FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'p')
			  AND n.nspname = ?
			  AND c.relname = ?
		)
	`, schema, table).Scan(&exists).Error; err != nil {
		return nil, fmt.Errorf("validate table: %w", err)
	}
	if !exists {
		return nil, NonRetryable(fmt.Errorf("table not found: %s.%s", schema, table))
	}

	stmt := fmt.Sprintf(`%s %s.%s`, stmtPrefix, quoteIdent(schema), quoteIdent(table))

	start := time.Now()
	if err := db.WithContext(ctx).Exec(stmt).Error; err != nil {
		return nil, fmt.Errorf("run %s: %w", stmtPrefix, err)
	}
	duration := time.Since(start)

	return map[string]any{
		"status":        "ok",
		"operation":     string(payload.Operation),
		"schema":        schema,
		"table":         table,
		"duration_ms":   duration.Milliseconds(),
		"completed_at":  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// maintenanceStatement maps a DBMaintenanceOp to the SQL prefix it
// runs. Returning a static string per op (rather than building from
// the enum) keeps the prefix off any caller-controlled path.
func maintenanceStatement(op DBMaintenanceOp) (string, bool) {
	switch op {
	case DBMaintenanceOpAnalyze:
		return "ANALYZE", true
	case DBMaintenanceOpVacuumAnalyze:
		return "VACUUM (ANALYZE)", true
	default:
		return "", false
	}
}

// quoteIdent wraps a PostgreSQL identifier in double quotes and
// escapes any embedded double quotes by doubling them, matching the
// behaviour of pq.QuoteIdentifier without pulling the dependency in.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
