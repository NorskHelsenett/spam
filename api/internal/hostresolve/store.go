package hostresolve

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// workItem is one row the worker needs to refresh: a host present in
// host_exposure plus the LB-IP fallback the resolver should use when
// public DNS comes back empty.
type workItem struct {
	Host  string `gorm:"column:host"`
	LBIPs string `gorm:"column:lb_ips"`
}

// listWork returns hosts that either have no host_resolution row yet OR
// whose row is older than staleAfter. One LB IP per host (MIN keeps the
// pick deterministic even when the same host appears across multiple
// clusters/namespaces with conflicting LBs — the inline-resolve path
// previously did the same first-non-empty pick).
//
// The LIMIT is a soft cap on a single worker pass so we don't try to
// resolve a fleet's worth of new hosts in one go after a cold start.
// The worker re-enters on a tick anyway.
func listWork(ctx context.Context, db *gorm.DB, staleAfter time.Duration, limit int) ([]workItem, error) {
	var rows []workItem
	err := db.WithContext(ctx).Raw(`
		WITH known AS (
			SELECT he.host, MIN(NULLIF(he.lb_ips, '')) AS lb_ips
			FROM host_exposure he
			WHERE he.host <> ''
			GROUP BY he.host
		)
		SELECT k.host, COALESCE(k.lb_ips, '') AS lb_ips
		FROM known k
		LEFT JOIN host_resolution hr ON hr.host = k.host
		WHERE hr.host IS NULL
		   OR hr.resolved_at < NOW() - make_interval(secs => ?)
		ORDER BY hr.resolved_at NULLS FIRST
		LIMIT ?
	`, int(staleAfter.Seconds()), limit).Scan(&rows).Error
	return rows, err
}

// upsert writes a single resolved row, bumping resolved_at on conflict
// so the next listWork pass skips it until staleAfter elapses. ips is
// the split-horizon answer, public_ips the DoH answer that (when
// host-specific) drives the classification — stored so "why is this
// external?" is answerable from the row itself.
func upsert(ctx context.Context, db *gorm.DB, host, classification, ips, publicIPs string, wildcard bool, lbIPs string) error {
	return db.WithContext(ctx).Exec(`
		INSERT INTO host_resolution (host, classification, ips, public_ips, wildcard, lb_ips, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, NOW())
		ON CONFLICT (host) DO UPDATE
		   SET classification = EXCLUDED.classification,
		       ips            = EXCLUDED.ips,
		       public_ips     = EXCLUDED.public_ips,
		       wildcard       = EXCLUDED.wildcard,
		       lb_ips          = EXCLUDED.lb_ips,
		       resolved_at    = NOW()
	`, host, classification, ips, publicIPs, wildcard, lbIPs).Error
}
