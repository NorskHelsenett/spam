package imagescan

import (
	"context"
	"time"
)

// ScannerControllerLease is the single-row leader election table for the
// scanner operator. Only one worker replica holds the lease at a time;
// the holder tick spawns pods, the other replica sits idle on this loop
// but still serves job-poller traffic and HMAC endpoints.
//
// The lease is cheap to renew (one UPDATE per tick) and self-healing:
// when the holder crashes, expires_at passes and any other replica's
// next tick takes over. TTL is intentionally short (30s) so failover
// latency stays under a minute.
type ScannerControllerLease struct {
	ID         string    `gorm:"primaryKey;size:32"` // always "singleton"
	HolderID   string    `gorm:"size:128;not null"`
	AcquiredAt time.Time `gorm:"not null"`
	ExpiresAt  time.Time `gorm:"not null;index"`
}

func (ScannerControllerLease) TableName() string { return "scanner_controller_lease" }

const (
	leaseTTL       = 30 * time.Second
	leaseTableName = "scanner_controller_lease"
)

// acquireLease atomically claims or renews the singleton lease. Returns
// true when this worker is the leader after the UPDATE. The predicate
// `holder_id = ? OR expires_at < NOW()` means the current holder keeps
// its grip on renewal; any other worker only takes over after the TTL
// has passed.
//
// Uses an INSERT ... ON CONFLICT dance so the first worker to run
// creates the row without a migration prerequisite beyond the table
// itself (AutoMigrate creates the struct; the row is lazily bootstrapped
// on first acquire). Keeps schema management in one place.
func (o *Operator) acquireLease(ctx context.Context) (bool, error) {
	// Bootstrap the row if missing. ON CONFLICT DO NOTHING so the
	// second+ caller is cheap.
	if err := o.db.WithContext(ctx).Exec(`
		INSERT INTO `+leaseTableName+` (id, holder_id, acquired_at, expires_at)
		VALUES ('singleton', '', NOW(), NOW())
		ON CONFLICT (id) DO NOTHING
	`).Error; err != nil {
		return false, err
	}

	// Atomic take-or-renew.
	result := o.db.WithContext(ctx).Exec(`
		UPDATE `+leaseTableName+`
		SET holder_id = ?,
		    acquired_at = NOW(),
		    expires_at  = NOW() + make_interval(secs => ?)
		WHERE id = 'singleton'
		  AND (holder_id = ? OR expires_at < NOW())
	`, o.holderID, leaseTTL.Seconds(), o.holderID)
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected == 1, nil
}

// releaseLease is called on graceful shutdown so failover happens
// immediately instead of waiting out the TTL. Best-effort — errors are
// swallowed because we're tearing down anyway.
func (o *Operator) releaseLease(ctx context.Context) {
	if o == nil {
		return
	}
	_ = o.db.WithContext(ctx).Exec(`
		UPDATE `+leaseTableName+`
		SET expires_at = NOW()
		WHERE id = 'singleton' AND holder_id = ?
	`, o.holderID).Error
}
