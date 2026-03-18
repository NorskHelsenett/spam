package cache

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

// kvEntry is the GORM model for the kv_store unlogged table.
type kvEntry struct {
	Key       string     `gorm:"primaryKey"`
	Value     []byte     `gorm:"type:jsonb;not null"`
	ExpiresAt *time.Time `gorm:"index"`
	UpdatedAt time.Time
}

func (kvEntry) TableName() string { return "kv_store" }

// PostgresStore implements Store using an UNLOGGED PostgreSQL table.
// UNLOGGED skips WAL so writes are fast; data survives clean restarts but is
// cleared on crash — acceptable for cache and ephemeral session data.
// Expired entries are evicted lazily on Get and periodically via Evict.
type PostgresStore struct {
	db *gorm.DB
}

// NewPostgresStore returns a PostgresStore. Call EnsureTable once at startup
// to create the unlogged table and indexes.
func NewPostgresStore(db *gorm.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// EnsureTable creates the kv_store unlogged table if it does not exist.
func EnsureTable(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).Exec(`
		CREATE UNLOGGED TABLE IF NOT EXISTS kv_store (
			key        TEXT        PRIMARY KEY,
			value      JSONB       NOT NULL,
			expires_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE INDEX IF NOT EXISTS idx_kv_store_expires
			ON kv_store (expires_at)
			WHERE expires_at IS NOT NULL;
	`).Error
}

func (p *PostgresStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var entry kvEntry
	err := p.db.WithContext(ctx).
		Where("key = ? AND (expires_at IS NULL OR expires_at > now())", key).
		First(&entry).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return entry.Value, true, nil
}

func (p *PostgresStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	var expiresAt *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expiresAt = &t
	}
	return p.db.WithContext(ctx).Exec(`
		INSERT INTO kv_store (key, value, expires_at, updated_at)
		VALUES (?, ?, ?, now())
		ON CONFLICT (key) DO UPDATE
			SET value      = EXCLUDED.value,
			    expires_at = EXCLUDED.expires_at,
			    updated_at = now()
	`, key, value, expiresAt).Error
}

func (p *PostgresStore) Delete(ctx context.Context, key string) error {
	return p.db.WithContext(ctx).Exec("DELETE FROM kv_store WHERE key = ?", key).Error
}

func (p *PostgresStore) DeleteByPrefix(ctx context.Context, prefix string) error {
	return p.db.WithContext(ctx).Exec("DELETE FROM kv_store WHERE key LIKE ?", prefix+"%").Error
}

// Evict deletes all expired entries. Call this periodically (e.g. once per hour
// from a background goroutine or a worker job) to reclaim space.
func (p *PostgresStore) Evict(ctx context.Context) (int64, error) {
	tx := p.db.WithContext(ctx).Exec("DELETE FROM kv_store WHERE expires_at IS NOT NULL AND expires_at <= now()")
	return tx.RowsAffected, tx.Error
}
