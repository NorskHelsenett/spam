package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config holds the data required to open a database connection.
type Config struct {
	DSN string
}

// Open establishes a GORM connection to PostgreSQL using the provided configuration.
func Open(ctx context.Context, cfg Config) (*gorm.DB, error) {
	if strings.TrimSpace(cfg.DSN) == "" {
		return nil, errors.New("database DSN must not be empty")
	}

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	db, err := gorm.Open(postgres.Open(cfg.DSN), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database handle: %w", err)
	}

	sqlDB.SetMaxIdleConns(envInt("SPAM_DB_MAX_IDLE_CONNS", 25))
	sqlDB.SetMaxOpenConns(envInt("SPAM_DB_MAX_OPEN_CONNS", 50))
	sqlDB.SetConnMaxLifetime(time.Hour)
	// Recycle idle connections well before any server-side or network
	// idle timeout closes them under us mid-request.
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}

// envInt reads a positive integer from the environment, falling back
// to def when unset or invalid.
func envInt(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		log.Printf("db: ignoring invalid %s %q, using %d", name, raw, def)
		return def
	}
	return n
}

// Close releases the underlying SQL database resources.
func Close(gormDB *gorm.DB) error {
	if gormDB == nil {
		return nil
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		return fmt.Errorf("retrieve sql.DB: %w", err)
	}

	return sqlDB.Close()
}
