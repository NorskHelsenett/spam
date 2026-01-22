package db

import (
	"context"
	"errors"
	"fmt"
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

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetConnMaxLifetime(time.Hour)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
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
