package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config captures the runtime configuration required by the API server.
type Config struct {
	HTTPPort    string
	DatabaseURL string
}

// Load reads configuration values from the environment.
//
// Priority order for database configuration:
//  1. DATABASE_URL environment variable as a full DSN.
//  2. Individual PG* environment variables which are composed into a DSN.
func Load() (Config, error) {
	cfg := Config{
		HTTPPort:    getEnv("HTTP_PORT", "8080"),
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
	}

	if cfg.DatabaseURL == "" {
		dsn, err := buildDSNFromPGEnv()
		if err != nil {
			return Config{}, err
		}
		cfg.DatabaseURL = dsn
	}

	if cfg.HTTPPort == "" {
		return Config{}, errors.New("HTTP_PORT must not be empty")
	}

	return cfg, nil
}

func buildDSNFromPGEnv() (string, error) {
	host := strings.TrimSpace(os.Getenv("PGHOST"))
	user := strings.TrimSpace(os.Getenv("PGUSER"))
	name := strings.TrimSpace(os.Getenv("PGDATABASE"))

	if host == "" || user == "" || name == "" {
		return "", errors.New("database configuration missing: set DATABASE_URL or PGHOST, PGUSER, and PGDATABASE")
	}

	port := getEnv("PGPORT", "5432")
	password := strings.TrimSpace(os.Getenv("PGPASSWORD"))
	sslMode := getEnv("PGSSLMODE", "disable")
	timeZone := getEnv("PGTZ", "UTC")

	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		host, port, user, password, name, sslMode, timeZone,
	), nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
