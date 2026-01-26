package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config captures the runtime configuration required by the API server.
type Config struct {
	HTTPPort    string
	DatabaseURL string
	OIDC        OIDCConfig
}

// OIDCConfig captures configuration for the OIDC login flow and session cookies.
type OIDCConfig struct {
	IssuerURL         string
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	Scopes            []string
	SessionCookieName string
	AuthCookieName    string
	SessionTTL        time.Duration
	CookieHashKey     []byte
	CookieBlockKey    []byte
	CookieSecure      bool
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

	oidcCfg, err := loadOIDCConfig()
	if err != nil {
		return Config{}, err
	}
	cfg.OIDC = oidcCfg

	return cfg, nil
}

// WorkerConfig captures configuration for the background worker.
type WorkerConfig struct {
	DatabaseURL string
	Concurrency int // Number of concurrent job processors
}

// LoadWorker reads configuration for the worker process.
// Only requires database connection - no OIDC or HTTP config needed.
func LoadWorker() (WorkerConfig, error) {
	cfg := WorkerConfig{
		DatabaseURL: strings.TrimSpace(os.Getenv("DATABASE_URL")),
		Concurrency: parseIntEnv("WORKER_CONCURRENCY", 4),
	}

	if cfg.DatabaseURL == "" {
		dsn, err := buildDSNFromPGEnv()
		if err != nil {
			return WorkerConfig{}, err
		}
		cfg.DatabaseURL = dsn
	}

	// Ensure concurrency is at least 1
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}

	return cfg, nil
}

func buildDSNFromPGEnv() (string, error) {
	host := strings.TrimSpace(os.Getenv("POSTGRES_HOST"))
	user := strings.TrimSpace(os.Getenv("POSTGRES_USER"))
	name := strings.TrimSpace(os.Getenv("POSTGRES_DB"))

	if host == "" || user == "" || name == "" {
		return "", errors.New("database configuration missing: set DATABASE_URL or POSTGRES_HOST, POSTGRES_USER, and POSTGRES_DB")
	}

	port := getEnv("POSTGRES_PORT", "5432")
	password := strings.TrimSpace(os.Getenv("POSTGRES_PASSWORD"))
	sslMode := getEnv("POSTGRES_SSLMODE", "disable")
	timeZone := getEnv("POSTGRES_TZ", "UTC")
	clientEncoding := getEnv("POSTGRES_CLIENT_ENCODING", "UTF8")

	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=%s client_encoding=%s",
		host, port, user, password, name, sslMode, timeZone,
		clientEncoding,
	), nil
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseIntEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func loadOIDCConfig() (OIDCConfig, error) {
	issuerURL := strings.TrimSpace(os.Getenv("OIDC_ISSUER_URL"))
	clientID := strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OIDC_CLIENT_SECRET"))
	redirectURL := strings.TrimSpace(os.Getenv("OIDC_REDIRECT_URL"))

	if issuerURL == "" || clientID == "" || redirectURL == "" {
		return OIDCConfig{}, errors.New("OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_REDIRECT_URL must be set")
	}

	scopes := parseScopes(getEnv("OIDC_SCOPES", "openid profile email"))

	sessionCookieName := getEnv("SESSION_COOKIE_NAME", "spam_session")
	authCookieName := getEnv("AUTH_STATE_COOKIE_NAME", "spam_oidc")
	sessionTTL, err := parseDuration(getEnv("SESSION_TTL", "8h"))
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("SESSION_TTL: %w", err)
	}

	hashKey, err := decodeKeyEnv("SESSION_COOKIE_HASH_KEY")
	if err != nil {
		return OIDCConfig{}, err
	}
	if len(hashKey) < 32 {
		return OIDCConfig{}, errors.New("SESSION_COOKIE_HASH_KEY must decode to at least 32 bytes")
	}

	blockKey, err := decodeKeyEnv("SESSION_COOKIE_BLOCK_KEY")
	if err != nil {
		return OIDCConfig{}, err
	}
	if !isValidBlockKey(blockKey) {
		return OIDCConfig{}, errors.New("SESSION_COOKIE_BLOCK_KEY must decode to 16, 24, or 32 bytes")
	}

	cookieSecure := getEnv("COOKIE_SECURE", "true")
	secure, err := parseBool(cookieSecure)
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("COOKIE_SECURE: %w", err)
	}

	return OIDCConfig{
		IssuerURL:         issuerURL,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		RedirectURL:       redirectURL,
		Scopes:            scopes,
		SessionCookieName: sessionCookieName,
		AuthCookieName:    authCookieName,
		SessionTTL:        sessionTTL,
		CookieHashKey:     hashKey,
		CookieBlockKey:    blockKey,
		CookieSecure:      secure,
	}, nil
}

func parseScopes(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return []string{"openid"}
	}
	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	scopes := make([]string, 0, len(parts))
	foundOpenID := false
	for _, part := range parts {
		scope := strings.TrimSpace(part)
		if scope == "" {
			continue
		}
		if scope == "openid" {
			foundOpenID = true
		}
		scopes = append(scopes, scope)
	}
	if !foundOpenID {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

func parseDuration(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, errors.New("duration must not be empty")
	}
	return time.ParseDuration(raw)
}

func decodeKeyEnv(key string) ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil, fmt.Errorf("%s must be set", key)
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		return decoded, nil
	}
	decoded, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64 encoded", key)
	}
	return decoded, nil
}

func isValidBlockKey(key []byte) bool {
	switch len(key) {
	case 16, 24, 32:
		return true
	default:
		return false
	}
}

func parseBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "t", "yes", "y":
		return true, nil
	case "0", "false", "f", "no", "n":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean: %q", raw)
	}
}
