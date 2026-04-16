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

const (
	// staleJobBuffer is the grace period added to runner active deadline when
	// calculating the stale timeout. This accounts for K8s scheduling delays,
	// pod startup time, and network latency for callbacks.
	staleJobBuffer = 15 * time.Minute

	// defaultStaleTimeout is used when the runner is disabled.
	defaultStaleTimeout = 15 * time.Minute
)

// Config captures the runtime configuration required by the API server.
type Config struct {
	HTTPPort           string
	DatabaseURL        string
	OIDC               OIDCConfig
	ProviderSecretsKey []byte
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

	secretKey, err := parseSecretKeyEnv("PROVIDER_SECRETS_KEY")
	if err != nil {
		return Config{}, err
	}
	cfg.ProviderSecretsKey = secretKey

	return cfg, nil
}

// WorkerConfig captures configuration for the background worker.
type WorkerConfig struct {
	DatabaseURL        string
	Concurrency        int           // Number of concurrent job processors
	StaleTimeout       time.Duration // Duration after which RUNNING jobs are considered stale
	ProviderSecretsKey []byte        // Key for decrypting provider secrets (for poller)
	Runner             RunnerConfig
}

// RunnerConfig captures configuration for the Kubernetes runner system.
type RunnerConfig struct {
	Enabled            bool              // Enable runner functionality
	HMACKey            []byte            // Key for signing run tokens
	ProviderSecretsKey []byte            // Key for encrypting provider secrets
	Image              string            // Runner container image
	Namespace          string            // Kubernetes namespace for runner jobs
	ServiceAccount     string            // ServiceAccount for runner jobs
	WorkerURL          string            // Internal callback URL (http://worker:8081)
	HTTPPort           int               // Worker runner HTTP port (default 8081)
	TTLSeconds         int32             // TTL for completed K8s jobs
	ActiveDeadline     int64             // Maximum runtime for K8s jobs in seconds
	KubeconfigPath     string            // Path to kubeconfig (empty for in-cluster)
	PodAnnotations     map[string]string // Additional annotations for runner pods (auto-inherits from worker pod)
	EgressSelfTest     RunnerEgressSelfTestConfig
	// ImageScanEnv are extra environment variables forwarded to image-scan
	// runner pods. Typical keys: GRYPE_DB_UPDATE_URL, GRYPE_DB_AUTO_UPDATE,
	// TRIVY_DB_REPOSITORY, TRIVY_JAVA_DB_REPOSITORY. Parsed from
	// RUNNER_IMAGE_SCAN_ENV (same format as RUNNER_POD_ANNOTATIONS:
	// "KEY1=VAL1,KEY2=VAL2").
	ImageScanEnv map[string]string
}

type RunnerEgressSelfTestConfig struct {
	Enabled        bool
	URL            string
	TimeoutSeconds int
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

	// Load provider secrets key (needed for poller regardless of runner)
	secretKey, err := parseSecretKeyEnv("PROVIDER_SECRETS_KEY")
	if err != nil {
		return WorkerConfig{}, err
	}
	cfg.ProviderSecretsKey = secretKey

	// Load runner config
	runnerCfg, err := loadRunnerConfig()
	if err != nil {
		return WorkerConfig{}, fmt.Errorf("runner config: %w", err)
	}
	cfg.Runner = runnerCfg

	// Stale timeout: runner active deadline + buffer (or default if runner disabled)
	if cfg.Runner.Enabled {
		cfg.StaleTimeout = time.Duration(cfg.Runner.ActiveDeadline)*time.Second + staleJobBuffer
	} else {
		cfg.StaleTimeout = defaultStaleTimeout
	}

	return cfg, nil
}

func loadRunnerConfig() (RunnerConfig, error) {
	enabled := parseBoolEnv("RUNNER_ENABLED", false)
	if !enabled {
		return RunnerConfig{}, nil
	}

	cfg := RunnerConfig{
		Enabled:        true,
		Image:          getEnv("RUNNER_IMAGE", "spam-runner:latest"),
		Namespace:      getEnv("RUNNER_NAMESPACE", "default"),
		ServiceAccount: getEnv("RUNNER_SERVICE_ACCOUNT", "spam-runner"),
		WorkerURL:      getEnv("RUNNER_WORKER_URL", "http://localhost:8081"),
		HTTPPort:       parseIntEnv("RUNNER_HTTP_PORT", 8081),
		TTLSeconds:     int32(parseIntEnv("RUNNER_TTL_SECONDS", 3600)),
		ActiveDeadline: int64(parseIntEnv("RUNNER_ACTIVE_DEADLINE", 1800)),
		KubeconfigPath: strings.TrimSpace(os.Getenv("RUNNER_KUBECONFIG")),
		PodAnnotations: parseMapEnv("RUNNER_POD_ANNOTATIONS"),
		EgressSelfTest: RunnerEgressSelfTestConfig{
			Enabled:        parseBoolEnv("RUNNER_EGRESS_SELF_TEST_ENABLED", false),
			URL:            getEnv("RUNNER_EGRESS_SELF_TEST_URL", "https://example.com"),
			TimeoutSeconds: parseIntEnv("RUNNER_EGRESS_SELF_TEST_TIMEOUT_SECONDS", 5),
		},
		ImageScanEnv: parseMapEnv("RUNNER_IMAGE_SCAN_ENV"),
	}

	// HMAC key is required when runner is enabled
	hmacKeyStr := strings.TrimSpace(os.Getenv("RUNNER_HMAC_KEY"))
	if hmacKeyStr == "" {
		return RunnerConfig{}, errors.New("RUNNER_HMAC_KEY must be set when RUNNER_ENABLED=true")
	}

	// Try base64 decode first, fall back to raw string
	hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyStr)
	if err != nil {
		hmacKey = []byte(hmacKeyStr)
	}
	if len(hmacKey) < 32 {
		return RunnerConfig{}, errors.New("RUNNER_HMAC_KEY must be at least 32 bytes")
	}
	cfg.HMACKey = hmacKey

	secretKey, err := parseSecretKeyEnv("PROVIDER_SECRETS_KEY")
	if err != nil {
		return RunnerConfig{}, err
	}
	cfg.ProviderSecretsKey = secretKey

	return cfg, nil
}

// LoadRunnerConfigOptional loads runner configuration for read-only access (e.g., API server).
// Unlike loadRunnerConfig, this doesn't require HMAC key since it's only used for querying K8s.
func LoadRunnerConfigOptional() (RunnerConfig, error) {
	enabled := parseBoolEnv("RUNNER_ENABLED", false)
	if !enabled {
		return RunnerConfig{}, errors.New("runner not enabled")
	}

	cfg := RunnerConfig{
		Enabled:        true,
		Image:          getEnv("RUNNER_IMAGE", "spam-runner:latest"),
		Namespace:      getEnv("RUNNER_NAMESPACE", "default"),
		ServiceAccount: getEnv("RUNNER_SERVICE_ACCOUNT", "spam-runner"),
		WorkerURL:      getEnv("RUNNER_WORKER_URL", "http://localhost:8081"),
		HTTPPort:       parseIntEnv("RUNNER_HTTP_PORT", 8081),
		TTLSeconds:     int32(parseIntEnv("RUNNER_TTL_SECONDS", 3600)),
		ActiveDeadline: int64(parseIntEnv("RUNNER_ACTIVE_DEADLINE", 1800)),
		KubeconfigPath: strings.TrimSpace(os.Getenv("RUNNER_KUBECONFIG")),
		PodAnnotations: parseMapEnv("RUNNER_POD_ANNOTATIONS"),
		EgressSelfTest: RunnerEgressSelfTestConfig{
			Enabled:        parseBoolEnv("RUNNER_EGRESS_SELF_TEST_ENABLED", false),
			URL:            getEnv("RUNNER_EGRESS_SELF_TEST_URL", "https://example.com"),
			TimeoutSeconds: parseIntEnv("RUNNER_EGRESS_SELF_TEST_TIMEOUT_SECONDS", 5),
		},
		ImageScanEnv: parseMapEnv("RUNNER_IMAGE_SCAN_ENV"),
	}

	// HMAC key is optional for read-only access
	hmacKeyStr := strings.TrimSpace(os.Getenv("RUNNER_HMAC_KEY"))
	if hmacKeyStr != "" {
		hmacKey, err := base64.StdEncoding.DecodeString(hmacKeyStr)
		if err != nil {
			hmacKey = []byte(hmacKeyStr)
		}
		cfg.HMACKey = hmacKey
	}

	secretKey, err := parseSecretKeyEnv("PROVIDER_SECRETS_KEY")
	if err != nil {
		return RunnerConfig{}, err
	}
	cfg.ProviderSecretsKey = secretKey

	return cfg, nil
}

func parseBoolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := parseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
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

func parseSecretKeyEnv(key string) ([]byte, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil, nil
	}

	if isValidBlockKey([]byte(value)) {
		return []byte(value), nil
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil && isValidBlockKey(decoded) {
		return decoded, nil
	}

	return nil, errors.New("PROVIDER_SECRETS_KEY must be 16, 24, or 32 bytes (raw or base64)")
}

// parseMapEnv parses a comma-separated key=value environment variable.
// Example: "key1=value1,key2=value2" -> map[string]string{"key1": "value1", "key2": "value2"}
func parseMapEnv(key string) map[string]string {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return nil
	}

	result := make(map[string]string)
	pairs := strings.Split(val, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}
