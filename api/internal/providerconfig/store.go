package providerconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Store struct {
	db  *gorm.DB
	key []byte
}

func NewStore(db *gorm.DB, key []byte) *Store {
	return &Store{db: db, key: key}
}

// VerifyKey checks that the configured encryption key can decrypt existing secrets.
// Returns a list of warnings for providers whose secrets cannot be decrypted.
// This is non-fatal so the app can start and admins can rotate broken tokens.
func (s *Store) VerifyKey(ctx context.Context) []string {
	var secrets []ProviderSecret
	if err := s.db.WithContext(ctx).
		Where("revoked_at IS NULL").
		Order("created_at desc").
		Find(&secrets).Error; err != nil {
		return []string{fmt.Sprintf("failed to query provider secrets: %v", err)}
	}

	if len(secrets) == 0 {
		return nil
	}

	if !isValidAESKey(s.key) {
		return []string{fmt.Sprintf("PROVIDER_SECRETS_KEY is missing or invalid, but %d active secret(s) exist — token rotation via API will fail until key is set", len(secrets))}
	}

	// Check one secret per provider (most recent)
	seen := make(map[string]bool)
	var warnings []string
	for _, secret := range secrets {
		if seen[secret.ProviderID] {
			continue
		}
		seen[secret.ProviderID] = true
		if _, err := DecryptToken(s.key, secret.TokenEncrypted); err != nil {
			warnings = append(warnings, fmt.Sprintf("provider %s: cannot decrypt secret — rotate token to fix (%v)", secret.ProviderID, err))
		}
	}

	return warnings
}

type AdminProvider struct {
	ID               string     `json:"id"`
	ProviderURL      string     `json:"provider_url"`
	BaseURL          string     `json:"base_url"`
	OwnerPath        string     `json:"owner_path"`
	Type             string     `json:"type"`
	DisplayName      string     `json:"display_name"`
	TokenFingerprint string     `json:"token_fingerprint,omitempty"`
	Enabled          bool       `json:"enabled"`
	PollInterval     *int       `json:"poll_interval,omitempty"`
	HealthStatus     string     `json:"health_status"`
	HealthMessage    string     `json:"health_message,omitempty"`
	LastHealthCheck  *time.Time `json:"last_health_check,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastRotatedAt    *time.Time `json:"last_rotated_at,omitempty"`
}

type PublicProvider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	BaseURL   string `json:"base_url"`
	OwnerPath string `json:"owner_path,omitempty"`
	IsPublic  bool   `json:"is_public"`
}

func EnsureDefaults(ctx context.Context, db *gorm.DB) error {
	var count int64
	if err := db.WithContext(ctx).Model(&ProviderInstance{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	defaults := []ProviderInstance{
		{
			ID:           uuid.NewString(),
			Type:         ProviderGitHub,
			BaseURL:      "https://github.com",
			OwnerPath:    "NorskHelsenett",
			DisplayName:  "github.com/NorskHelsenett",
			Enabled:      true,
			HealthStatus: ProviderHealthUnknown,
		},
		{
			ID:           uuid.NewString(),
			Type:         ProviderGitLab,
			BaseURL:      "https://gitlab.com",
			OwnerPath:    "",
			DisplayName:  "gitlab.com",
			Enabled:      true,
			HealthStatus: ProviderHealthUnknown,
		},
	}

	return db.WithContext(ctx).Create(&defaults).Error
}

func (s *Store) ListAdmin(ctx context.Context) ([]AdminProvider, error) {
	var providers []ProviderInstance
	if err := s.db.WithContext(ctx).Order("created_at desc").Find(&providers).Error; err != nil {
		return nil, err
	}

	if len(providers) == 0 {
		return []AdminProvider{}, nil
	}

	// Batch load active secrets for all providers (fixes N+1 query)
	providerIDs := make([]string, len(providers))
	for i, p := range providers {
		providerIDs[i] = p.ID
	}

	var secrets []ProviderSecret
	if err := s.db.WithContext(ctx).
		Where("provider_id IN ? AND revoked_at IS NULL", providerIDs).
		Order("created_at desc").
		Find(&secrets).Error; err != nil {
		return nil, err
	}

	// Build map of provider_id -> most recent active secret
	secretMap := make(map[string]*ProviderSecret)
	for i := range secrets {
		sec := &secrets[i]
		if existing, ok := secretMap[sec.ProviderID]; !ok || sec.CreatedAt.After(existing.CreatedAt) {
			secretMap[sec.ProviderID] = sec
		}
	}

	result := make([]AdminProvider, 0, len(providers))
	for _, provider := range providers {
		admin := providerToAdmin(provider)
		if secret, ok := secretMap[provider.ID]; ok {
			admin.TokenFingerprint = secret.TokenFingerprint
			admin.LastRotatedAt = &secret.CreatedAt
		}
		result = append(result, admin)
	}
	return result, nil
}

// providerToAdmin converts a ProviderInstance to AdminProvider (without secret info).
func providerToAdmin(provider ProviderInstance) AdminProvider {
	admin := AdminProvider{
		ID:              provider.ID,
		ProviderURL:     provider.BaseURL,
		BaseURL:         provider.BaseURL,
		OwnerPath:       provider.OwnerPath,
		Type:            provider.Type,
		DisplayName:     provider.DisplayName,
		Enabled:         provider.Enabled,
		PollInterval:    provider.PollInterval,
		HealthStatus:    provider.HealthStatus,
		HealthMessage:   provider.HealthMessage,
		LastHealthCheck: provider.LastHealthCheck,
		CreatedAt:       provider.CreatedAt,
		UpdatedAt:       provider.UpdatedAt,
	}
	if provider.OwnerPath != "" {
		admin.ProviderURL = strings.TrimRight(provider.BaseURL, "/") + "/" + provider.OwnerPath
	}
	return admin
}

func (s *Store) ListPublic(ctx context.Context) ([]PublicProvider, error) {
	var providers []ProviderInstance
	if err := s.db.WithContext(ctx).Where("enabled = true").Order("created_at asc").Find(&providers).Error; err != nil {
		return nil, err
	}

	if len(providers) == 0 {
		return []PublicProvider{}, nil
	}

	// Batch load active secrets to determine which providers are public (fixes N+1 query)
	providerIDs := make([]string, len(providers))
	for i, p := range providers {
		providerIDs[i] = p.ID
	}

	var secrets []ProviderSecret
	if err := s.db.WithContext(ctx).
		Where("provider_id IN ? AND revoked_at IS NULL", providerIDs).
		Find(&secrets).Error; err != nil {
		return nil, err
	}

	// Build set of provider IDs that have active secrets
	hasSecret := make(map[string]bool)
	for _, sec := range secrets {
		hasSecret[sec.ProviderID] = true
	}

	result := make([]PublicProvider, 0, len(providers))
	for _, provider := range providers {
		result = append(result, PublicProvider{
			ID:        provider.ID,
			Name:      provider.DisplayName,
			Type:      provider.Type,
			BaseURL:   provider.BaseURL,
			OwnerPath: provider.OwnerPath,
			IsPublic:  !hasSecret[provider.ID],
		})
	}
	return result, nil
}

func (s *Store) Create(ctx context.Context, provider ProviderInstance, pat string, createdBy string) (*AdminProvider, error) {
	provider.ID = uuid.NewString()
	provider.CreatedByUserID = createdBy
	if strings.TrimSpace(provider.HealthStatus) == "" {
		provider.HealthStatus = ProviderHealthUnknown
	}

	var tokenFingerprint string
	var tokenCreatedAt *time.Time

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		existing := ProviderInstance{}
		if err := tx.WithContext(ctx).
			Where("type = ? AND base_url = ? AND owner_path = ?", provider.Type, provider.BaseURL, provider.OwnerPath).
			First(&existing).Error; err == nil {
			return errors.New("provider already exists")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}

		if err := tx.WithContext(ctx).Create(&provider).Error; err != nil {
			return err
		}

		if strings.TrimSpace(pat) != "" {
			if err := s.rotateTokenTx(ctx, tx, provider.ID, pat, createdBy); err != nil {
				return err
			}
			tokenFingerprint = FingerprintToken(pat)
			now := time.Now()
			tokenCreatedAt = &now
		}

		return nil
	}); err != nil {
		return nil, err
	}

	// Build AdminProvider directly from the created provider
	admin := providerToAdmin(provider)
	admin.TokenFingerprint = tokenFingerprint
	admin.LastRotatedAt = tokenCreatedAt
	return &admin, nil
}

func (s *Store) Update(ctx context.Context, providerID string, displayName *string, enabled *bool, pollInterval ...*int) (*AdminProvider, error) {
	updates := map[string]any{}
	if displayName != nil {
		updates["display_name"] = strings.TrimSpace(*displayName)
	}
	if enabled != nil {
		updates["enabled"] = *enabled
	}
	if len(pollInterval) > 0 && pollInterval[0] != nil {
		v := *pollInterval[0]
		if v <= 0 {
			updates["poll_interval"] = nil
		} else {
			updates["poll_interval"] = v
		}
	}

	if len(updates) == 0 {
		return nil, errors.New("no updates provided")
	}

	if err := s.db.WithContext(ctx).Model(&ProviderInstance{}).
		Where("id = ?", providerID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.getAdminByID(ctx, providerID)
}

// getAdminByID loads a single provider with its active secret info.
func (s *Store) getAdminByID(ctx context.Context, providerID string) (*AdminProvider, error) {
	var provider ProviderInstance
	if err := s.db.WithContext(ctx).Where("id = ?", providerID).First(&provider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("provider not found")
		}
		return nil, err
	}

	admin := providerToAdmin(provider)

	var secret ProviderSecret
	if err := s.db.WithContext(ctx).
		Where("provider_id = ? AND revoked_at IS NULL", providerID).
		Order("created_at desc").
		First(&secret).Error; err == nil {
		admin.TokenFingerprint = secret.TokenFingerprint
		admin.LastRotatedAt = &secret.CreatedAt
	}

	return &admin, nil
}

// RotateToken rotates the PAT for a provider.
// If pat is empty, the existing token is revoked (making the provider public).
func (s *Store) RotateToken(ctx context.Context, providerID string, pat string, userID string) (*AdminProvider, error) {
	trimmedPat := strings.TrimSpace(pat)

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Always revoke existing active tokens first
		if err := s.revokeActiveTokensTx(ctx, tx, providerID, userID); err != nil {
			return err
		}

		// If new PAT provided, create new secret
		if trimmedPat != "" {
			return s.createSecretTx(ctx, tx, providerID, trimmedPat, userID)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return s.getAdminByID(ctx, providerID)
}

func (s *Store) Delete(ctx context.Context, providerID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("provider_id = ?", providerID).Delete(&ProviderSecret{}).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ?", providerID).Delete(&ProviderInstance{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// revokeActiveTokensTx revokes all active tokens for a provider, recording who revoked them.
func (s *Store) revokeActiveTokensTx(ctx context.Context, tx *gorm.DB, providerID string, revokedBy string) error {
	now := time.Now()
	return tx.WithContext(ctx).Model(&ProviderSecret{}).
		Where("provider_id = ? AND revoked_at IS NULL", providerID).
		Updates(map[string]any{
			"revoked_at":         &now,
			"revoked_by_user_id": revokedBy,
		}).Error
}

// createSecretTx creates a new encrypted secret for a provider.
func (s *Store) createSecretTx(ctx context.Context, tx *gorm.DB, providerID string, pat string, createdBy string) error {
	if !isValidAESKey(s.key) {
		return errors.New("provider secrets key not configured")
	}

	encrypted, err := EncryptToken(s.key, pat)
	if err != nil {
		return err
	}

	secret := ProviderSecret{
		ID:               uuid.NewString(),
		ProviderID:       providerID,
		TokenEncrypted:   encrypted,
		TokenFingerprint: FingerprintToken(pat),
		CreatedByUserID:  createdBy,
	}

	return tx.WithContext(ctx).Create(&secret).Error
}

// rotateTokenTx is a helper for Create that revokes existing and creates new in one step.
func (s *Store) rotateTokenTx(ctx context.Context, tx *gorm.DB, providerID string, pat string, createdBy string) error {
	if err := s.revokeActiveTokensTx(ctx, tx, providerID, createdBy); err != nil {
		return err
	}
	return s.createSecretTx(ctx, tx, providerID, pat, createdBy)
}

// FindProviderMatch finds the best provider instance for a given repo path.
func FindProviderMatch(ctx context.Context, db *gorm.DB, providerType, baseURL, repoPath string) (*ProviderInstance, error) {
	baseURL = NormalizeBaseURL(providerType, baseURL)
	if baseURL == "" {
		return nil, nil
	}

	var providers []ProviderInstance
	if err := db.WithContext(ctx).
		Where("type = ? AND base_url = ? AND enabled = true", providerType, baseURL).
		Find(&providers).Error; err != nil {
		return nil, err
	}

	if len(providers) == 0 {
		return nil, nil
	}

	repoPath = strings.Trim(repoPath, "/")
	owner := repoPath
	if parts := strings.Split(repoPath, "/"); len(parts) > 0 {
		owner = parts[0]
	}

	var best *ProviderInstance
	for i, provider := range providers {
		if providerType == ProviderGitHub {
			if provider.OwnerPath == owner {
				best = &providers[i]
				break
			}
			continue
		}
		if provider.OwnerPath == "" {
			if best == nil {
				best = &providers[i]
			}
			continue
		}
		if strings.HasPrefix(repoPath, provider.OwnerPath) {
			if best == nil || len(provider.OwnerPath) > len(best.OwnerPath) {
				best = &providers[i]
			}
		}
	}
	return best, nil
}

func GetActiveToken(ctx context.Context, db *gorm.DB, providerID string, key []byte) (string, error) {
	if providerID == "" {
		return "", nil
	}

	var secret ProviderSecret
	if err := db.WithContext(ctx).
		Where("provider_id = ? AND revoked_at IS NULL", providerID).
		Order("created_at desc").
		First(&secret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("load provider secret: %w", err)
	}

	return DecryptToken(key, secret.TokenEncrypted)
}

func (s *Store) GetActiveToken(ctx context.Context, providerID string) (string, error) {
	if s == nil {
		return "", nil
	}
	return GetActiveToken(ctx, s.db, providerID, s.key)
}

// GetActiveTokenByBaseURL looks up the best matching provider instance for the
// given providerType, baseURL, and repoPath, then returns its active token.
func (s *Store) GetActiveTokenByBaseURL(ctx context.Context, providerType, baseURL, repoPath string) (string, error) {
	if s == nil {
		return "", nil
	}
	p, err := FindProviderMatch(ctx, s.db, providerType, baseURL, repoPath)
	if err != nil || p == nil {
		return "", err
	}
	return GetActiveToken(ctx, s.db, p.ID, s.key)
}

// ListEnabledWithPolling returns providers where polling is enabled.
func (s *Store) ListEnabledWithPolling(ctx context.Context) ([]ProviderInstance, error) {
	var providers []ProviderInstance
	if err := s.db.WithContext(ctx).
		Where("enabled = true AND poll_interval IS NOT NULL AND poll_interval > 0").
		Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

func normalizeHealthStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case ProviderHealthHealthy:
		return ProviderHealthHealthy
	case ProviderHealthDegraded:
		return ProviderHealthDegraded
	case ProviderHealthFailed:
		return ProviderHealthFailed
	default:
		return ProviderHealthUnknown
	}
}

// UpdateHealth records provider connectivity/repo health status for UI and diagnostics.
func (s *Store) UpdateHealth(ctx context.Context, providerID, status, message string) error {
	if strings.TrimSpace(providerID) == "" {
		return nil
	}

	now := time.Now()
	updates := map[string]any{
		"health_status":     normalizeHealthStatus(status),
		"health_message":    strings.TrimSpace(message),
		"last_health_check": now,
		"updated_at":        now,
	}

	return s.db.WithContext(ctx).
		Model(&ProviderInstance{}).
		Where("id = ?", providerID).
		Updates(updates).Error
}
