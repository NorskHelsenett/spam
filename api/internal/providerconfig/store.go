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

type AdminProvider struct {
	ID               string     `json:"id"`
	ProviderURL      string     `json:"provider_url"`
	BaseURL          string     `json:"base_url"`
	OwnerPath        string     `json:"owner_path"`
	Type             string     `json:"type"`
	DisplayName      string     `json:"display_name"`
	TokenFingerprint string     `json:"token_fingerprint,omitempty"`
	Enabled          bool       `json:"enabled"`
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
			ID:          uuid.NewString(),
			Type:        ProviderGitHub,
			BaseURL:     "https://github.com",
			OwnerPath:   "NorskHelsenett",
			DisplayName: "github.com/NorskHelsenett",
			Enabled:     true,
		},
		{
			ID:          uuid.NewString(),
			Type:        ProviderGitLab,
			BaseURL:     "https://gitlab.com",
			OwnerPath:   "",
			DisplayName: "gitlab.com",
			Enabled:     true,
		},
	}

	return db.WithContext(ctx).Create(&defaults).Error
}

func (s *Store) ListAdmin(ctx context.Context) ([]AdminProvider, error) {
	var providers []ProviderInstance
	if err := s.db.WithContext(ctx).Order("created_at desc").Find(&providers).Error; err != nil {
		return nil, err
	}

	result := make([]AdminProvider, 0, len(providers))
	for _, provider := range providers {
		admin := AdminProvider{
			ID:          provider.ID,
			ProviderURL: provider.BaseURL,
			BaseURL:     provider.BaseURL,
			OwnerPath:   provider.OwnerPath,
			Type:        provider.Type,
			DisplayName: provider.DisplayName,
			Enabled:     provider.Enabled,
			CreatedAt:   provider.CreatedAt,
			UpdatedAt:   provider.UpdatedAt,
		}
		if provider.OwnerPath != "" {
			admin.ProviderURL = strings.TrimRight(provider.BaseURL, "/") + "/" + provider.OwnerPath
		}

		var secret ProviderSecret
		if err := s.db.WithContext(ctx).
			Where("provider_id = ? AND revoked_at IS NULL", provider.ID).
			Order("created_at desc").
			First(&secret).Error; err == nil {
			admin.TokenFingerprint = secret.TokenFingerprint
			admin.LastRotatedAt = &secret.CreatedAt
		}

		result = append(result, admin)
	}
	return result, nil
}

func (s *Store) ListPublic(ctx context.Context) ([]PublicProvider, error) {
	var providers []ProviderInstance
	if err := s.db.WithContext(ctx).Where("enabled = true").Order("created_at asc").Find(&providers).Error; err != nil {
		return nil, err
	}

	result := make([]PublicProvider, 0, len(providers))
	for _, provider := range providers {
		isPublic := true
		var secret ProviderSecret
		if err := s.db.WithContext(ctx).
			Where("provider_id = ? AND revoked_at IS NULL", provider.ID).
			First(&secret).Error; err == nil {
			isPublic = false
		}

		result = append(result, PublicProvider{
			ID:        provider.ID,
			Name:      provider.DisplayName,
			Type:      provider.Type,
			BaseURL:   provider.BaseURL,
			OwnerPath: provider.OwnerPath,
			IsPublic:  isPublic,
		})
	}
	return result, nil
}

func (s *Store) Create(ctx context.Context, provider ProviderInstance, pat string, createdBy string) (*AdminProvider, error) {
	provider.ID = uuid.NewString()
	provider.CreatedByUserID = createdBy

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
		}

		return nil
	}); err != nil {
		return nil, err
	}

	admins, err := s.ListAdmin(ctx)
	if err != nil {
		return nil, err
	}
	for _, admin := range admins {
		if admin.ID == provider.ID {
			return &admin, nil
		}
	}
	return nil, errors.New("provider created but not found")
}

func (s *Store) Update(ctx context.Context, providerID string, displayName *string, enabled *bool) (*AdminProvider, error) {
	updates := map[string]interface{}{}
	if displayName != nil {
		updates["display_name"] = strings.TrimSpace(*displayName)
	}
	if enabled != nil {
		updates["enabled"] = *enabled
	}

	if len(updates) == 0 {
		return nil, errors.New("no updates provided")
	}

	if err := s.db.WithContext(ctx).Model(&ProviderInstance{}).
		Where("id = ?", providerID).
		Updates(updates).Error; err != nil {
		return nil, err
	}

	admins, err := s.ListAdmin(ctx)
	if err != nil {
		return nil, err
	}
	for _, admin := range admins {
		if admin.ID == providerID {
			return &admin, nil
		}
	}
	return nil, errors.New("provider not found")
}

func (s *Store) RotateToken(ctx context.Context, providerID string, pat string, createdBy string) (*AdminProvider, error) {
	if strings.TrimSpace(pat) == "" {
		return nil, errors.New("token required")
	}
	if err := s.rotateToken(ctx, providerID, pat, createdBy); err != nil {
		return nil, err
	}

	admins, err := s.ListAdmin(ctx)
	if err != nil {
		return nil, err
	}
	for _, admin := range admins {
		if admin.ID == providerID {
			return &admin, nil
		}
	}
	return nil, errors.New("provider not found")
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

func (s *Store) rotateToken(ctx context.Context, providerID string, pat string, createdBy string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.rotateTokenTx(ctx, tx, providerID, pat, createdBy)
	})
}

func (s *Store) rotateTokenTx(ctx context.Context, tx *gorm.DB, providerID string, pat string, createdBy string) error {
	if !isValidAESKey(s.key) {
		return errors.New("provider secrets key not configured")
	}

	encrypted, err := EncryptToken(s.key, pat)
	if err != nil {
		return err
	}
	fingerprint := FingerprintToken(pat)

	now := time.Now()
	if err := tx.WithContext(ctx).Model(&ProviderSecret{}).
		Where("provider_id = ? AND revoked_at IS NULL", providerID).
		Update("revoked_at", &now).Error; err != nil {
		return err
	}

	secret := ProviderSecret{
		ID:               uuid.NewString(),
		ProviderID:       providerID,
		TokenEncrypted:   encrypted,
		TokenFingerprint: fingerprint,
		CreatedByUserID:  createdBy,
	}

	return tx.WithContext(ctx).Create(&secret).Error
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
