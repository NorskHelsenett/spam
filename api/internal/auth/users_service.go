package auth

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var errUserPendingApproval = errors.New("user pending approval")

type ensureUserResult struct {
	user      User
	approved  bool
	created   bool
	firstUser bool
}

func (s *Service) ensureUser(ctx context.Context, claims userClaims) (ensureUserResult, error) {
	var result ensureUserResult

	// EntraID returns emails with original casing (e.g. Jonas.Bo.Grimsgaard@nhn.no)
	// while other IdPs lowercase them. Normalize here so login is the single
	// point of truth and existing rows are healed on next sign-in.
	claims.Email = strings.ToLower(strings.TrimSpace(claims.Email))

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := ensureGroups(tx); err != nil {
			return err
		}

		// Treat email as the human identity: one users row per email, even when
		// the same human logs in via different issuers. Subject is overwritten
		// to whichever issuer logged in most recently. Fall back to subject
		// lookup when the IdP didn't return an email.
		var user User
		var lookupErr error
		if claims.Email != "" {
			lookupErr = tx.Where("email = ?", claims.Email).First(&user).Error
		} else {
			lookupErr = tx.Where("subject = ?", claims.Subject).First(&user).Error
		}
		if lookupErr != nil {
			if !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
				return lookupErr
			}

			var count int64
			if err := tx.Model(&User{}).Count(&count).Error; err != nil {
				return err
			}

			now := time.Now()
			user = User{
				ID:          uuid.NewString(),
				Subject:     claims.Subject,
				Email:       claims.Email,
				Name:        preferredName(claims),
				LastLoginAt: &now,
			}

			if count == 0 {
				user.ApprovedAt = &now
				result.firstUser = true
			}

			if err := tx.Create(&user).Error; err != nil {
				return err
			}

			if err := assignDefaultGroups(tx, user.ID, result.firstUser); err != nil {
				return err
			}

			if !result.firstUser {
				if err := events.NotifyEvent(tx, events.StreamEventNewUser, UserSummary{
					ID:        user.ID,
					Subject:   user.Subject,
					Email:     user.Email,
					Name:      user.Name,
					Picture:   pictureOrGravatar("", user.Email),
					Approved:  false,
					Hidden:    false,
					Role:      "pending",
					Groups:    []string{GroupDefault},
					CreatedAt: user.CreatedAt,
				}); err != nil {
					log.Printf("failed to notify new_user event: %v", err)
				}
			}

			result.created = true
		} else {
			now := time.Now()
			updates := map[string]interface{}{
				"subject":       claims.Subject,
				"email":         claims.Email,
				"name":          preferredName(claims),
				"last_login_at": now,
				"updated_at":    now,
			}
			if err := tx.Model(&user).Updates(updates).Error; err != nil {
				return err
			}
			user.Subject = claims.Subject
			user.Email = claims.Email
			user.Name = preferredName(claims)
			user.LastLoginAt = &now
		}

		result.user = user
		result.approved = user.ApprovedAt != nil

		return nil
	})

	if err != nil {
		return ensureUserResult{}, err
	}

	if !result.approved {
		return result, errUserPendingApproval
	}

	return result, nil
}

func ensureGroups(tx *gorm.DB) error {
	groups := []Group{
		{ID: uuid.NewString(), Slug: GroupDefault, Name: "Default"},
		{ID: uuid.NewString(), Slug: GroupAdmin, Name: "Admin"},
		{ID: uuid.NewString(), Slug: GroupGlobalReader, Name: "Global Reader"},
	}

	for _, group := range groups {
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "slug"}},
			DoNothing: true,
		}).Create(&group).Error; err != nil {
			return err
		}
	}

	return nil
}

func assignDefaultGroups(tx *gorm.DB, userID string, makeAdmin bool) error {
	var groups []Group
	if err := tx.Where("slug IN ?", []string{GroupDefault, GroupAdmin, GroupGlobalReader}).Find(&groups).Error; err != nil {
		return err
	}

	now := time.Now()
	for _, group := range groups {
		if group.Slug != GroupDefault && !makeAdmin {
			continue
		}
		if err := tx.Where("user_id = ? AND group_id = ?", userID, group.ID).
			FirstOrCreate(&UserGroup{UserID: userID, GroupID: group.ID, CreatedAt: now}).Error; err != nil {
			return err
		}
	}

	return nil
}
