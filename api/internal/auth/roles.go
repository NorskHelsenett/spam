package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gorm.io/gorm"
)

type UserSummary struct {
	ID          string     `json:"id"`
	Subject     string     `json:"subject"`
	Email       string     `json:"email,omitempty"`
	Name        string     `json:"name,omitempty"`
	Approved    bool       `json:"approved"`
	Hidden      bool       `json:"hidden"`
	Role        string     `json:"role"`
	Groups      []string   `json:"groups"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (s *Service) RequireAdmin(r *http.Request) (*User, error) {
	session, err := s.loadSession(r)
	if err != nil {
		return nil, err
	}
	if session.UserID == "" {
		return nil, errors.New("missing user id")
	}
	isAdmin, err := s.userHasGroup(r.Context(), session.UserID, GroupAdmin)
	if err != nil {
		return nil, err
	}
	if !isAdmin {
		return nil, errors.New("forbidden")
	}

	var user User
	if err := s.db.WithContext(r.Context()).First(&user, "id = ?", session.UserID).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *Service) RequireAdminOrGlobalReader(r *http.Request) (*User, error) {
	session, err := s.loadSession(r)
	if err != nil {
		return nil, err
	}
	if session.UserID == "" {
		return nil, errors.New("missing user id")
	}

	isAdmin, err := s.userHasGroup(r.Context(), session.UserID, GroupAdmin)
	if err != nil {
		return nil, err
	}

	if !isAdmin {
		isGlobalReader, err := s.userHasGroup(r.Context(), session.UserID, GroupGlobalReader)
		if err != nil {
			return nil, err
		}
		if !isGlobalReader {
			return nil, errors.New("forbidden")
		}
	}

	var user User
	if err := s.db.WithContext(r.Context()).First(&user, "id = ?", session.UserID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) ListUsers(ctx context.Context) ([]UserSummary, error) {
	var users []User
	if err := s.db.WithContext(ctx).Order("created_at asc").Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return []UserSummary{}, nil
	}

	userIDs := make([]string, 0, len(users))
	for _, user := range users {
		userIDs = append(userIDs, user.ID)
	}

	groupMap, err := groupMapForUsers(ctx, s.db, userIDs)
	if err != nil {
		return nil, err
	}

	summaries := make([]UserSummary, 0, len(users))
	for _, user := range users {
		groups := groupMap[user.ID]
		approved := user.ApprovedAt != nil
		role := roleFromGroups(groups, approved)
		summaries = append(summaries, UserSummary{
			ID:          user.ID,
			Subject:     user.Subject,
			Email:       user.Email,
			Name:        user.Name,
			Approved:    approved,
			Hidden:      user.HiddenAt != nil,
			Role:        role,
			Groups:      groups,
			LastLoginAt: user.LastLoginAt,
			CreatedAt:   user.CreatedAt,
		})
	}

	return summaries, nil
}

func (s *Service) UpdateUserRole(ctx context.Context, userID, role, approvedBy string) (*UserSummary, error) {
	if userID == "" {
		return nil, errors.New("user id required")
	}
	if role == "" {
		return nil, errors.New("role required")
	}

	roleSlug := normalizeRole(role)
	if roleSlug == "" {
		return nil, errors.New("invalid role")
	}

	var summary *UserSummary
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user User
		if err := tx.First(&user, "id = ?", userID).Error; err != nil {
			return err
		}

		if err := ensureGroups(tx); err != nil {
			return err
		}

		groupIDs, err := groupIDsBySlug(tx)
		if err != nil {
			return err
		}

		now := time.Now()
		updates := map[string]interface{}{}
		if roleSlug == "pending" {
			updates["approved_at"] = nil
			updates["approved_by_user_id"] = nil
		} else if user.ApprovedAt == nil {
			updates["approved_at"] = now
			updates["approved_by_user_id"] = approvedBy
		}

		if len(updates) > 0 {
			updates["updated_at"] = now
			if err := tx.Model(&user).Updates(updates).Error; err != nil {
				return err
			}
		}

		if err := ensureUserGroup(tx, user.ID, groupIDs[GroupDefault]); err != nil {
			return err
		}

		roleGroupIDs := []string{groupIDs[GroupAdmin], groupIDs[GroupGlobalReader]}
		if err := tx.Where("user_id = ? AND group_id IN ?", user.ID, roleGroupIDs).Delete(&UserGroup{}).Error; err != nil {
			return err
		}

		if roleSlug == GroupAdmin {
			if err := ensureUserGroup(tx, user.ID, groupIDs[GroupAdmin]); err != nil {
				return err
			}
		}
		if roleSlug == GroupGlobalReader {
			if err := ensureUserGroup(tx, user.ID, groupIDs[GroupGlobalReader]); err != nil {
				return err
			}
		}

		groups, err := s.userGroupSlugsTx(tx, user.ID)
		if err != nil {
			return err
		}

		approved := user.ApprovedAt != nil
		if roleSlug == "pending" {
			approved = false
		} else if user.ApprovedAt == nil {
			approved = true
		}

		summary = &UserSummary{
			ID:          user.ID,
			Subject:     user.Subject,
			Email:       user.Email,
			Name:        user.Name,
			Approved:    approved,
			Role:        roleFromGroups(groups, approved),
			Groups:      groups,
			LastLoginAt: user.LastLoginAt,
			CreatedAt:   user.CreatedAt,
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return summary, nil
}

func (s *Service) userAccessSnapshot(ctx context.Context, userID string) ([]string, string, bool, error) {
	var user User
	if err := s.db.WithContext(ctx).First(&user, "id = ?", userID).Error; err != nil {
		return nil, "", false, err
	}

	groups, err := s.userGroupSlugs(ctx, userID)
	if err != nil {
		return nil, "", false, err
	}

	approved := user.ApprovedAt != nil
	return groups, roleFromGroups(groups, approved), approved, nil
}

// UserApprovalStatus returns the approval flag and role for a user.
func (s *Service) UserApprovalStatus(ctx context.Context, userID string) (bool, string, error) {
	_, role, approved, err := s.userAccessSnapshot(ctx, userID)
	if err != nil {
		return false, "", err
	}
	return approved, role, nil
}

func (s *Service) userHasGroup(ctx context.Context, userID, slug string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).
		Table("user_groups").
		Joins("join groups on groups.id = user_groups.group_id").
		Where("user_groups.user_id = ? AND groups.slug = ?", userID, slug).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Service) userGroupSlugs(ctx context.Context, userID string) ([]string, error) {
	var slugs []string
	err := s.db.WithContext(ctx).
		Table("user_groups").
		Select("groups.slug").
		Joins("join groups on groups.id = user_groups.group_id").
		Where("user_groups.user_id = ?", userID).
		Scan(&slugs).Error
	if err != nil {
		return nil, err
	}
	return slugs, nil
}

func (s *Service) userGroupSlugsTx(tx *gorm.DB, userID string) ([]string, error) {
	var slugs []string
	err := tx.
		Table("user_groups").
		Select("groups.slug").
		Joins("join groups on groups.id = user_groups.group_id").
		Where("user_groups.user_id = ?", userID).
		Scan(&slugs).Error
	if err != nil {
		return nil, err
	}
	return slugs, nil
}

func groupIDsBySlug(tx *gorm.DB) (map[string]string, error) {
	var groups []Group
	if err := tx.Find(&groups).Error; err != nil {
		return nil, err
	}

	out := make(map[string]string, len(groups))
	for _, group := range groups {
		out[group.Slug] = group.ID
	}
	return out, nil
}

func ensureUserGroup(tx *gorm.DB, userID, groupID string) error {
	if userID == "" || groupID == "" {
		return nil
	}
	return tx.Where("user_id = ? AND group_id = ?", userID, groupID).
		FirstOrCreate(&UserGroup{UserID: userID, GroupID: groupID}).Error
}

func groupMapForUsers(ctx context.Context, db *gorm.DB, userIDs []string) (map[string][]string, error) {
	type row struct {
		UserID string
		Slug   string
	}
	var rows []row

	err := db.WithContext(ctx).
		Table("user_groups").
		Select("user_groups.user_id, groups.slug").
		Joins("join groups on groups.id = user_groups.group_id").
		Where("user_groups.user_id IN ?", userIDs).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(userIDs))
	for _, row := range rows {
		result[row.UserID] = append(result[row.UserID], row.Slug)
	}
	return result, nil
}

func normalizeRole(role string) string {
	switch role {
	case GroupAdmin:
		return GroupAdmin
	case GroupGlobalReader:
		return GroupGlobalReader
	case GroupDefault:
		return GroupDefault
	case "pending":
		return "pending"
	default:
		return ""
	}
}

func (s *Service) SetUserHidden(ctx context.Context, userID string, hidden bool) (*UserSummary, error) {
	if userID == "" {
		return nil, errors.New("user id required")
	}

	var user User
	if err := s.db.WithContext(ctx).First(&user, "id = ?", userID).Error; err != nil {
		return nil, err
	}

	now := time.Now()
	updates := map[string]interface{}{"updated_at": now}
	if hidden {
		updates["hidden_at"] = now
	} else {
		updates["hidden_at"] = nil
	}
	if err := s.db.WithContext(ctx).Model(&user).Updates(updates).Error; err != nil {
		return nil, err
	}

	groups, err := s.userGroupSlugs(ctx, userID)
	if err != nil {
		return nil, err
	}

	approved := user.ApprovedAt != nil
	return &UserSummary{
		ID:          user.ID,
		Subject:     user.Subject,
		Email:       user.Email,
		Name:        user.Name,
		Approved:    approved,
		Hidden:      hidden,
		Role:        roleFromGroups(groups, approved),
		Groups:      groups,
		LastLoginAt: user.LastLoginAt,
		CreatedAt:   user.CreatedAt,
	}, nil
}

func roleFromGroups(groups []string, approved bool) string {
	if !approved {
		return "pending"
	}
	for _, slug := range groups {
		if slug == GroupAdmin {
			return GroupAdmin
		}
	}
	for _, slug := range groups {
		if slug == GroupGlobalReader {
			return GroupGlobalReader
		}
	}
	return GroupDefault
}
