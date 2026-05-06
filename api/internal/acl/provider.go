package acl

import (
	"context"
	"encoding/json"

	"gorm.io/gorm"
)

// Provider contributes scope grants for a Subject. Implementations are
// composed via ChainProvider. A provider returning an empty slice is
// valid (the subject has no grants from that source); a nil slice is
// treated the same way.
//
// Future providers (OIDC claims, GitHub App, external RBAC) implement
// this same interface and are appended to the chain without touching
// handlers or the SQL scope compiler.
type Provider interface {
	Grants(ctx context.Context, subj Subject, scopeType string) ([]ScopePattern, error)
}

// ChainProvider walks its providers in order and unions the results.
type ChainProvider struct {
	Providers []Provider
}

// Grants returns the union of all provider grants for the subject.
func (c *ChainProvider) Grants(ctx context.Context, subj Subject, scopeType string) ([]ScopePattern, error) {
	if c == nil || len(c.Providers) == 0 {
		return nil, nil
	}
	var out []ScopePattern
	for _, p := range c.Providers {
		grants, err := p.Grants(ctx, subj, scopeType)
		if err != nil {
			return nil, err
		}
		out = append(out, grants...)
	}
	return out, nil
}

// LocalProvider reads grants from the acl_grants table.
type LocalProvider struct {
	DB *gorm.DB
}

// NewLocalProvider builds a LocalProvider backed by db.
func NewLocalProvider(db *gorm.DB) *LocalProvider { return &LocalProvider{DB: db} }

// Grants returns every grant that could apply to subj for scopeType.
// Matching rules:
//   - group:<slug>  matches every group the subject is a member of
//   - user:<id>     matches the subject's user id
//
// Rows whose scope_pattern JSON cannot be decoded are skipped with no
// error — a malformed grant should never widen access.
func (p *LocalProvider) Grants(ctx context.Context, subj Subject, scopeType string) ([]ScopePattern, error) {
	if p == nil || p.DB == nil {
		return nil, nil
	}
	if subj.UserID == "" && len(subj.GroupSlugs) == 0 {
		return nil, nil
	}

	q := p.DB.WithContext(ctx).
		Table("acl_grants").
		Select("scope_pattern").
		Where("scope_type = ? AND action = ?", scopeType, ActionRead)

	switch {
	case subj.UserID != "" && len(subj.GroupSlugs) > 0:
		q = q.Where(
			"(subject_type = ? AND subject_id = ?) OR (subject_type = ? AND subject_id IN ?)",
			SubjectUser, subj.UserID,
			SubjectGroup, subj.GroupSlugs,
		)
	case subj.UserID != "":
		q = q.Where("subject_type = ? AND subject_id = ?", SubjectUser, subj.UserID)
	default:
		q = q.Where("subject_type = ? AND subject_id IN ?", SubjectGroup, subj.GroupSlugs)
	}

	var raws [][]byte
	if err := q.Scan(&raws).Error; err != nil {
		return nil, err
	}

	out := make([]ScopePattern, 0, len(raws))
	for _, raw := range raws {
		if len(raw) == 0 {
			out = append(out, ScopePattern{})
			continue
		}
		var p ScopePattern
		if err := json.Unmarshal(raw, &p); err != nil {
			// Skip malformed grants — never fail open.
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
