package imagescan

import (
	"context"
	"net/url"
	"strings"

	"gorm.io/gorm"
)

// parseSourceURL extracts (host, org, slug) from an OCI
// `org.opencontainers.image.source` label. Handles https URLs and the
// scp-style git SSH form (`git@host:org/slug.git`). Returns ok=false on
// anything we can't normalize to a 3-tuple so callers can fall through
// to the raw URL.
func parseSourceURL(raw string) (host, org, slug string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", false
	}
	// scp-style SSH: git@github.com:org/repo.git
	if strings.HasPrefix(raw, "git@") {
		rest := strings.TrimPrefix(raw, "git@")
		if colon := strings.Index(rest, ":"); colon > 0 {
			host = rest[:colon]
			path := strings.Trim(rest[colon+1:], "/")
			parts := strings.SplitN(path, "/", 2)
			if len(parts) == 2 {
				return host, parts[0], strings.TrimSuffix(parts[1], ".git"), true
			}
		}
		return "", "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	path := strings.Trim(u.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return u.Host, parts[0], strings.TrimSuffix(parts[1], ".git"), true
}

// ResolveSourceRepoID turns an OCI source label into the internal
// repo.id, or "" if no repo in the providers table matches. Matches
// (org, slug) in SQL and filters by host in Go: for managed hosts
// (github.com, gitlab.com) by repo.provider, for self-hosted instances
// by provider_instances.base_url.
//
// Called on scan upload to populate image_digests.source_repo_id so the
// image detail page and the repo→images reverse lookup can JOIN instead
// of re-parsing labels at read time.
func ResolveSourceRepoID(ctx context.Context, db *gorm.DB, sourceURL string) (string, error) {
	host, org, slug, ok := parseSourceURL(sourceURL)
	if !ok {
		return "", nil
	}
	var rows []struct {
		RepoID   string `gorm:"column:repo_id"`
		Provider string
		BaseURL  string `gorm:"column:base_url"`
	}
	err := db.WithContext(ctx).Raw(`
		SELECT r.id AS repo_id, r.provider,
		       COALESCE(pi.base_url, '') AS base_url
		FROM repos r
		LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
		WHERE lower(r.org) = lower(?) AND lower(r.slug) = lower(?)
		LIMIT 10
	`, org, slug).Scan(&rows).Error
	if err != nil || len(rows) == 0 {
		return "", err
	}
	lowerHost := strings.ToLower(host)
	for _, row := range rows {
		if baseURL := strings.TrimSpace(row.BaseURL); baseURL != "" {
			if u, err := url.Parse(baseURL); err == nil && strings.EqualFold(u.Host, lowerHost) {
				return row.RepoID, nil
			}
		}
		if (lowerHost == "github.com" && row.Provider == "github") ||
			(lowerHost == "gitlab.com" && row.Provider == "gitlab") {
			return row.RepoID, nil
		}
	}
	return "", nil
}
