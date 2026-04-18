package imagescan

import (
	"context"
	"encoding/json"
	"log"
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

// BackfillSourceRepoIDs populates image_digests.source_repo_id for rows
// that were scanned before the column existed. For each digest without
// a link, it reads the most recent `labels` artifact, parses
// org.opencontainers.image.source, resolves it against the providers
// table, and writes the result back. Safe to call on every worker
// startup — the query filters to only rows where the column is still
// empty, so it's a no-op after the first pass.
//
// Returns (scanned, linked) — how many digests were considered and how
// many got a repo_id set.
func BackfillSourceRepoIDs(ctx context.Context, db *gorm.DB) (int, int, error) {
	type row struct {
		ID      string
		Content []byte
	}
	var rows []row
	err := db.WithContext(ctx).Raw(`
		SELECT id.id, a.content
		FROM image_digests id
		JOIN LATERAL (
		    SELECT a.content
		    FROM image_scan_artifacts a
		    JOIN jobs j ON j.id = a.scan_run_id
		    WHERE j.payload->>'image_digest_id' = id.id
		      AND a.category = 'labels'
		    ORDER BY a.created_at DESC
		    LIMIT 1
		) a ON true
		WHERE id.source_repo_id IS NULL OR id.source_repo_id = ''
	`).Scan(&rows).Error
	if err != nil {
		return 0, 0, err
	}

	linked := 0
	for _, r := range rows {
		source := extractSourceLabelFromConfig(r.Content)
		if source == "" {
			continue
		}
		repoID, err := ResolveSourceRepoID(ctx, db, source)
		if err != nil || repoID == "" {
			continue
		}
		if err := db.WithContext(ctx).Exec(
			"UPDATE image_digests SET source_repo_id = ? WHERE id = ?",
			repoID, r.ID,
		).Error; err != nil {
			log.Printf("backfill source_repo_id for %s: %v", r.ID, err)
			continue
		}
		linked++
	}
	return len(rows), linked, nil
}

// extractSourceLabelFromConfig mirrors the runner package helper; kept
// here so the backfill doesn't need to import runner (which would be a
// reversed layering).
func extractSourceLabelFromConfig(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return ""
	}
	return strings.TrimSpace(config.Config.Labels["org.opencontainers.image.source"])
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
