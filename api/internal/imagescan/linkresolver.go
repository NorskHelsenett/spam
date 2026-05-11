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

// RelinkRepoImages fires when a repo is inserted/updated, scanning
// orphan image_digests whose cached source_label matches this repo's
// (host, org, slug) and setting their source_repo_id. Lets "repo
// imported after image was scanned" settle instantly without a
// periodic sweep.
//
// The matcher mirrors ResolveSourceRepoID: host comparison uses the
// provider_instance.base_url for self-hosted providers, or the
// provider column for github.com / gitlab.com. Returns the number of
// images that got newly linked.
func RelinkRepoImages(ctx context.Context, db *gorm.DB, repoID string) (int, error) {
	if strings.TrimSpace(repoID) == "" {
		return 0, nil
	}
	type repoRow struct {
		Provider string
		Org      string
		Slug     string
		BaseURL  string `gorm:"column:base_url"`
	}
	var r repoRow
	err := db.WithContext(ctx).Raw(`
		SELECT r.provider, r.org, r.slug, COALESCE(pi.base_url, '') AS base_url
		FROM repos r
		LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id
		WHERE r.id = ?
	`, repoID).Scan(&r).Error
	if err != nil || r.Org == "" || r.Slug == "" {
		return 0, err
	}

	// Pull all orphan image_digests that have a non-empty source_label.
	// We can't filter further in SQL cheaply because source_label is a
	// full URL (needs parsing) — but the row count is tiny vs total
	// images, and this runs only when a repo is created.
	type orphan struct {
		ID          string
		SourceLabel string `gorm:"column:source_label"`
	}
	var orphans []orphan
	err = db.WithContext(ctx).Raw(`
		SELECT id, source_label
		FROM image_digests
		WHERE (source_repo_id IS NULL OR source_repo_id = '')
		  AND source_label IS NOT NULL AND source_label <> '' AND source_label <> '-'
	`).Scan(&orphans).Error
	if err != nil {
		return 0, err
	}

	linked := 0
	for _, o := range orphans {
		host, org, slug, ok := parseSourceURL(o.SourceLabel)
		if !ok {
			continue
		}
		if !strings.EqualFold(org, r.Org) || !strings.EqualFold(slug, r.Slug) {
			continue
		}
		matched := false
		if r.BaseURL != "" {
			if u, err := url.Parse(r.BaseURL); err == nil && strings.EqualFold(u.Host, host) {
				matched = true
			}
		}
		if !matched {
			switch {
			case strings.EqualFold(host, "github.com") && r.Provider == "github":
				matched = true
			case strings.EqualFold(host, "gitlab.com") && r.Provider == "gitlab":
				matched = true
			}
		}
		if !matched {
			continue
		}
		if err := db.WithContext(ctx).Exec(
			"UPDATE image_digests SET source_repo_id = ? WHERE id = ?",
			repoID, o.ID,
		).Error; err != nil {
			log.Printf("relink image %s -> %s: %v", o.ID, repoID, err)
			continue
		}
		linked++
	}
	return linked, nil
}

// BackfillSourceRepoIDs converges image_digests.source_repo_id +
// source_label with whatever labels + providers the database currently
// holds. Runs in two passes:
//
//   Pass A (expensive, amortised): for digests whose source_label is
//   still empty, read the most recent `labels` artifact, parse
//   org.opencontainers.image.source, cache it on source_label. Each
//   digest hits the artifacts table at most once.
//
//   Pass B (cheap, periodic): for digests with source_label set but
//   source_repo_id empty, re-resolve against providers and update.
//   This is what handles "repo imported AFTER image was scanned" — on
//   each tick, newly-added repos get their orphan images linked. Uses
//   only the short source_label column, no artifact reads.
//
// Both passes skip rows that are already fully linked, so converges
// to O(net-new-rows) cost per tick.
//
// Returns (scanned, linked) where scanned counts pass-A rows visited
// (including no-ops) and linked counts how many digests were newly
// resolved to a repo across both passes.
func BackfillSourceRepoIDs(ctx context.Context, db *gorm.DB) (int, int, error) {
	// --- Pass A: populate source_label from labels artifacts ---
	type labelRow struct {
		ID      string
		Content []byte
	}
	var labelRows []labelRow
	// j.type = 'IMAGE_SCAN' lets the planner pick idx_jobs_image_scan_digest_all
	// (partial index on payload->>'image_digest_id' WHERE type='IMAGE_SCAN').
	// Without the explicit type predicate, the planner can't prove the
	// partial filter holds and falls back to a seq-scan of jobs per
	// image_digest — pg_stat_statements caught this as a multi-second
	// startup query on a 20M-row jobs table.
	err := db.WithContext(ctx).Raw(`
		SELECT id.id, a.content
		FROM image_digests id
		JOIN LATERAL (
		    SELECT a.content
		    FROM image_scan_artifacts a
		    JOIN jobs j ON j.id = a.scan_run_id
		    WHERE j.type = 'IMAGE_SCAN'
		      AND j.payload->>'image_digest_id' = id.id
		      AND a.category = 'labels'
		    ORDER BY a.created_at DESC
		    LIMIT 1
		) a ON true
		WHERE id.source_label IS NULL OR id.source_label = ''
	`).Scan(&labelRows).Error
	if err != nil {
		return 0, 0, err
	}
	for _, r := range labelRows {
		source := extractSourceLabelFromConfig(r.Content)
		if source == "" {
			// Write a marker so Pass A doesn't re-read this artifact
			// every tick when the label is genuinely absent. A short
			// non-URL sentinel keeps ResolveSourceRepoID a no-op.
			source = "-"
		}
		if err := db.WithContext(ctx).Exec(
			"UPDATE image_digests SET source_label = ? WHERE id = ?",
			source, r.ID,
		).Error; err != nil {
			log.Printf("backfill source_label for %s: %v", r.ID, err)
		}
	}

	// --- Pass B: resolve source_label → source_repo_id ---
	type resolveRow struct {
		ID          string
		SourceLabel string `gorm:"column:source_label"`
	}
	var resolveRows []resolveRow
	err = db.WithContext(ctx).Raw(`
		SELECT id, source_label
		FROM image_digests
		WHERE (source_repo_id IS NULL OR source_repo_id = '')
		  AND source_label IS NOT NULL AND source_label <> '' AND source_label <> '-'
	`).Scan(&resolveRows).Error
	if err != nil {
		return len(labelRows), 0, err
	}
	linked := 0
	for _, r := range resolveRows {
		repoID, err := ResolveSourceRepoID(ctx, db, r.SourceLabel)
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
	return len(labelRows), linked, nil
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
