package dephealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

// githubFetcher resolves activity metadata (last pushed, archived,
// stars, open issues, contributor concentration) from the GitHub
// REST API. Reuses the first configured GitHub provider's PAT from
// provider_secrets — the user signed off on this trade-off in
// Phase 3 planning: it shares the rate-limit budget with repo
// polling but avoids forcing admins to manage a second token.
//
// ETag-based caching: GitHub's /repos/* endpoint returns an ETag
// header; on subsequent requests we set If-None-Match to it and
// short-circuit on 304 without consuming the rate-limit budget.
// In steady state most rows return 304, so the weekly sweep is
// genuinely cheap.
type githubFetcher struct {
	httpClient *http.Client
	token      string // optional — empty falls back to unauth (60 req/h)
}

const githubAPIBase = "https://api.github.com"

func (githubFetcher) Provider() string { return "github" }

// loadGitHubFetcher returns a fetcher backed by the worker-supplied
// GitHub PAT (set via SetGitHubToken at boot). Falling back to an
// unauthenticated client (60 req/h) when no token is configured —
// useful for development/test, painful in production but at least
// observable via the per-row error field.
//
// The token is set once at boot rather than re-decrypted per sweep
// to keep dephealth a leaf in the import graph (avoiding the cycle
// dephealth → providerconfig → assets). Token rotation requires a
// worker restart, which is fine for a weekly sweep.
func loadGitHubFetcher(ctx context.Context, db *gorm.DB) *githubFetcher {
	_ = ctx
	_ = db
	return &githubFetcher{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		token:      strings.TrimSpace(currentGitHubToken()),
	}
}

// Fetch hits /repos/{owner}/{repo} (one round trip) and returns the
// fields dep_health cares about. Honours the caller-supplied etag
// for If-None-Match short-circuiting; returns NotModified=true when
// GitHub replies 304 so the runner keeps the existing row's data.
func (f *githubFetcher) Fetch(ctx context.Context, sourceURL string, etag string) (ProviderInfo, error) {
	owner, repo, ok := splitGitHubOwnerRepo(sourceURL)
	if !ok {
		return ProviderInfo{}, fmt.Errorf("not a github URL: %s", sourceURL)
	}

	endpoint := fmt.Sprintf("%s/repos/%s/%s", githubAPIBase, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ProviderInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return ProviderInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return ProviderInfo{NotModified: true, Etag: etag}, nil
	}
	if resp.StatusCode == http.StatusForbidden {
		// 403 from GitHub usually = rate-limited. Surface the reset
		// timestamp so admins can see when the budget recovers; the
		// caller treats this as a transient error and skips the row
		// without recording it.
		reset := resp.Header.Get("X-RateLimit-Reset")
		return ProviderInfo{}, fmt.Errorf("github rate-limited; reset at unix=%s", reset)
	}
	if resp.StatusCode == http.StatusNotFound {
		// Repo deleted, renamed, or made private — return zero-value
		// info so the row's existing activity data is preserved
		// (refreshOne keeps existing on a 304-like result).
		return ProviderInfo{NotModified: true, Etag: etag}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return ProviderInfo{}, fmt.Errorf("github: HTTP %d", resp.StatusCode)
	}

	var doc struct {
		PushedAt        time.Time `json:"pushed_at"`
		Archived        bool      `json:"archived"`
		StargazersCount int       `json:"stargazers_count"`
		OpenIssuesCount int       `json:"open_issues_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return ProviderInfo{}, fmt.Errorf("decode github payload: %w", err)
	}

	out := ProviderInfo{
		Etag:            resp.Header.Get("ETag"),
		Stars:           doc.StargazersCount,
		OpenIssues:      doc.OpenIssuesCount,
		IsArchived:      doc.Archived,
	}
	if !doc.PushedAt.IsZero() {
		t := doc.PushedAt
		out.LastActivityAt = &t
	}
	// Skip the contributor + commits-90d calls in the MVP — they're
	// extra round trips on the rate-limit budget. Phase 3.1 can add
	// them once we see how the steady-state rate looks under load.
	return out, nil
}

// splitGitHubOwnerRepo turns a normalized https://github.com/x/y URL
// into ("x", "y", true). Returns (_, _, false) for any other host
// or shape.
func splitGitHubOwnerRepo(rawURL string) (string, string, bool) {
	const prefix = "https://github.com/"
	if !strings.HasPrefix(rawURL, prefix) {
		return "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(rawURL, prefix), "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
