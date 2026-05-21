package uiapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/NorskHelsenett/spam/internal/acl"
	"github.com/NorskHelsenett/spam/internal/auth"
	"github.com/NorskHelsenett/spam/internal/vulnmetrics"
	"gorm.io/gorm"
)

// VulnSummaryHandler returns overall vulnerability counts and last scan time.
//
// GET /api/vuln/summary
//
// Two-tier dispatch: admins / global_readers / wildcard repo grants hit
// the shared cached LoadSummary (cross-tenant aggregate). Narrow-grant
// callers (cluster-only users, scoped grants) get a per-request scoped
// recompute against their readable repo + image set — so a ROR cluster-
// only user sees a non-empty summary for vulns in their cluster's
// running images instead of the previous 404.
func VulnSummaryHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		if hasUnrestrictedRepos(r) {
			summary, err := vulnmetrics.LoadSummary(r.Context(), db)
			if err != nil {
				http.Error(w, "failed to load vulnerability summary", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, summary)
			return
		}

		subj := acl.SubjectFromRequest(r)
		prov := acl.ProviderFromRequest(r)
		// Strict repo clause: no public-repo leak, OCI cluster→repo
		// bridge included. See acl.ReadableRepoClauseStrict.
		repoClause, err := acl.ReadableRepoClauseStrict(r.Context(), prov, subj, "r")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		imageClause, err := acl.ReadableImageClause(r.Context(), prov, subj, "d")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		repoSQL, repoArgs := repoSubquery(repoClause)
		imageSQL, imageArgs := imageSubquery(imageClause)

		summary, err := vulnmetrics.LoadSummaryScoped(r.Context(), db, repoSQL, repoArgs, imageSQL, imageArgs)
		if err != nil {
			http.Error(w, "failed to load vulnerability summary", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}

// VulnReposHandler returns per-repo vulnerability counts sorted by severity.
//
// GET /api/vuln/repos
func VulnReposHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		rows, err := vulnmetrics.LoadRepos(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load vulnerability repos", http.StatusInternalServerError)
			return
		}

		// Use the strict-clause repo id set: explicit grants + OCI
		// cluster→repo bridge, no public-repo fallback. Cluster-only
		// callers see repos whose verified images run in their
		// clusters and nothing else.
		readable, unrestricted, err := readableRepoIDSetStrict(r, db)
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		if !unrestricted {
			filtered := rows[:0]
			for _, row := range rows {
				if _, ok := readable[row.RepoID]; ok {
					filtered = append(filtered, row)
				}
			}
			rows = filtered
		}

		writeJSON(w, http.StatusOK, rows)
	}
}

// VulnListHandler returns a paginated, server-filtered page of
// vulnerability groups — one entry per CVE rolled up across every repo
// and image it appears on.
//
// GET /api/vuln/list?limit=&offset=&severity=CRITICAL,HIGH&q=&source=trivy,grype
//                  &fix=1&kev=1&epss_min=0.1&year=2024,2023&repo_id=
//
// The response shape is {total, limit, offset, items: VulnGroup[]}.
// total counts distinct vuln_ids matching the filters so the client can
// size a virtual scroller off a single page load.
func VulnListHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		q := r.URL.Query()
		params := vulnmetrics.VulnListParams{
			Limit:      parseIntDefault(q.Get("limit"), 50),
			Offset:     parseIntDefault(q.Get("offset"), 0),
			Severities: splitUpper(q.Get("severity")),
			Query:      q.Get("q"),
			Sources:    splitLower(q.Get("source")),
			FixOnly:    q.Get("fix") == "1" || strings.EqualFold(q.Get("fix"), "true"),
			KEVOnly:    q.Get("kev") == "1" || strings.EqualFold(q.Get("kev"), "true"),
			EPSSMin:    parseFloatClamped(q.Get("epss_min"), 0, 1),
			Years:      splitCSV(q.Get("year")),
			RepoID:     q.Get("repo_id"),
		}

		// Fast path: caller scoped the request to a specific repo —
		// gate up-front by ACL so we don't load rows the caller can't
		// see, and short-circuit the repo/image ACL fragments below.
		if params.RepoID != "" {
			if ok, err := canReadRepoByID(r, db, params.RepoID); err != nil || !ok {
				notFoundOrForbidden(w)
				return
			}
			params.RepoSQL = "TRUE"
			params.ImageSQL = "FALSE"
		} else {
			subj := acl.SubjectFromRequest(r)
			prov := acl.ProviderFromRequest(r)

			repoClause, err := acl.ReadableRepoClauseStrict(r.Context(), prov, subj, "r")
			if err != nil {
				http.Error(w, "failed to scope results", http.StatusInternalServerError)
				return
			}
			imageClause, err := acl.ReadableImageClause(r.Context(), prov, subj, "d")
			if err != nil {
				http.Error(w, "failed to scope results", http.StatusInternalServerError)
				return
			}

			params.RepoSQL, params.RepoArgs = repoSubquery(repoClause)
			params.ImageSQL, params.ImageArgs = imageSubquery(imageClause)
		}

		resp, err := vulnmetrics.LoadListPage(r.Context(), db, params)
		if err != nil {
			http.Error(w, "failed to load vulnerability list", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// VulnFacetsHandler returns the distinct sources + CVE years that
// currently appear in either the repo-side or image-side unified
// vuln view. The frontend uses these to populate filter dropdowns
// so they never show options that would yield zero results. Backed
// by vulnmetrics.LoadFacets which caches against the same summary
// version as LoadSummary — recomputes whenever new scan activity
// could have introduced new values.
//
// GET /api/vuln/facets
//
// Response: {"sources": ["grype", "osv"], "years": ["2024", "2023", ...]}
func VulnFacetsHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}
		facets, err := vulnmetrics.LoadFacets(r.Context(), db)
		if err != nil {
			http.Error(w, "failed to load vuln facets", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, facets)
	}
}

// VulnTrendHandler returns daily aggregate vulnerability counts for the last N days.
//
// GET /api/vuln/trend?days=30
//
// Two-tier dispatch matching VulnSummaryHandler: admins /
// global_readers / wildcard-repo callers hit the cached snapshot
// table (true historical backlog). Everyone else gets a per-request
// recompute scoped through their ACL — so a cluster operator's
// trend reflects only the vulns they actually have access to,
// matching the summary and list views on the same page.
func VulnTrendHandler(db *gorm.DB, _ *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireApproved(w, r) {
			return
		}

		days := 30
		if d := r.URL.Query().Get("days"); d != "" {
			if v, err := strconv.Atoi(d); err == nil && v > 0 && v <= 365 {
				days = v
			}
		}

		if hasUnrestrictedRepos(r) {
			rows, err := vulnmetrics.LoadTrend(r.Context(), db, days)
			if err != nil {
				http.Error(w, "failed to load vulnerability trend", http.StatusInternalServerError)
				return
			}
			writeJSON(w, http.StatusOK, rows)
			return
		}

		subj := acl.SubjectFromRequest(r)
		prov := acl.ProviderFromRequest(r)
		repoClause, err := acl.ReadableRepoClauseStrict(r.Context(), prov, subj, "r")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		imageClause, err := acl.ReadableImageClause(r.Context(), prov, subj, "d")
		if err != nil {
			http.Error(w, "failed to scope results", http.StatusInternalServerError)
			return
		}
		repoSQL, repoArgs := repoSubquery(repoClause)
		imageSQL, imageArgs := imageSubquery(imageClause)

		rows, err := vulnmetrics.LoadTrendScoped(r.Context(), db, days, repoSQL, repoArgs, imageSQL, imageArgs)
		if err != nil {
			http.Error(w, "failed to load vulnerability trend", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	}
}

// repoSubquery wraps a ReadableRepoClause fragment (aliased to "r")
// into a predicate against the vuln-view row's repo_id column.
func repoSubquery(c acl.Clause) (string, []any) {
	if c.Unrestricted {
		return "TRUE", nil
	}
	if c.Deny() {
		return "FALSE", nil
	}
	return fmt.Sprintf("v.repo_id IN (SELECT r.id FROM repos r WHERE %s)", c.SQL), c.Args
}

// imageSubquery wraps a ReadableImageClause fragment (aliased to "d")
// into a predicate against the image-vuln-view row's image_id column.
func imageSubquery(c acl.Clause) (string, []any) {
	if c.Unrestricted {
		return "TRUE", nil
	}
	if c.Deny() {
		return "FALSE", nil
	}
	return fmt.Sprintf("v.image_id IN (SELECT d.id FROM image_digests d WHERE %s)", c.SQL), c.Args
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

// parseFloatClamped parses a float query param, clamps to [lo, hi],
// and returns 0 on parse failure or empty input.
func parseFloatClamped(s string, lo, hi float64) float64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// splitCSV trims whitespace and drops empty entries from a comma-
// separated query param.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitUpper(s string) []string {
	parts := splitCSV(s)
	for i, p := range parts {
		parts[i] = strings.ToUpper(p)
	}
	return parts
}

func splitLower(s string) []string {
	parts := splitCSV(s)
	for i, p := range parts {
		parts[i] = strings.ToLower(p)
	}
	return parts
}
