package dephealth

import (
	"context"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// staleAfter governs how long a row stays trusted before the next
// sweep tries to refresh it. Per-row TTL means most days the job
// fires and exits quickly with "0 rows refreshed" because nothing
// crossed the threshold.
const staleAfter = 7 * 24 * time.Hour

// RunResult summarises a sweep batch. Total is the number of unique
// (ecosystem, name) pairs the discovery query found; Refreshed is
// how many of those actually got new data (the rest were inside the
// staleAfter window or 304-cached).
type RunResult struct {
	Total     int `json:"total"`
	Refreshed int `json:"refreshed"`
	Failed    int `json:"failed"`
}

// Resolver is the per-ecosystem fetcher contract. Phase 3b plugs
// concrete implementations in (npm, PyPI, etc.); the processor
// itself doesn't need to know what's behind the interface, which
// keeps the framework testable in isolation.
type Resolver interface {
	// Ecosystem returns the registry name this resolver handles
	// ("npm", "pypi", "go", ...). Used to pick the right resolver
	// for a manifest_dependency row.
	Ecosystem() string

	// Fetch resolves the package's source repo URL + latest
	// version + any registry-side flags (deprecated, etc.). The
	// caller composes that with a separate provider-side fetch
	// (GitHub/GitLab) for activity metrics.
	Fetch(ctx context.Context, packageName string) (Resolution, error)
}

// Resolution is the registry-side answer for a single package.
type Resolution struct {
	SourceURL      string
	SourceProvider string // 'github' | 'gitlab' | ''
	LatestVersion  string
	IsDeprecated   bool
}

// ProviderFetcher resolves activity metadata from the source repo
// host (GitHub / GitLab). Implemented in Phase 3b.
type ProviderFetcher interface {
	Provider() string // 'github' | 'gitlab'
	Fetch(ctx context.Context, sourceURL string, etag string) (ProviderInfo, error)
}

// ProviderInfo is what a ProviderFetcher returns. NotModified
// indicates the upstream replied 304 and we should keep the cached
// row's existing data instead of overwriting.
type ProviderInfo struct {
	NotModified      bool
	Etag             string
	LastActivityAt   *time.Time
	Commits90d       int
	Stars            int
	OpenIssues       int
	IsArchived       bool
	SingleMaintainer bool
}

// Runner orchestrates a sweep. It's stateless across invocations —
// the registry of resolvers + the GitHub fetcher is constructed
// fresh per RunOnce call so config changes (token rotation, registry
// allow-list) take effect immediately.
type Runner struct {
	db        *gorm.DB
	resolvers map[string]Resolver
	provider  ProviderFetcher
}

func NewRunner(db *gorm.DB, resolvers []Resolver, provider ProviderFetcher) *Runner {
	idx := make(map[string]Resolver, len(resolvers))
	for _, r := range resolvers {
		idx[r.Ecosystem()] = r
	}
	return &Runner{db: db, resolvers: idx, provider: provider}
}

// RunOnce performs a single sweep: discover unique
// (ecosystem, package_name) pairs from manifest_dependencies, drop
// the ones whose dep_health row is fresh enough, fetch the rest,
// upsert. Bounded by maxRows so a cold start doesn't try to do
// everything at once; the next scheduled run picks up where this
// one left off.
func (r *Runner) RunOnce(ctx context.Context, maxRows int, progress func(written int)) (RunResult, error) {
	if r.db == nil {
		return RunResult{}, errors.New("dephealth: nil db")
	}
	if maxRows <= 0 {
		maxRows = 200
	}

	staleCutoff := time.Now().UTC().Add(-staleAfter)

	type discovered struct {
		Ecosystem   string
		PackageName string
	}
	var rows []discovered

	// Discovery: union of (a) ecosystems we have a resolver for and
	// (b) packages either missing a dep_health row or older than
	// staleAfter. Cap the result so a single run is bounded.
	if err := r.db.WithContext(ctx).Raw(`
		SELECT DISTINCT md.ecosystem, md.name AS package_name
		FROM manifest_dependencies md
		LEFT JOIN dep_health dh
		       ON dh.ecosystem = md.ecosystem
		      AND dh.package_name = md.name
		WHERE COALESCE(md.ecosystem, '') <> ''
		  AND COALESCE(md.name, '') <> ''
		  AND (dh.fetched_at IS NULL OR dh.fetched_at < ?)
		ORDER BY md.ecosystem, md.name
		LIMIT ?
	`, staleCutoff, maxRows).Scan(&rows).Error; err != nil {
		return RunResult{}, err
	}

	res := RunResult{Total: len(rows)}
	for _, row := range rows {
		if ctx.Err() != nil {
			break
		}
		resolver, ok := r.resolvers[row.Ecosystem]
		if !ok {
			// Ecosystem we don't yet support — record an error row so
			// we don't keep retrying every sweep, and skip.
			r.upsertError(ctx, row.Ecosystem, row.PackageName, "no resolver for ecosystem")
			res.Failed++
			continue
		}
		if err := r.refreshOne(ctx, resolver, row.Ecosystem, row.PackageName); err != nil {
			log.Printf("dephealth: refresh %s/%s: %v", row.Ecosystem, row.PackageName, err)
			res.Failed++
			continue
		}
		res.Refreshed++
		if progress != nil && res.Refreshed%25 == 0 {
			progress(res.Refreshed)
		}
	}
	if progress != nil {
		progress(res.Refreshed)
	}
	return res, nil
}

// refreshOne pulls registry + provider data for a single package
// and upserts the dep_health row. Provider lookup is best-effort —
// a missing or unparseable source URL doesn't fail the row, it just
// leaves the activity fields zero so the score function falls back
// to whatever the registry alone reveals.
func (r *Runner) refreshOne(ctx context.Context, resolver Resolver, ecosystem, name string) error {
	resolution, err := resolver.Fetch(ctx, name)
	if err != nil {
		r.upsertError(ctx, ecosystem, name, err.Error())
		return err
	}

	// Pull the existing row so we can pass its etag through and
	// preserve activity fields on a 304 from the provider.
	var existing Health
	_ = r.db.WithContext(ctx).
		Where("ecosystem = ? AND package_name = ?", ecosystem, name).
		First(&existing).Error

	row := Health{
		Ecosystem:        ecosystem,
		PackageName:      name,
		SourceURL:        resolution.SourceURL,
		SourceProvider:   resolution.SourceProvider,
		LatestVersion:    resolution.LatestVersion,
		IsArchived:       existing.IsArchived,
		IsDeprecated:     resolution.IsDeprecated,
		SingleMaintainer: existing.SingleMaintainer,
		LastActivityAt:   existing.LastActivityAt,
		Commits90d:       existing.Commits90d,
		Stars:            existing.Stars,
		OpenIssues:       existing.OpenIssues,
		Etag:             existing.Etag,
		FetchedAt:        time.Now().UTC(),
	}

	if r.provider != nil && resolution.SourceURL != "" && resolution.SourceProvider == r.provider.Provider() {
		info, perr := r.provider.Fetch(ctx, resolution.SourceURL, existing.Etag)
		if perr == nil {
			if !info.NotModified {
				row.LastActivityAt = info.LastActivityAt
				row.Commits90d = info.Commits90d
				row.Stars = info.Stars
				row.OpenIssues = info.OpenIssues
				row.IsArchived = info.IsArchived
				row.SingleMaintainer = info.SingleMaintainer
				row.Etag = info.Etag
			}
		} else {
			// Don't fail the whole row on a provider hiccup — leave
			// the previous activity fields in place and just record
			// the error message so admins can see what's stuck.
			row.Error = perr.Error()
		}
	}

	// Versions-behind: pick the most recent manifest_dependencies
	// version for this package and compute the delta vs. latest.
	// Most-recent rather than max-semver because we don't track all
	// versions across history — manifest_dependencies is bound to
	// the latest scan per repo.
	if row.LatestVersion != "" {
		var installed string
		_ = r.db.WithContext(ctx).Raw(`
			SELECT version
			FROM manifest_dependencies
			WHERE ecosystem = ? AND name = ? AND COALESCE(version, '') <> ''
			ORDER BY created_at DESC
			LIMIT 1
		`, ecosystem, name).Scan(&installed).Error
		if installed != "" {
			major, minor, patch := VersionsBehind(installed, row.LatestVersion)
			row.VersionsBehindMajor = major
			row.VersionsBehindMinor = minor
			row.VersionsBehindPatch = patch
		}
	}

	row.HealthScore = int16(Score(row))

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "ecosystem"}, {Name: "package_name"}},
			UpdateAll: true,
		}).
		Create(&row).Error
}

// upsertError records a per-package error so subsequent sweeps see
// the row as "fresh" (within staleAfter) and don't retry it on
// every tick. Falls back to the existing row's data — we never want
// an error path to wipe useful information that was successfully
// fetched in the past.
func (r *Runner) upsertError(ctx context.Context, ecosystem, name, message string) {
	row := Health{
		Ecosystem:   ecosystem,
		PackageName: name,
		Error:       message,
		FetchedAt:   time.Now().UTC(),
	}
	_ = r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "ecosystem"}, {Name: "package_name"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"error", "fetched_at",
			}),
		}).
		Create(&row).Error
}
