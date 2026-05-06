// Package dephealth manages third-party library health metadata
// fetched from public registries (npm, PyPI, Go modules, RubyGems,
// crates, NuGet, Maven Central) and their source-repo providers
// (GitHub, GitLab).
//
// The data feeds Trust scoring on /app's triage view: assets that
// depend on archived, deprecated, single-maintainer, or many-
// versions-behind packages get penalised in proportion. Daily-ish
// refresh via FETCH_DEP_HEALTH job; ETag/If-None-Match keeps the
// steady-state HTTP load tiny.
package dephealth

import "time"

// Health is the GORM-mapped row of the dep_health table. PK is the
// composite (Ecosystem, PackageName) — same package name across
// ecosystems is genuinely a different package (e.g. PyPI `requests`
// vs npm `requests` are unrelated), so we don't dedupe across them.
type Health struct {
	Ecosystem        string    `gorm:"primaryKey;column:ecosystem"`
	PackageName      string    `gorm:"primaryKey;column:package_name"`
	SourceURL        string    `gorm:"column:source_url"`
	SourceProvider   string    `gorm:"column:source_provider"` // 'github' | 'gitlab' | ''
	LatestVersion    string    `gorm:"column:latest_version"`
	LastActivityAt   *time.Time `gorm:"column:last_activity_at"`
	Commits90d       int       `gorm:"column:commits_90d"`
	Stars            int       `gorm:"column:stars"`
	OpenIssues       int       `gorm:"column:open_issues"`
	IsArchived       bool      `gorm:"column:is_archived"`
	IsDeprecated     bool      `gorm:"column:is_deprecated"`
	SingleMaintainer bool      `gorm:"column:single_maintainer"`
	HealthScore      int16     `gorm:"column:health_score"`
	FetchedAt        time.Time `gorm:"column:fetched_at"`
	Etag             string    `gorm:"column:etag"`
	Error            string    `gorm:"column:error"`
}

func (Health) TableName() string { return "dep_health" }

// Score collapses the raw health signals into a 0..100 number where
// higher is better. The Trust formula in assetrisk consumes this and
// the boolean flags directly; keeping the score function pure means
// it's testable without a DB and tuneable in one place.
//
// Refusing to score (returning 0) when the row carries an error
// means Trust won't penalise a transient registry outage; only
// observed health information should move the score.
func Score(h Health) int {
	if h.Error != "" {
		return 0
	}
	if h.IsArchived || h.IsDeprecated {
		return 10
	}

	score := 100

	// Activity recency — packages with no commits in a year are
	// effectively unmaintained even if not formally archived.
	if h.LastActivityAt != nil {
		days := int(time.Since(*h.LastActivityAt).Hours() / 24)
		switch {
		case days > 365:
			score -= 40
		case days > 180:
			score -= 20
		case days > 90:
			score -= 10
		}
	} else {
		// No activity recorded — soft penalty so missing data isn't
		// silently treated as fine, but isn't as bad as confirmed
		// abandonment.
		score -= 25
	}

	if h.SingleMaintainer {
		score -= 15
	}

	// Recent commit volume — a sliding window proxy for
	// "is anyone actually touching this".
	if h.Commits90d == 0 && h.LastActivityAt != nil {
		score -= 10
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
