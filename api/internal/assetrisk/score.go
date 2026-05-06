// Package assetrisk turns asset_risk MV rows into ranked triage tiers.
//
// All scoring is pure-function on Signals so the Go layer can be unit-
// tested without a DB and the formulas can be tuned in one place. The
// metrics package handles cache + DB; this file is intentionally
// sql-free.
package assetrisk

import (
	"math"
	"time"
)

// Signals is the per-asset row sourced from the asset_risk MV. The JSON
// tags double as the wire format for /api/triage rows.
type Signals struct {
	AssetType string `json:"asset_type" gorm:"column:asset_type"`
	AssetID   string `json:"asset_id"   gorm:"column:asset_id"`
	AssetSlug string `json:"asset_slug" gorm:"column:asset_slug"`

	// Threat inputs.
	CriticalCount     int64   `json:"critical_count"        gorm:"column:critical_count"`
	HighCount         int64   `json:"high_count"            gorm:"column:high_count"`
	KEVCount          int64   `json:"kev_count"             gorm:"column:kev_count"`
	EPSSMax           float32 `json:"epss_max"              gorm:"column:epss_max"`
	HasFixForCritical bool    `json:"has_fix_for_critical"  gorm:"column:has_fix_for_critical"`
	ActiveSecretCount int64   `json:"active_secret_count"   gorm:"column:active_secret_count"`
	InternetExposed   bool    `json:"internet_exposed"      gorm:"column:internet_exposed"`

	// Trust inputs.
	SignedCommitsPct float32    `json:"signed_commits_pct" gorm:"column:signed_commits_pct"`
	ImageSigned      bool       `json:"image_signed"       gorm:"column:image_signed"`
	ScanAgeDays      int        `json:"scan_age_days"      gorm:"column:scan_age_days"`
	LastScanAt       *time.Time `json:"last_scan_at"       gorm:"column:last_scan_at"`
	HasSBOM          bool       `json:"has_sbom"           gorm:"column:has_sbom"`

	// Dep-health signals (Phase 3): worst_dep_health_score is the
	// minimum across the asset's direct deps (0..100, lower=worse;
	// 100 = "no observed issues" since assets without measured deps
	// shouldn't be penalised). Counts are direct-only because
	// transitives are typically unfixable from the asset being
	// scored.
	WorstDepHealthScore float32 `json:"worst_dep_health_score" gorm:"column:worst_dep_health_score"`
	ArchivedDepCount    int64   `json:"archived_dep_count"     gorm:"column:archived_dep_count"`
	DeprecatedDepCount  int64   `json:"deprecated_dep_count"   gorm:"column:deprecated_dep_count"`
}

// ThreatScore turns acute-risk signals into a 0..100 number where
// higher is worse. The weights are deliberately conservative — we'd
// rather have a clean queue than a perfectly ranked one.
func ThreatScore(s Signals) int {
	score := 0

	// Active leaked credentials are the most actionable signal.
	if s.ActiveSecretCount > 0 {
		score += 35
	}

	// KEV — confirmed exploited in the wild. Stacks with exposure.
	switch {
	case s.KEVCount > 0 && s.InternetExposed:
		score += 30
	case s.KEVCount > 0:
		score += 20
	}

	// EPSS — predicted exploitation. Tiered so the operational
	// threshold (≥10%) registers without false-precision.
	switch {
	case s.EPSSMax >= 0.5:
		score += 15
	case s.EPSSMax >= 0.1:
		score += 8
	}

	// Internet exposure alone (without a KEV) still raises the bar.
	if s.InternetExposed && s.KEVCount == 0 {
		score += 10
	}

	// Severity volume — log-shaped so a project with 50 criticals
	// doesn't dominate one with a single fix-available critical.
	if s.CriticalCount > 0 {
		score += int(math.Min(15, 5*math.Log10(float64(s.CriticalCount)+1)))
	}
	if s.HighCount > 0 {
		score += int(math.Min(8, 3*math.Log10(float64(s.HighCount)+1)))
	}

	return clamp(score, 0, 100)
}

// TrustScore turns custody-confidence signals into a 0..100 number
// where higher is better. Starts at 100 and deducts for missing
// posture; an asset with no acute issues but no signing/sbom can still
// land in the queue via the threshold check in Tier.
func TrustScore(s Signals) int {
	score := 100

	if !s.HasSBOM {
		score -= 25 // we have no visibility into deps at all
	}

	switch {
	case s.ScanAgeDays > 30:
		score -= 25
	case s.ScanAgeDays > 14:
		score -= 15
	}

	// Repo-side: commit-signing posture. Skip for non-repos.
	if s.AssetType == "repo" {
		switch {
		case s.SignedCommitsPct < 30:
			score -= 15
		case s.SignedCommitsPct < 70:
			score -= 8
		}
	}

	// Image-side: cosign verification. Until Phase 2 wires verify-
	// against-policy, every image lands here at -20 — the score is
	// honest about the dead-column gap rather than pretending images
	// are signed.
	if s.AssetType == "image" && !s.ImageSigned {
		score -= 20
	}

	// Dep-health: penalise assets that depend on archived /
	// deprecated packages or whose worst direct-dep health score is
	// low. Capped per signal so a repo with many archived deps gets
	// flagged but doesn't tank to F instantly.
	if s.ArchivedDepCount > 0 {
		penalty := int(s.ArchivedDepCount) * 10
		if penalty > 30 {
			penalty = 30
		}
		score -= penalty
	}
	if s.DeprecatedDepCount > 0 {
		penalty := int(s.DeprecatedDepCount) * 8
		if penalty > 25 {
			penalty = 25
		}
		score -= penalty
	}
	// Worst-package wins: if any direct dep is below the 40-score
	// threshold (abandoned, single-maintainer, etc.), apply a
	// modest fixed penalty regardless of count.
	if s.WorstDepHealthScore > 0 && s.WorstDepHealthScore < 40 {
		score -= 15
	}

	return clamp(score, 0, 100)
}

// TrustGrade maps a 0..100 trust score to a coarse letter so UI
// surfaces can render "Trust: B-" without inventing thresholds.
func TrustGrade(score int) string {
	switch {
	case score >= 95:
		return "A"
	case score >= 90:
		return "A-"
	case score >= 85:
		return "B+"
	case score >= 75:
		return "B"
	case score >= 70:
		return "B-"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// Tier classifies an asset into the page's three buckets, plus a
// "skip" bucket for rows below the actionable threshold so the watch
// list doesn't bloat with noise. The composite cutoff is
// threat + (100 - trust) >= 20, which means a perfectly clean asset
// (Threat 0, Trust 100) computes to 0 and falls out, while anything
// with even one warning crosses the line.
//
// Tiers are checked in priority order — fix_now wins over this_week
// when both predicates match.
const (
	TierFixNow   = "fix_now"
	TierThisWeek = "this_week"
	TierWatch    = "watch"
	TierSkip     = "skip"
)

// AttentionThreshold is the cutoff below which assets drop out of the
// watch tier. Tunable in one place so the API/UI stay consistent.
const AttentionThreshold = 20

func Tier(s Signals) string {
	if s.ActiveSecretCount > 0 {
		return TierFixNow
	}
	if s.KEVCount > 0 && s.InternetExposed {
		return TierFixNow
	}
	if s.KEVCount > 0 && s.HasFixForCritical {
		return TierFixNow
	}

	if s.KEVCount > 0 {
		return TierThisWeek
	}
	if s.CriticalCount > 0 && s.EPSSMax >= 0.10 {
		return TierThisWeek
	}
	if s.ScanAgeDays > 30 && (s.CriticalCount > 0 || s.HighCount > 0) {
		return TierThisWeek
	}
	if s.AssetType == "repo" && s.SignedCommitsPct < 50 && s.CriticalCount > 0 {
		return TierThisWeek
	}

	threat := ThreatScore(s)
	trust := TrustScore(s)
	if threat+(100-trust) >= AttentionThreshold {
		return TierWatch
	}
	return TierSkip
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
