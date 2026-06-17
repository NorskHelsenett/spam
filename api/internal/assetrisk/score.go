// Package assetrisk turns asset_risk MV rows into ranked triage tiers.
//
// All scoring is pure-function on Signals so the Go layer can be unit-
// tested without a DB and the formulas can be tuned in one place. The
// metrics package handles cache + DB; this file is intentionally
// sql-free.
package assetrisk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

// Signals is the per-asset row sourced from the asset_risk MV. The JSON
// tags double as the wire format for /api/triage rows.
type Signals struct {
	AssetType string `json:"asset_type" gorm:"column:asset_type"`
	AssetID   string `json:"asset_id"   gorm:"column:asset_id"`
	AssetSlug string `json:"asset_slug" gorm:"column:asset_slug"`
	ImageDigest string `json:"image_digest,omitempty" gorm:"column:image_digest"`

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

	// Versions-behind: the worst major-version lag across the
	// asset's direct deps, plus the count of direct deps that are
	// at least one major behind. Captures "stale upgrade backlog"
	// as a posture signal even when no individual dep is archived.
	MaxMajorBehind      int   `json:"max_major_behind"        gorm:"column:max_major_behind"`
	MajorBehindDepCount int64 `json:"major_behind_dep_count"  gorm:"column:major_behind_dep_count"`

	// Full severity spectrum + fixability beyond criticals, so the
	// deprioritized bucket can explain itself ("medium/low only",
	// "no fix available").
	MediumCount   int64 `json:"medium_count"      gorm:"column:medium_count"`
	LowCount      int64 `json:"low_count"         gorm:"column:low_count"`
	HasFixForHigh bool  `json:"has_fix_for_high"  gorm:"column:has_fix_for_high"`

	// KEV detail: fixability, CISA ransomware flag, BOD 22-01 due
	// date, and the worst EPSS among KEV vulns.
	KEVFixableCount    int64   `json:"kev_fixable_count"    gorm:"column:kev_fixable_count"`
	KEVRansomwareCount int64   `json:"kev_ransomware_count" gorm:"column:kev_ransomware_count"`
	KEVDuePassed       bool    `json:"kev_due_passed"       gorm:"column:kev_due_passed"`
	KEVEPSSMax         float32 `json:"kev_epss_max"         gorm:"column:kev_epss_max"`

	// Exposure-scoped vuln signals: only vulns carried by a digest
	// that is itself internet-reachable. Exact for images (digest =
	// exposure unit), pre-aggregated per cluster.
	ExposedKEVCount      int64   `json:"exposed_kev_count"      gorm:"column:exposed_kev_count"`
	ExposedCriticalCount int64   `json:"exposed_critical_count" gorm:"column:exposed_critical_count"`
	ExposedEPSSMax       float32 `json:"exposed_epss_max"       gorm:"column:exposed_epss_max"`

	// Deployment spread (images only): one rebuild, ClusterCount
	// redeploys, ExposedClusterCount of which face the internet.
	ClusterCount        int64 `json:"cluster_count"         gorm:"column:cluster_count"`
	ExposedClusterCount int64 `json:"exposed_cluster_count" gorm:"column:exposed_cluster_count"`
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

	// KEV — confirmed exploited in the wild. Stacks with exposure;
	// ExposedKEVCount is exact (the KEV vuln itself sits on an
	// exposed digest), not the old asset-level conjunction.
	switch {
	case s.ExposedKEVCount > 0:
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

	// Major-version upgrade backlog. Each direct dep ≥1 major
	// version behind is -3, capped at -15 so a project carrying
	// six stale deps doesn't lose more Trust than one with one.
	// Patch + minor lag aren't penalised — they're noise across a
	// real codebase and adding them tanks every long-lived repo.
	if s.MajorBehindDepCount > 0 {
		penalty := int(s.MajorBehindDepCount) * 3
		if penalty > 15 {
			penalty = 15
		}
		score -= penalty
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

// Tier classifies an asset into the page's buckets. The rules are
// purely vuln-driven — KEV (confirmed exploited in the wild), EPSS
// (predicted exploitation), internet exposure, severity, fixability,
// plus active leaked secrets. Posture signals (SBOM, signing, scan
// age, dep health) never move an asset between tiers; they surface
// through TrustScore/ContextReasons as display-only context.
//
// Tier meanings:
//
//	fix_now       actively exploited or near-certain exploitation,
//	              and reachable from the internet / already leaking.
//	this_week     confirmed or highly likely exploitation, but not
//	              internet-reachable — a controlled patch window is
//	              acceptable.
//	watch         real risk with no urgency signal; normal patch
//	              cadence. Conditions can escalate it (a KEV fix
//	              shipping moves T1 → W1).
//	deprioritized findings exist (or scan data is missing) but none
//	              warrant action — shown with an explicit reason so
//	              "ignore this" is a decision, not an omission.
//	skip          scanned and clean; not returned at all.
//
// Tiers are checked in priority order — first match wins.
const (
	TierFixNow        = "fix_now"
	TierThisWeek      = "this_week"
	TierWatch         = "watch"
	TierDeprioritized = "deprioritized"
	TierSkip          = "skip"
)

// EPSS bands. FIRST suggests ~0.1 as the operational "elevated"
// cutoff (top ~5% of CVEs); 0.5 is near-certain weaponization
// territory (top ~0.5%) — rare enough to never cause false urgency.
const (
	EPSSVeryHigh = 0.5
	EPSSElevated = 0.1
)

func Tier(s Signals) string {
	// fix_now — exploited or near-certain, and reachable / leaking.
	if s.ActiveSecretCount > 0 {
		return TierFixNow // F1: live credential = breach-in-waiting
	}
	if s.ExposedKEVCount > 0 {
		return TierFixNow // F2: KEV on an internet-exposed digest
	}
	if s.KEVRansomwareCount > 0 && s.KEVFixableCount > 0 {
		return TierFixNow // F3: ransomware-campaign KEV with a patch
	}
	if s.ExposedCriticalCount > 0 && s.ExposedEPSSMax >= EPSSVeryHigh {
		return TierFixNow // F4: exposed critical, ≥50% exploit odds
	}

	// this_week — confirmed/likely exploitation, not reachable.
	if s.KEVFixableCount > 0 {
		return TierThisWeek // W1: exploited in the wild, patch exists
	}
	if s.KEVCount > 0 && s.KEVDuePassed {
		return TierThisWeek // W2: KEV past its CISA BOD 22-01 due date
	}
	if s.EPSSMax >= EPSSVeryHigh && (s.CriticalCount > 0 || s.HighCount > 0) {
		return TierThisWeek // W3: very likely exploitation, severe impact
	}
	if s.ExposedCriticalCount > 0 && s.ExposedEPSSMax >= EPSSElevated {
		return TierThisWeek // W4: exposed critical, elevated exploit odds
	}

	// watch — real risk, no urgency signal.
	if s.KEVCount > 0 {
		return TierWatch // T1: KEV with no fix, not exposed, not overdue
	}
	if s.EPSSMax >= EPSSElevated && (s.CriticalCount > 0 || s.HighCount > 0) {
		return TierWatch // T2: elevated exploit odds, severe impact
	}
	if s.EPSSMax >= EPSSVeryHigh {
		return TierWatch // T3: very high EPSS on medium/low-only impact
	}
	if s.CriticalCount > 0 && s.HasFixForCritical {
		return TierWatch // T4: fixable criticals — routine patching
	}
	if s.InternetExposed && (s.CriticalCount > 0 || s.HighCount > 0) {
		return TierWatch // T5: exposed and severe, nothing predicts exploit
	}

	// deprioritized — explicitly not worth acting on, with a reason.
	if s.CriticalCount > 0 || s.HighCount > 0 || s.MediumCount > 0 || s.LowCount > 0 {
		return TierDeprioritized
	}
	if !s.HasSBOM || s.LastScanAt == nil {
		return TierDeprioritized // visibility gap — "complete" stays honest
	}

	return TierSkip
}

// SignalsHash fingerprints the tier-relevant signals of an asset.
// LLM-generated advisories are cached against this hash so a summary
// regenerates only when something that could change the advisory
// actually changed. Scan-age / posture fields are deliberately
// excluded — they drift daily without altering the vuln story.
func SignalsHash(s Signals) string {
	key := fmt.Sprintf("v1|%s|%s|%d|%d|%d|%d|%d|%d|%d|%t|%t|%t|%.4f|%.4f|%.4f|%d|%t|%d|%d",
		s.AssetType, s.AssetID,
		s.CriticalCount, s.HighCount, s.MediumCount, s.LowCount,
		s.KEVCount, s.KEVFixableCount, s.KEVRansomwareCount,
		s.KEVDuePassed, s.HasFixForCritical, s.HasFixForHigh,
		s.EPSSMax, s.KEVEPSSMax, s.ExposedEPSSMax,
		s.ExposedKEVCount, s.InternetExposed,
		s.ClusterCount, s.ExposedClusterCount,
	)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
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
