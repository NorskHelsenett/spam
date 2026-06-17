package assetrisk

import (
	"testing"
	"time"
)

func ts() *time.Time {
	t := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	return &t
}

// scanned returns a baseline asset with scan visibility and no
// findings — the canonical TierSkip row. Tests mutate it per case.
func scanned() Signals {
	return Signals{
		AssetType:  "image",
		HasSBOM:    true,
		LastScanAt: ts(),
	}
}

func TestTierMatrix(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Signals)
		want string
	}{
		// fix_now
		{"F1 active secret", func(s *Signals) {
			s.ActiveSecretCount = 1
		}, TierFixNow},
		{"F2 KEV on exposed digest", func(s *Signals) {
			s.KEVCount = 1
			s.ExposedKEVCount = 1
			s.InternetExposed = true
		}, TierFixNow},
		{"F3 ransomware KEV with fix", func(s *Signals) {
			s.KEVCount = 1
			s.KEVRansomwareCount = 1
			s.KEVFixableCount = 1
		}, TierFixNow},
		{"F4 exposed critical with very high EPSS", func(s *Signals) {
			s.CriticalCount = 1
			s.ExposedCriticalCount = 1
			s.ExposedEPSSMax = 0.6
			s.EPSSMax = 0.6
			s.InternetExposed = true
		}, TierFixNow},

		// this_week
		{"W1 KEV with fix, not exposed", func(s *Signals) {
			s.KEVCount = 1
			s.KEVFixableCount = 1
		}, TierThisWeek},
		{"W2 KEV past due date, no fix", func(s *Signals) {
			s.KEVCount = 1
			s.KEVDuePassed = true
		}, TierThisWeek},
		{"W3 very high EPSS on critical, not exposed", func(s *Signals) {
			s.CriticalCount = 1
			s.EPSSMax = 0.7
		}, TierThisWeek},
		{"W3 very high EPSS on high, not exposed", func(s *Signals) {
			s.HighCount = 2
			s.EPSSMax = 0.55
		}, TierThisWeek},
		{"W4 exposed critical, elevated EPSS, non-KEV", func(s *Signals) {
			s.CriticalCount = 1
			s.ExposedCriticalCount = 1
			s.ExposedEPSSMax = 0.4
			s.EPSSMax = 0.4
			s.InternetExposed = true
		}, TierThisWeek},

		// watch
		{"T1 KEV without fix, not exposed, not overdue", func(s *Signals) {
			s.KEVCount = 1
		}, TierWatch},
		{"T2 elevated EPSS on critical", func(s *Signals) {
			s.CriticalCount = 1
			s.EPSSMax = 0.2
		}, TierWatch},
		{"T3 very high EPSS on medium-only impact", func(s *Signals) {
			s.MediumCount = 3
			s.EPSSMax = 0.55
		}, TierWatch},
		{"T4 fixable critical, low EPSS, not exposed", func(s *Signals) {
			s.CriticalCount = 2
			s.HasFixForCritical = true
			s.EPSSMax = 0.01
		}, TierWatch},
		{"T5 exposed high, nothing predicts exploitation", func(s *Signals) {
			s.HighCount = 1
			s.InternetExposed = true
		}, TierWatch},

		// deprioritized
		{"D1 critical without fix, low EPSS, unexposed", func(s *Signals) {
			s.CriticalCount = 1
			s.EPSSMax = 0.02
		}, TierDeprioritized},
		{"D2 fixable high, low EPSS, unexposed", func(s *Signals) {
			s.HighCount = 1
			s.HasFixForHigh = true
			s.EPSSMax = 0.05
		}, TierDeprioritized},
		{"D3 medium/low findings only", func(s *Signals) {
			s.MediumCount = 4
			s.LowCount = 10
		}, TierDeprioritized},
		{"D4 never scanned", func(s *Signals) {
			s.HasSBOM = false
			s.LastScanAt = nil
			s.ScanAgeDays = 999
		}, TierDeprioritized},

		// skip + posture isolation: posture signals alone must never
		// raise a tier above skip.
		{"clean scanned asset skips", func(s *Signals) {}, TierSkip},
		{"posture-only signals still skip", func(s *Signals) {
			s.ScanAgeDays = 90
			s.SignedCommitsPct = 0
			s.ImageSigned = false
			s.ArchivedDepCount = 5
			s.DeprecatedDepCount = 3
			s.WorstDepHealthScore = 10
			s.MajorBehindDepCount = 6
		}, TierSkip},
		{"stale scan with high vuln no longer escalates past watch", func(s *Signals) {
			s.HighCount = 1
			s.ScanAgeDays = 60
			s.InternetExposed = true
		}, TierWatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scanned()
			tc.mut(&s)
			if got := Tier(s); got != tc.want {
				t.Fatalf("Tier() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTierReasonsHeadlineMatchesDeprioritizedRule(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Signals)
		want string
	}{
		{"no fix available", func(s *Signals) {
			s.CriticalCount = 1
		}, "no_fix_available"},
		{"low epss not exposed", func(s *Signals) {
			s.HighCount = 1
			s.HasFixForHigh = true
		}, "low_epss_not_exposed"},
		{"low severity only", func(s *Signals) {
			s.LowCount = 2
		}, "low_severity_only"},
		{"no scan data", func(s *Signals) {
			s.HasSBOM = false
			s.LastScanAt = nil
		}, "no_scan_data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scanned()
			tc.mut(&s)
			tier := Tier(s)
			if tier != TierDeprioritized {
				t.Fatalf("Tier() = %q, want deprioritized", tier)
			}
			rs := TierReasons(s, tier)
			if len(rs) == 0 {
				t.Fatal("TierReasons() returned no reasons")
			}
			if rs[0].ID != tc.want {
				t.Fatalf("deprioritized headline = %q, want %q", rs[0].ID, tc.want)
			}
		})
	}
}

func TestReasonSeparation(t *testing.T) {
	s := scanned()
	s.KEVCount = 1
	s.KEVFixableCount = 1
	s.ScanAgeDays = 45
	s.HasSBOM = false
	s.ArchivedDepCount = 2

	postureIDs := map[string]bool{
		"scan_stale": true, "low_commit_signing": true, "image_unsigned": true,
		"no_sbom": true, "archived_deps": true, "deprecated_deps": true,
		"low_dep_health": true, "major_behind": true,
	}

	for _, r := range TierReasons(s, Tier(s)) {
		if postureIDs[r.ID] {
			t.Errorf("posture reason %q leaked into TierReasons", r.ID)
		}
	}

	ctx := ContextReasons(s)
	seen := map[string]bool{}
	for _, r := range ctx {
		seen[r.ID] = true
		if !postureIDs[r.ID] {
			t.Errorf("non-posture reason %q in ContextReasons", r.ID)
		}
	}
	for _, want := range []string{"scan_stale", "image_unsigned", "no_sbom", "archived_deps"} {
		if !seen[want] {
			t.Errorf("ContextReasons missing %q", want)
		}
	}
}

func TestKEVPresentOnlyWhenNoSpecificKEVReason(t *testing.T) {
	s := scanned()
	s.KEVCount = 2
	s.KEVFixableCount = 1

	for _, r := range TierReasons(s, Tier(s)) {
		if r.ID == "kev_present" {
			t.Error("kev_present emitted alongside kev_fixable")
		}
	}

	s = scanned()
	s.KEVCount = 1 // no fix, not exposed, not overdue
	var found bool
	for _, r := range TierReasons(s, Tier(s)) {
		if r.ID == "kev_present" {
			found = true
		}
	}
	if !found {
		t.Error("kev_present missing for bare-KEV row")
	}
}

func TestRankTriageBandOrdering(t *testing.T) {
	row := func(slug string, mut func(*Signals)) TriageRow {
		s := scanned()
		s.AssetSlug = slug
		mut(&s)
		return TriageRow{Signals: s}
	}

	rows := []TriageRow{
		row("e-low-epss", func(s *Signals) { s.EPSSMax = 0.05; s.CriticalCount = 1 }),
		row("d-high-epss", func(s *Signals) { s.EPSSMax = 0.9; s.CriticalCount = 1 }),
		row("c-kev", func(s *Signals) { s.KEVCount = 1; s.EPSSMax = 0.2 }),
		row("b-exposed-kev", func(s *Signals) { s.KEVCount = 1; s.ExposedKEVCount = 1; s.EPSSMax = 0.1 }),
		row("a-secret", func(s *Signals) { s.ActiveSecretCount = 1 }),
	}
	// Shuffle-resistant: input is reverse of expected.
	rankTriage(rows)

	want := []string{"a-secret", "b-exposed-kev", "c-kev", "d-high-epss", "e-low-epss"}
	for i, w := range want {
		if rows[i].AssetSlug != w {
			t.Fatalf("rank[%d] = %q, want %q", i, rows[i].AssetSlug, w)
		}
	}

	// EPSS desc within the same band, slug as final tie-break.
	rows = []TriageRow{
		row("b", func(s *Signals) { s.KEVCount = 1; s.EPSSMax = 0.3 }),
		row("a", func(s *Signals) { s.KEVCount = 1; s.EPSSMax = 0.3 }),
		row("c", func(s *Signals) { s.KEVCount = 1; s.EPSSMax = 0.8 }),
	}
	rankTriage(rows)
	for i, w := range []string{"c", "a", "b"} {
		if rows[i].AssetSlug != w {
			t.Fatalf("epss rank[%d] = %q, want %q", i, rows[i].AssetSlug, w)
		}
	}
}
