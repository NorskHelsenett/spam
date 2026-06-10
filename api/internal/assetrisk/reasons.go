package assetrisk

// Reason is a structured "why is this asset in this tier" entry.
//
// ID is a stable template identifier (e.g. "kev_and_exposed") so the
// frontend can render a localized template; Fields holds the
// substitution data. Keeping the wire format structured rather than
// pre-rendered means a future LLM-narration step can read the same
// rows and produce a natural-language paragraph without forcing the
// API to make rendering decisions.
type Reason struct {
	ID     string         `json:"id"`
	Fields map[string]any `json:"fields,omitempty"`
}

// TierReasons returns the ordered vuln-driven reasons that justify the
// asset's tier. Order matters: the first entry is the headline reason
// rendered next to the asset row; subsequent entries become a "more"
// expansion. The order mirrors the Tier() rule bands so the headline
// always names the rule that fired.
//
// Posture signals are deliberately absent — they never move a tier, so
// listing them here would misrepresent why the asset needs attention.
// They live in ContextReasons.
func TierReasons(s Signals, tier string) []Reason {
	out := make([]Reason, 0, 4)

	if s.ActiveSecretCount > 0 {
		out = append(out, Reason{
			ID: "active_secret_leak",
			Fields: map[string]any{
				"count": s.ActiveSecretCount,
			},
		})
	}

	// KEV reasons, most specific first. kev_present only fires when
	// no sharper KEV reason already explains the row.
	kevSpecific := false
	if s.ExposedKEVCount > 0 {
		kevSpecific = true
		out = append(out, Reason{
			ID: "kev_and_exposed",
			Fields: map[string]any{
				"exposed_kev_count": s.ExposedKEVCount,
			},
		})
	}
	if s.KEVRansomwareCount > 0 {
		kevSpecific = true
		out = append(out, Reason{
			ID: "kev_ransomware",
			Fields: map[string]any{
				"count": s.KEVRansomwareCount,
			},
		})
	}
	if s.KEVCount > 0 && s.KEVDuePassed {
		kevSpecific = true
		out = append(out, Reason{ID: "kev_overdue"})
	}
	if s.KEVFixableCount > 0 {
		kevSpecific = true
		out = append(out, Reason{
			ID: "kev_fixable",
			Fields: map[string]any{
				"count": s.KEVFixableCount,
			},
		})
	}
	if s.KEVCount > 0 && !kevSpecific {
		out = append(out, Reason{
			ID: "kev_present",
			Fields: map[string]any{
				"kev_count": s.KEVCount,
			},
		})
	}

	if s.EPSSMax >= EPSSVeryHigh {
		out = append(out, Reason{
			ID: "epss_very_high",
			Fields: map[string]any{
				"epss_max": s.EPSSMax,
			},
		})
	} else if s.EPSSMax >= EPSSElevated {
		out = append(out, Reason{
			ID: "epss_elevated",
			Fields: map[string]any{
				"epss_max": s.EPSSMax,
			},
		})
	}

	if s.ExposedCriticalCount > 0 {
		out = append(out, Reason{
			ID: "exposed_critical",
			Fields: map[string]any{
				"critical": s.ExposedCriticalCount,
			},
		})
	}

	if s.CriticalCount > 0 && s.HasFixForCritical {
		out = append(out, Reason{
			ID: "critical_fixable",
			Fields: map[string]any{
				"critical": s.CriticalCount,
			},
		})
	}

	// Deprioritized rows headline the reason they were parked — the
	// D1..D4 decision is prepended so it always renders as the first
	// pill, ahead of any incidental signal (e.g. elevated EPSS on a
	// medium-only row).
	if tier == TierDeprioritized {
		var dep Reason
		switch {
		case (s.CriticalCount > 0 && !s.HasFixForCritical) ||
			(s.HighCount > 0 && !s.HasFixForHigh):
			dep = Reason{
				ID: "no_fix_available",
				Fields: map[string]any{
					"critical": s.CriticalCount,
					"high":     s.HighCount,
				},
			}
		case s.CriticalCount > 0 || s.HighCount > 0:
			dep = Reason{
				ID: "low_epss_not_exposed",
				Fields: map[string]any{
					"epss_max": s.EPSSMax,
					"critical": s.CriticalCount,
					"high":     s.HighCount,
				},
			}
		case s.MediumCount > 0 || s.LowCount > 0:
			dep = Reason{
				ID: "low_severity_only",
				Fields: map[string]any{
					"medium": s.MediumCount,
					"low":    s.LowCount,
				},
			}
		default:
			dep = Reason{
				ID: "no_scan_data",
				Fields: map[string]any{
					"scan_age_days": s.ScanAgeDays,
				},
			}
		}
		out = append([]Reason{dep}, out...)
	}

	return out
}

// ContextReasons returns the posture signals as display-only context.
// These never influence Tier() — the UI renders them separately
// ("posture — does not affect tier") so the advisory's urgency claims
// stay credible.
func ContextReasons(s Signals) []Reason {
	out := make([]Reason, 0, 4)

	if s.ScanAgeDays > 30 {
		out = append(out, Reason{
			ID: "scan_stale",
			Fields: map[string]any{
				"days": s.ScanAgeDays,
			},
		})
	}

	if s.AssetType == "repo" && s.SignedCommitsPct < 50 {
		out = append(out, Reason{
			ID: "low_commit_signing",
			Fields: map[string]any{
				"signed_pct": s.SignedCommitsPct,
			},
		})
	}

	if s.AssetType == "image" && !s.ImageSigned {
		out = append(out, Reason{
			ID: "image_unsigned",
		})
	}

	if !s.HasSBOM {
		out = append(out, Reason{
			ID: "no_sbom",
		})
	}

	if s.ArchivedDepCount > 0 {
		out = append(out, Reason{
			ID: "archived_deps",
			Fields: map[string]any{
				"count": s.ArchivedDepCount,
			},
		})
	}
	if s.DeprecatedDepCount > 0 {
		out = append(out, Reason{
			ID: "deprecated_deps",
			Fields: map[string]any{
				"count": s.DeprecatedDepCount,
			},
		})
	}
	if s.WorstDepHealthScore > 0 && s.WorstDepHealthScore < 40 {
		out = append(out, Reason{
			ID: "low_dep_health",
			Fields: map[string]any{
				"worst_score": s.WorstDepHealthScore,
			},
		})
	}

	if s.MajorBehindDepCount > 0 {
		out = append(out, Reason{
			ID: "major_behind",
			Fields: map[string]any{
				"count":     s.MajorBehindDepCount,
				"max_major": s.MaxMajorBehind,
			},
		})
	}

	return out
}
