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

// Reasons returns the ordered set of reason entries for an asset.
// Order matters: the first entry is the headline reason rendered next
// to the asset row; subsequent entries become a "more" expansion.
func Reasons(s Signals) []Reason {
	out := make([]Reason, 0, 4)

	if s.ActiveSecretCount > 0 {
		out = append(out, Reason{
			ID: "active_secret_leak",
			Fields: map[string]any{
				"count": s.ActiveSecretCount,
			},
		})
	}

	if s.KEVCount > 0 && s.InternetExposed {
		out = append(out, Reason{
			ID: "kev_and_exposed",
			Fields: map[string]any{
				"kev_count": s.KEVCount,
			},
		})
	} else if s.KEVCount > 0 {
		out = append(out, Reason{
			ID: "kev_present",
			Fields: map[string]any{
				"kev_count": s.KEVCount,
			},
		})
	}

	if s.EPSSMax >= 0.5 {
		out = append(out, Reason{
			ID: "epss_very_high",
			Fields: map[string]any{
				"epss_max": s.EPSSMax,
			},
		})
	} else if s.EPSSMax >= 0.1 {
		out = append(out, Reason{
			ID: "epss_elevated",
			Fields: map[string]any{
				"epss_max": s.EPSSMax,
			},
		})
	}

	if s.CriticalCount > 0 {
		out = append(out, Reason{
			ID: "critical_severity",
			Fields: map[string]any{
				"critical": s.CriticalCount,
				"has_fix":  s.HasFixForCritical,
			},
		})
	}

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

	return out
}
