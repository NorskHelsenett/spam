package llmadvisory

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/assetrisk"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// workerInterval is the scan cadence. Generation is cheap to skip
	// (one indexed anti-join) so a tight loop is fine; actual LLM
	// calls only happen for stale/missing rows.
	workerInterval = 5 * time.Minute

	// batchPerCycle caps LLM calls per scan so a cold start (hundreds
	// of findings, zero advisories) ramps up over a few cycles
	// instead of hammering the shared endpoint.
	batchPerCycle = 20

	// topVulnsInPayload bounds the CVE evidence handed to the model.
	topVulnsInPayload = 8
)

// Advisory is one asset_advisories row.
type Advisory struct {
	AssetType            string    `json:"asset_type"             gorm:"column:asset_type;primaryKey"`
	AssetID              string    `json:"asset_id"               gorm:"column:asset_id;primaryKey"`
	SignalsHash          string    `json:"-"                      gorm:"column:signals_hash"`
	Summary              string    `json:"summary,omitempty"      gorm:"column:summary"`
	SummaryModel         string    `json:"summary_model,omitempty" gorm:"column:summary_model"`
	Verdict              string    `json:"verdict,omitempty"      gorm:"column:verdict"`
	VerdictJustification string    `json:"verdict_justification,omitempty" gorm:"column:verdict_justification"`
	VerdictConfidence    float32   `json:"verdict_confidence,omitempty" gorm:"column:verdict_confidence"`
	VerdictMissingData   string    `json:"verdict_missing_data,omitempty" gorm:"column:verdict_missing_data"`
	VerdictModel         string    `json:"verdict_model,omitempty" gorm:"column:verdict_model"`
	GeneratedAt          time.Time `json:"generated_at"           gorm:"column:generated_at"`
}

func (Advisory) TableName() string { return "asset_advisories" }

// StartWorker runs the generation loop until ctx is cancelled. Call
// once from main after the asset_risk first-populate so the first
// cycle has signals to read.
func StartWorker(ctx context.Context, db *gorm.DB) {
	go func() {
		ticker := time.NewTicker(workerInterval)
		defer ticker.Stop()
		for {
			runCycle(ctx, db)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func runCycle(ctx context.Context, db *gorm.DB) {
	sumCfg, sumErr := GetSettings(ctx, db, UseCaseSummary)
	verCfg, verErr := GetSettings(ctx, db, UseCaseVerdict)
	if sumErr != nil || verErr != nil {
		return // table missing (pre-migration) or DB down — next tick retries
	}
	if !sumCfg.Enabled && !verCfg.Enabled {
		return
	}

	work := selectStale(ctx, db, urgentTiers)
	generated := 0
	for _, sig := range work {
		if generated >= batchPerCycle || ctx.Err() != nil {
			return
		}
		if generateOne(ctx, db, sumCfg, verCfg, sig) {
			generated++
		}
	}
}

// Backfill drains the advisory backlog for the fix_now tier in one
// pass — no per-cycle cap; this is the explicit admin "fill it now"
// path (ADVISORY_BACKFILL job). Returns how many assets produced
// output out of how many were stale.
func Backfill(ctx context.Context, db *gorm.DB, onProgress func(done, total int)) (int, int, error) {
	sumCfg, err := GetSettings(ctx, db, UseCaseSummary)
	if err != nil {
		return 0, 0, err
	}
	verCfg, err := GetSettings(ctx, db, UseCaseVerdict)
	if err != nil {
		return 0, 0, err
	}
	if !sumCfg.Enabled && !verCfg.Enabled {
		return 0, 0, errors.New("no LLM use case is enabled — turn one on under /admin/ai first")
	}

	work := selectStale(ctx, db, map[string]bool{assetrisk.TierFixNow: true})
	generated := 0
	for i, sig := range work {
		if ctx.Err() != nil {
			return generated, len(work), ctx.Err()
		}
		if generateOne(ctx, db, sumCfg, verCfg, sig) {
			generated++
		}
		if onProgress != nil {
			onProgress(i+1, len(work))
		}
	}
	return generated, len(work), nil
}

// generateOne runs the enabled use cases for a single asset and
// upserts the cache row. Returns true when at least one output was
// stored.
func generateOne(ctx context.Context, db *gorm.DB, sumCfg, verCfg Settings, sig assetrisk.Signals) bool {
	payload, err := BuildPayload(ctx, db, sig)
	if err != nil {
		log.Printf("llmadvisory: payload %s/%s: %v", sig.AssetType, sig.AssetID, err)
		return false
	}
	row := Advisory{
		AssetType:   sig.AssetType,
		AssetID:     sig.AssetID,
		SignalsHash: assetrisk.SignalsHash(sig),
		GeneratedAt: time.Now(),
	}
	if sumCfg.Enabled {
		if out, err := Chat(ctx, sumCfg, payload); err != nil {
			log.Printf("llmadvisory: summary %s: %v", sig.AssetSlug, err)
		} else {
			row.Summary = out
			row.SummaryModel = sumCfg.Model
		}
	}
	if verCfg.Enabled {
		if out, err := Chat(ctx, verCfg, payload); err != nil {
			log.Printf("llmadvisory: verdict %s: %v", sig.AssetSlug, err)
		} else if v, err := ParseVerdict(out); err != nil {
			log.Printf("llmadvisory: verdict parse %s: %v", sig.AssetSlug, err)
		} else {
			row.Verdict = v.Verdict
			row.VerdictJustification = v.Justification
			row.VerdictConfidence = v.Confidence
			row.VerdictMissingData = strings.Join(v.MissingData, "; ")
			row.VerdictModel = verCfg.Model
		}
	}
	if row.Summary == "" && row.Verdict == "" {
		return false // both calls failed — leave the old row in place
	}
	if err := db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "asset_type"}, {Name: "asset_id"}},
		UpdateAll: true,
	}).Create(&row).Error; err != nil {
		log.Printf("llmadvisory: upsert %s: %v", sig.AssetSlug, err)
		return false
	}
	return true
}

// urgentTiers is the background worker's scope: the tiers a team is
// actually asked to act on.
var urgentTiers = map[string]bool{
	assetrisk.TierFixNow:   true,
	assetrisk.TierThisWeek: true,
}

// selectStale returns image/repo signals whose tier is in tiers and
// whose cached advisory is missing or built from different signals.
// Tier() runs in Go to stay the single source of truth.
func selectStale(ctx context.Context, db *gorm.DB, tiers map[string]bool) []assetrisk.Signals {
	var rows []assetrisk.Signals
	if err := db.WithContext(ctx).Raw(`
		SELECT ar.*, COALESCE(d.digest, '') AS image_digest
		FROM asset_risk ar
		LEFT JOIN image_digests d ON ar.asset_type = 'image' AND ar.asset_id = d.id
		WHERE ar.asset_type IN ('image', 'repo')
	`).Scan(&rows).Error; err != nil {
		return nil
	}

	var existing []Advisory
	db.WithContext(ctx).Find(&existing)
	have := make(map[string]string, len(existing))
	for _, a := range existing {
		have[a.AssetType+"|"+a.AssetID] = a.SignalsHash
	}

	var out []assetrisk.Signals
	for _, sig := range rows {
		if !tiers[assetrisk.Tier(sig)] {
			continue
		}
		if have[sig.AssetType+"|"+sig.AssetID] == assetrisk.SignalsHash(sig) {
			continue
		}
		out = append(out, sig)
	}
	return out
}

// BuildPayload assembles the JSON evidence handed to the model: the
// asset's tier + signals, its top CVEs enriched with KEV/EPSS (VEX-
// filtered exactly like the tier counts), and its exposed hosts.
// Exported so the admin test bench can show precisely what the model
// sees.
func BuildPayload(ctx context.Context, db *gorm.DB, sig assetrisk.Signals) (string, error) {
	tier := assetrisk.Tier(sig)
	payload := map[string]any{
		"asset":      sig.AssetSlug,
		"asset_type": sig.AssetType,
		"tier":       tier,
		"signals": map[string]any{
			"critical_count":        sig.CriticalCount,
			"high_count":            sig.HighCount,
			"medium_count":          sig.MediumCount,
			"low_count":             sig.LowCount,
			"kev_count":             sig.KEVCount,
			"kev_fixable_count":     sig.KEVFixableCount,
			"kev_ransomware_count":  sig.KEVRansomwareCount,
			"epss_max":              sig.EPSSMax,
			"exposed_kev_count":     sig.ExposedKEVCount,
			"exposed_critical_count": sig.ExposedCriticalCount,
			"internet_exposed":      sig.InternetExposed,
			"cluster_count":         sig.ClusterCount,
			"exposed_cluster_count": sig.ExposedClusterCount,
			"active_secret_count":   sig.ActiveSecretCount,
			"has_fix_for_critical":  sig.HasFixForCritical,
			"has_fix_for_high":      sig.HasFixForHigh,
		},
	}
	if tier == assetrisk.TierDeprioritized {
		if rs := assetrisk.TierReasons(sig, tier); len(rs) > 0 {
			payload["deprioritized_reason"] = rs[0].ID
		}
	}

	if sig.AssetType == "image" {
		type vulnRow struct {
			ID       string  `json:"id"        gorm:"column:canonical_id"`
			Severity string  `json:"severity"  gorm:"column:severity"`
			Pkg      string  `json:"pkg"       gorm:"column:pkg_name"`
			Title    string  `json:"title"     gorm:"column:title"`
			Fixed    string  `json:"fixed"     gorm:"column:fixed_version"`
			EPSS     float32 `json:"epss"      gorm:"column:epss"`
			KEV      bool    `json:"kev"       gorm:"column:kev"`
		}
		var vulns []vulnRow
		if err := db.WithContext(ctx).Raw(`
			SELECT DISTINCT ON (COALESCE(vm.canonical_id, v.vuln_id))
				COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
				v.severity, v.pkg_name,
				LEFT(COALESCE(NULLIF(vm.title, ''), v.title), 160) AS title,
				v.fixed_version,
				COALESCE(e.score, 0)::real AS epss,
				(k.cve_id IS NOT NULL) AS kev
			FROM view_unified_image_vulnerabilities v
			LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
			LEFT JOIN epss_entries e ON e.cve_id = COALESCE(vm.canonical_id, v.vuln_id)
			LEFT JOIN cisa_kev_entries k ON k.cve_id = COALESCE(vm.canonical_id, v.vuln_id)
			WHERE v.image_id = ?
			  AND NOT EXISTS (
				SELECT 1
				FROM component_vex vex
				LEFT JOIN vuln_metadata vmx ON vmx.vuln_id = vex.vuln_id
				JOIN sbom_component_view sc ON sc.purl = vex.p_url
				JOIN sbom_bindings sb       ON sb.sbom_id     = sc.sbom_id
				                           AND sb.asset_type = 'IMAGE_DIGEST'
				WHERE vex.status IN ('not_affected', 'fixed')
				  AND COALESCE(vmx.canonical_id, vex.vuln_id)
				      = COALESCE(vm.canonical_id, v.vuln_id)
				  AND sb.asset_ref_id::text = v.image_id
			  )
			ORDER BY COALESCE(vm.canonical_id, v.vuln_id),
			         (k.cve_id IS NOT NULL) DESC, e.score DESC NULLS LAST
		`, sig.AssetID).Scan(&vulns).Error; err != nil {
			return "", err
		}
		// DISTINCT ON forces canonical_id ordering first; re-rank by
		// exploitation evidence and trim to the payload budget here.
		rank := func(v vulnRow) float64 {
			r := float64(v.EPSS)
			if v.KEV {
				r += 1
			}
			return r
		}
		for i := 0; i < len(vulns); i++ {
			for j := i + 1; j < len(vulns); j++ {
				if rank(vulns[j]) > rank(vulns[i]) {
					vulns[i], vulns[j] = vulns[j], vulns[i]
				}
			}
		}
		if len(vulns) > topVulnsInPayload {
			vulns = vulns[:topVulnsInPayload]
		}
		payload["top_vulns"] = vulns

		var hosts []string
		db.WithContext(ctx).Raw(
			`SELECT DISTINCT host FROM exposed_digests WHERE digest = ? ORDER BY host LIMIT 10`,
			sig.ImageDigest,
		).Scan(&hosts)
		payload["exposed_hosts"] = hosts
	} else {
		// Repos carry no per-CVE lazy detail yet — the structured
		// reasons are the evidence.
		payload["reasons"] = assetrisk.TierReasons(sig, tier)
	}

	b, err := json.Marshal(payload)
	return string(b), err
}

// LoadSignals fetches one asset's signals row — the admin test bench
// entry point.
func LoadSignals(ctx context.Context, db *gorm.DB, assetType, assetID string) (assetrisk.Signals, error) {
	var sig assetrisk.Signals
	err := db.WithContext(ctx).Raw(`
		SELECT ar.*, COALESCE(d.digest, '') AS image_digest
		FROM asset_risk ar
		LEFT JOIN image_digests d ON ar.asset_type = 'image' AND ar.asset_id = d.id
		WHERE ar.asset_type = ? AND ar.asset_id = ?
	`, assetType, assetID).Scan(&sig).Error
	if err == nil && sig.AssetID == "" {
		err = gorm.ErrRecordNotFound
	}
	return sig, err
}
