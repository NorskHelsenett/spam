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

	// Advisory payload budgets. The endpoint carries ~256k context,
	// so triage-driving vulns ship with their full description while
	// the remainder ships as one metadata line each — bounded so a
	// 3000-CVE base image stays well inside the window.
	advisoryTriageVulnCap = 60
	advisoryOtherVulnCap  = 500
	advisoryDescCap       = 2000
	advisoryHostCap       = 20
)

// exposedHost is one exposed-host row in the model payload: the
// public hostname, everything host_exposure knows about how it is
// served — cluster, namespace, route kind, TLS, the ingress
// load-balancer IPs, ingress class, environment label — plus the
// hostresolve worker's verdict: the DNS-resolved addresses and the
// internal/external/unresolvable/pending classification.
type exposedHost struct {
	Host           string `json:"host"                    gorm:"column:host"`
	Cluster        string `json:"cluster"                 gorm:"column:cluster"`
	Namespace      string `json:"namespace"               gorm:"column:namespace"`
	Kind           string `json:"kind"                    gorm:"column:kind"`
	TLS            bool   `json:"tls"                     gorm:"column:tls"`
	LBIPs          string `json:"lb_ips,omitempty"        gorm:"column:lb_ips"`
	IngressClass   string `json:"ingress_class,omitempty" gorm:"column:ingress_class"`
	Environment    string `json:"environment,omitempty"   gorm:"column:environment"`
	ResolvedIPs    string `json:"resolved_ips,omitempty"  gorm:"column:resolved_ips"`
	Classification string `json:"classification"          gorm:"column:classification"`
}

// exposedHostsQuery feeds both payload builders so the summary and
// the chat ground on the same exposure detail. host_resolution is
// the hostresolve worker's precomputed DNS verdict; a host it has
// not reached yet reads as pending.
const exposedHostsQuery = `
	SELECT DISTINCT ed.host,
	       COALESCE(he.cluster, ed.cluster_id) AS cluster,
	       ed.namespace,
	       ed.exposure_kind AS kind,
	       COALESCE(he.tls, false) AS tls,
	       COALESCE(he.lb_ips, '') AS lb_ips,
	       COALESCE(he.ingress_class, '') AS ingress_class,
	       COALESCE(he.environment, '') AS environment,
	       COALESCE(hr.ips, '') AS resolved_ips,
	       COALESCE(hr.classification, 'pending') AS classification
	FROM exposed_digests ed
	LEFT JOIN host_exposure he
	  ON he.cluster_id = ed.cluster_id AND he.namespace = ed.namespace
	 AND he.host = ed.host AND he.kind = ed.exposure_kind AND he.name = ed.exposure_name
	LEFT JOIN host_resolution hr ON hr.host = ed.host
	WHERE ed.digest = ? ORDER BY ed.host LIMIT ?`

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
// asset's tier + signals, its CVEs (VEX-filtered exactly like the
// tier counts), and its exposed hosts. Vulns that drive the tier —
// KEV, elevated EPSS, criticals, highs on an exposed asset — carry
// their full description; the rest ship as one metadata line each
// (id, title, CVSS, EPSS, KEV, fix) so the model sees the whole
// picture without the long tail dominating the context window.
// Exported so the admin test bench can show precisely what the model
// sees.
func BuildPayload(ctx context.Context, db *gorm.DB, sig assetrisk.Signals) (string, error) {
	tier := assetrisk.Tier(sig)
	payload := map[string]any{
		"asset":      sig.AssetSlug,
		"asset_type": sig.AssetType,
		"tier":       tier,
		"signals": map[string]any{
			"critical_count":         sig.CriticalCount,
			"high_count":             sig.HighCount,
			"medium_count":           sig.MediumCount,
			"low_count":              sig.LowCount,
			"kev_count":              sig.KEVCount,
			"kev_fixable_count":      sig.KEVFixableCount,
			"kev_ransomware_count":   sig.KEVRansomwareCount,
			"epss_max":               sig.EPSSMax,
			"exposed_kev_count":      sig.ExposedKEVCount,
			"exposed_critical_count": sig.ExposedCriticalCount,
			"internet_exposed":       sig.InternetExposed,
			"cluster_count":          sig.ClusterCount,
			"exposed_cluster_count":  sig.ExposedClusterCount,
			"active_secret_count":    sig.ActiveSecretCount,
			"has_fix_for_critical":   sig.HasFixForCritical,
			"has_fix_for_high":       sig.HasFixForHigh,
		},
	}
	if tier == assetrisk.TierDeprioritized {
		if rs := assetrisk.TierReasons(sig, tier); len(rs) > 0 {
			payload["deprioritized_reason"] = rs[0].ID
		}
	}

	if sig.AssetType == "image" {
		type vulnRow struct {
			ID            string  `json:"id"                      gorm:"column:canonical_id"`
			Severity      string  `json:"severity"                gorm:"column:severity"`
			Pkg           string  `json:"pkg"                     gorm:"column:pkg_name"`
			Installed     string  `json:"installed,omitempty"     gorm:"column:installed_version"`
			Fixed         string  `json:"fixed"                   gorm:"column:fixed_version"`
			Title         string  `json:"title"                   gorm:"column:title"`
			Description   string  `json:"description,omitempty"   gorm:"column:description"`
			CVSS          float32 `json:"cvss"                    gorm:"column:cvss"`
			EPSS          float32 `json:"epss"                    gorm:"column:epss"`
			KEV           bool    `json:"kev"                     gorm:"column:kev"`
			KEVDueDate    string  `json:"kev_due_date,omitempty"  gorm:"column:kev_due_date"`
			KEVRansomware bool    `json:"kev_ransomware,omitempty" gorm:"column:kev_ransomware"`
			Triage        bool    `json:"-"                       gorm:"column:triage"`
		}
		var vulns []vulnRow
		if err := db.WithContext(ctx).Raw(`
			SELECT * FROM (
				SELECT DISTINCT ON (COALESCE(vm.canonical_id, v.vuln_id))
					COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
					v.severity, v.pkg_name, v.installed_version, v.fixed_version,
					COALESCE(NULLIF(vm.title, ''), v.title) AS title,
					LEFT(COALESCE(NULLIF(vm.description, ''), v.description), ?) AS description,
					COALESCE(vm.cvss_score, 0)::real AS cvss,
					COALESCE(e.score, 0)::real AS epss,
					(k.cve_id IS NOT NULL) AS kev,
					COALESCE(k.due_date::text, '') AS kev_due_date,
					COALESCE(k.known_ransomware, false) AS kev_ransomware,
					(
						k.cve_id IS NOT NULL
						OR COALESCE(e.score, 0) >= ?
						OR v.severity = 'CRITICAL'
						OR (? AND v.severity = 'HIGH')
					) AS triage
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
				ORDER BY COALESCE(vm.canonical_id, v.vuln_id)
			) dedup
			ORDER BY kev DESC, epss DESC,
			         CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
		`, advisoryDescCap, assetrisk.EPSSElevated, sig.InternetExposed, sig.AssetID).Scan(&vulns).Error; err != nil {
			return "", err
		}
		// Split on the triage flag: tier-driving vulns keep the full
		// row, the long tail is stripped to its metadata line.
		var triageVulns, otherVulns []vulnRow
		for _, v := range vulns {
			if v.Triage {
				triageVulns = append(triageVulns, v)
				continue
			}
			v.Description = ""
			v.Installed = ""
			otherVulns = append(otherVulns, v)
		}
		payload["vuln_total"] = len(vulns)
		if len(triageVulns) > advisoryTriageVulnCap {
			triageVulns = triageVulns[:advisoryTriageVulnCap]
			payload["triage_vulns_note"] = "truncated to the highest-risk entries; totals in signals cover everything"
		}
		if len(otherVulns) > advisoryOtherVulnCap {
			otherVulns = otherVulns[:advisoryOtherVulnCap]
			payload["other_vulns_note"] = "truncated; totals in signals cover everything"
		}
		payload["triage_vulns"] = triageVulns
		payload["other_vulns"] = otherVulns

		var hosts []exposedHost
		db.WithContext(ctx).Raw(exposedHostsQuery, sig.ImageDigest, advisoryHostCap).Scan(&hosts)
		payload["exposed_hosts"] = hosts
	} else {
		// Repos carry no per-CVE lazy detail yet — the structured
		// reasons are the evidence.
		payload["reasons"] = assetrisk.TierReasons(sig, tier)
	}

	b, err := json.Marshal(payload)
	return string(b), err
}

// Chat payload budgets. The chat models carry ~256k context, so the
// grounding can be far richer than the batch-advisory payload — but
// still bounded so a 3000-CVE base image doesn't ship megabytes per
// turn.
const (
	chatVulnCap    = 150
	chatDescCap    = 600
	chatHostCap    = 30
	chatClusterCap = 20
)

// BuildChatPayload assembles the full-context grounding for the
// finding chat: every signal, ALL vulns up to the cap (with full
// titles, descriptions, installed/fixed versions, per-CVE KEV
// detail + EPSS percentile), exposed hosts with namespace/cluster,
// the clusters running the digest, posture context, and the cached
// advisory + shadow verdict when present. BuildPayload carries full
// descriptions only for tier-driving vulns — it feeds bulk
// generation; this feeds interactive triage.
func BuildChatPayload(ctx context.Context, db *gorm.DB, sig assetrisk.Signals) (string, error) {
	tier := assetrisk.Tier(sig)
	payload := map[string]any{
		"asset":        sig.AssetSlug,
		"asset_type":   sig.AssetType,
		"tier":         tier,
		"tier_reasons": assetrisk.TierReasons(sig, tier),
		"signals": map[string]any{
			"critical_count":         sig.CriticalCount,
			"high_count":             sig.HighCount,
			"medium_count":           sig.MediumCount,
			"low_count":              sig.LowCount,
			"kev_count":              sig.KEVCount,
			"kev_fixable_count":      sig.KEVFixableCount,
			"kev_ransomware_count":   sig.KEVRansomwareCount,
			"kev_due_passed":         sig.KEVDuePassed,
			"epss_max":               sig.EPSSMax,
			"exposed_kev_count":      sig.ExposedKEVCount,
			"exposed_critical_count": sig.ExposedCriticalCount,
			"exposed_epss_max":       sig.ExposedEPSSMax,
			"internet_exposed":       sig.InternetExposed,
			"cluster_count":          sig.ClusterCount,
			"exposed_cluster_count":  sig.ExposedClusterCount,
			"active_secret_count":    sig.ActiveSecretCount,
			"has_fix_for_critical":   sig.HasFixForCritical,
			"has_fix_for_high":       sig.HasFixForHigh,
		},
		"posture": map[string]any{
			"has_sbom":        sig.HasSBOM,
			"scan_age_days":   sig.ScanAgeDays,
			"image_signed":    sig.ImageSigned,
			"archived_deps":   sig.ArchivedDepCount,
			"deprecated_deps": sig.DeprecatedDepCount,
		},
	}

	// Cached enrichment, so the model can reference (or be challenged
	// on) what the dashboard already claims.
	var adv Advisory
	if err := db.WithContext(ctx).
		Where("asset_type = ? AND asset_id = ?", sig.AssetType, sig.AssetID).
		First(&adv).Error; err == nil {
		enrich := map[string]any{}
		if adv.Summary != "" {
			enrich["advisory_summary"] = adv.Summary
		}
		if adv.Verdict != "" {
			enrich["shadow_verdict"] = map[string]any{
				"verdict":       adv.Verdict,
				"justification": adv.VerdictJustification,
				"confidence":    adv.VerdictConfidence,
				"missing_data":  adv.VerdictMissingData,
			}
		}
		if len(enrich) > 0 {
			payload["existing_assessment"] = enrich
		}
	}

	if sig.AssetType == "image" {
		type chatVuln struct {
			ID             string  `json:"id"              gorm:"column:canonical_id"`
			Severity       string  `json:"severity"        gorm:"column:severity"`
			Pkg            string  `json:"pkg"             gorm:"column:pkg_name"`
			Installed      string  `json:"installed"       gorm:"column:installed_version"`
			Fixed          string  `json:"fixed"           gorm:"column:fixed_version"`
			Title          string  `json:"title"           gorm:"column:title"`
			Description    string  `json:"description,omitempty" gorm:"column:description"`
			EPSS           float32 `json:"epss"            gorm:"column:epss"`
			EPSSPercentile float32 `json:"epss_percentile" gorm:"column:epss_percentile"`
			KEV            bool    `json:"kev"             gorm:"column:kev"`
			KEVDueDate     string  `json:"kev_due_date,omitempty" gorm:"column:kev_due_date"`
			KEVRansomware  bool    `json:"kev_ransomware"  gorm:"column:kev_ransomware"`
		}
		var vulns []chatVuln
		if err := db.WithContext(ctx).Raw(`
			SELECT * FROM (
				SELECT DISTINCT ON (COALESCE(vm.canonical_id, v.vuln_id))
					COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
					v.severity, v.pkg_name, v.installed_version, v.fixed_version,
					COALESCE(NULLIF(vm.title, ''), v.title) AS title,
					LEFT(COALESCE(NULLIF(vm.description, ''), v.description), ?) AS description,
					COALESCE(e.score, 0)::real AS epss,
					COALESCE(e.percentile, 0)::real AS epss_percentile,
					(k.cve_id IS NOT NULL) AS kev,
					COALESCE(k.due_date::text, '') AS kev_due_date,
					COALESCE(k.known_ransomware, false) AS kev_ransomware
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
				ORDER BY COALESCE(vm.canonical_id, v.vuln_id)
			) dedup
			ORDER BY kev DESC, epss DESC,
			         CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
			LIMIT ?
		`, chatDescCap, sig.AssetID, chatVulnCap).Scan(&vulns).Error; err != nil {
			return "", err
		}
		payload["vulns"] = vulns

		var vulnTotal int
		db.WithContext(ctx).Raw(`
			SELECT COUNT(DISTINCT COALESCE(vm.canonical_id, v.vuln_id))
			FROM view_unified_image_vulnerabilities v
			LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
			WHERE v.image_id = ?
		`, sig.AssetID).Scan(&vulnTotal)
		payload["vuln_total"] = vulnTotal
		if vulnTotal > len(vulns) {
			payload["vulns_note"] = "list truncated to the highest-risk entries; totals in signals cover everything"
		}

		var hosts []exposedHost
		db.WithContext(ctx).Raw(exposedHostsQuery, sig.ImageDigest, chatHostCap).Scan(&hosts)
		payload["exposed_hosts"] = hosts

		type chatCluster struct {
			Name    string `json:"name"    gorm:"column:name"`
			Exposed bool   `json:"exposed" gorm:"column:exposed"`
		}
		var clusters []chatCluster
		db.WithContext(ctx).Raw(`
			SELECT
				COALESCE(NULLIF(c.display_name, ''), NULLIF(c.ror_cluster_name, ''), cd.cluster_id) AS name,
				EXISTS (
					SELECT 1 FROM exposed_digests ed
					WHERE ed.digest = ? AND ed.cluster_id = cd.cluster_id
				) AS exposed
			FROM (
				SELECT DISTINCT cr.data->>'cluster_id' AS cluster_id
				FROM cluster_record cr
				WHERE cr.data->>'kind' = 'Container'
				  AND cr.data->>'digest' = ?
				  AND COALESCE(cr.data->>'msg', '') <> 'DELETE'
			) cd
			LEFT JOIN clusters c ON c.cluster_id = cd.cluster_id
			ORDER BY exposed DESC, name LIMIT ?
		`, sig.ImageDigest, sig.ImageDigest, chatClusterCap).Scan(&clusters)
		payload["runs_in_clusters"] = clusters
	} else {
		type chatRepoVuln struct {
			ID       string  `json:"id"       gorm:"column:canonical_id"`
			Severity string  `json:"severity" gorm:"column:severity"`
			Fixed    string  `json:"fixed"    gorm:"column:fixed_version"`
			EPSS     float32 `json:"epss"     gorm:"column:epss"`
			KEV      bool    `json:"kev"      gorm:"column:kev"`
		}
		var vulns []chatRepoVuln
		db.WithContext(ctx).Raw(`
			SELECT * FROM (
				SELECT DISTINCT ON (COALESCE(vm.canonical_id, v.vuln_id))
					COALESCE(vm.canonical_id, v.vuln_id) AS canonical_id,
					v.severity, v.fixed_version,
					COALESCE(e.score, 0)::real AS epss,
					(k.cve_id IS NOT NULL) AS kev
				FROM view_unified_repositories_vulnerabilities v
				LEFT JOIN vuln_metadata vm ON vm.vuln_id = v.vuln_id
				LEFT JOIN epss_entries e ON e.cve_id = COALESCE(vm.canonical_id, v.vuln_id)
				LEFT JOIN cisa_kev_entries k ON k.cve_id = COALESCE(vm.canonical_id, v.vuln_id)
				WHERE v.repo_id = ?
				ORDER BY COALESCE(vm.canonical_id, v.vuln_id)
			) dedup
			ORDER BY kev DESC, epss DESC LIMIT ?
		`, sig.AssetID, chatVulnCap).Scan(&vulns)
		payload["vulns"] = vulns
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
