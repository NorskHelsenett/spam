package secretprobe

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RunResult summarizes a probe batch run.
type RunResult struct {
	Total         int `json:"total"`
	Probed        int `json:"probed"`
	Skipped       int `json:"skipped"`
	FalsePositive int `json:"false_positive"`
	AlreadyProbed int `json:"already_probed"`
}

// Finding matches the shape of a single finding from run_secrets.findings JSONB.
type Finding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	Fingerprint string `json:"Fingerprint"`
}

// RunOptions controls which secrets are probed.
type RunOptions struct {
	RepoID      string   // empty = all repos
	RuleIDs     []string // empty = all registered rule IDs
	Force       bool     // re-probe even if already probed
	OnlyOffline bool     // only run offline probes (JWT, key parsing — no network)
}

// Runner executes secret probes against findings stored in run_secrets.
type Runner struct {
	db     *gorm.DB
	logger *AuditLogger
}

// NewRunner creates a probe runner with audit logging.
func NewRunner(db *gorm.DB) *Runner {
	return &Runner{
		db:     db,
		logger: NewAuditLogger(db),
	}
}

// Run probes secrets according to the given options.
func (r *Runner) Run(ctx context.Context, opts RunOptions, progress func(probed, total int)) (*RunResult, error) {
	// Attach audit logger to context so all HTTP calls are logged.
	ctx = WithAuditLogger(ctx, r.logger)

	type row struct {
		RepoID          string
		ProviderBaseURL string
		Findings        json.RawMessage
	}

	query := `
SELECT rs.repo_id,
       COALESCE(pi.base_url, '') AS provider_base_url,
       rs.findings
FROM (
  SELECT DISTINCT ON (repo_id) repo_id, findings
  FROM run_secrets
  WHERE repo_id IS NOT NULL AND repo_id <> ''
  ORDER BY repo_id, created_at DESC
) rs
JOIN repos r ON r.id = rs.repo_id
LEFT JOIN provider_instances pi ON pi.id = r.provider_instance_id`

	var rows []row
	if opts.RepoID != "" {
		query += ` WHERE rs.repo_id = ?`
		r.db.WithContext(ctx).Raw(query, opts.RepoID).Scan(&rows)
	} else {
		r.db.WithContext(ctx).Raw(query).Scan(&rows)
	}

	// Build rule ID filter set.
	ruleFilter := map[string]bool{}
	for _, id := range opts.RuleIDs {
		ruleFilter[id] = true
	}

	// Flatten all findings, applying rule filter.
	type findingWithCtx struct {
		Finding
		ProviderBaseURL string
	}
	var all []findingWithCtx
	for _, row := range rows {
		var findings []Finding
		if err := json.Unmarshal(row.Findings, &findings); err != nil {
			continue
		}
		for _, f := range findings {
			// Skip if rule filter is set and this rule isn't included.
			if len(ruleFilter) > 0 && !ruleFilter[f.RuleID] {
				continue
			}
			// Skip if no prober is registered for this rule.
			p := Lookup(f.RuleID)
			if p == nil {
				continue
			}
			// Skip network probes when only offline is requested.
			if opts.OnlyOffline && p.Kind() != ProbeKindOffline {
				continue
			}
			all = append(all, findingWithCtx{Finding: f, ProviderBaseURL: row.ProviderBaseURL})
		}
	}

	result := &RunResult{Total: len(all)}
	seen := map[string]bool{}

	for i, f := range all {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}

		secret := ExtractSecret(f.Match)
		if f.Secret != "" {
			secret = ExtractSecret(f.Secret)
		}
		hash := SecretHash(secret)

		if seen[hash] {
			result.Skipped++
			continue
		}
		seen[hash] = true

		// Skip if already probed (unless forced).
		if !opts.Force {
			var count int64
			r.db.WithContext(ctx).Model(&SecretProbe{}).Where("secret_hash = ?", hash).Count(&count)
			if count > 0 {
				result.AlreadyProbed++
				continue
			}
		}

		// Falsy check (no network).
		if falsy, reason := IsFalsy(secret); falsy {
			r.store(ctx, hash, f.RuleID, ProbeOutput{
				Status: StatusFalsePositive,
				Reason: reason,
			})
			result.FalsePositive++
			if progress != nil {
				progress(i+1, len(all))
			}
			continue
		}

		// Probe with timeout and audit context.
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		probeCtx = WithProbeIdentity(probeCtx, hash, f.RuleID)

		output := Lookup(f.RuleID).Probe(probeCtx, ProbeContext{
			Secret:          secret,
			RuleID:          f.RuleID,
			ProviderBaseURL: f.ProviderBaseURL,
		})
		cancel()

		r.store(ctx, hash, f.RuleID, output)
		result.Probed++

		if progress != nil {
			progress(i+1, len(all))
		}

		log.Printf("secretprobe: %s [%s] → %s", f.RuleID, hash[:12], output.Status)
	}

	return result, nil
}

// ProbeOne probes a single secret by its hash. Looks up the finding in run_secrets,
// extracts the secret, and runs the probe. Always re-probes (ignores existing results).
func (r *Runner) ProbeOne(ctx context.Context, repoID, fingerprint string) (*SecretProbe, error) {
	ctx = WithAuditLogger(ctx, r.logger)

	// Find the finding in the latest run_secrets for this repo.
	var rawFindings json.RawMessage
	var providerBaseURL string
	err := r.db.WithContext(ctx).Raw(`
		SELECT rs.findings, COALESCE(pi.base_url, '') AS provider_base_url
		FROM run_secrets rs
		JOIN repos repo ON repo.id = rs.repo_id
		LEFT JOIN provider_instances pi ON pi.id = repo.provider_instance_id
		WHERE rs.repo_id = ?
		ORDER BY rs.created_at DESC LIMIT 1
	`, repoID).Row().Scan(&rawFindings, &providerBaseURL)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	if err := json.Unmarshal(rawFindings, &findings); err != nil {
		return nil, err
	}

	// Match by fingerprint.
	var target *Finding
	for _, f := range findings {
		if f.Fingerprint == fingerprint {
			target = &f
			break
		}
	}
	if target == nil {
		return nil, gorm.ErrRecordNotFound
	}

	secret := ExtractSecret(target.Match)
	if target.Secret != "" {
		secret = ExtractSecret(target.Secret)
	}
	hash := SecretHash(secret)

	prober := Lookup(target.RuleID)
	if prober == nil {
		// No prober for this rule — store as unknown.
		r.store(ctx, hash, target.RuleID, ProbeOutput{
			Status: StatusUnknown,
			Reason: "no prober registered for " + target.RuleID,
		})
		probe := &SecretProbe{SecretHash: hash, RuleID: target.RuleID, Status: StatusUnknown}
		return probe, nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	probeCtx = WithProbeIdentity(probeCtx, hash, target.RuleID)

	output := prober.Probe(probeCtx, ProbeContext{
		Secret:          secret,
		RuleID:          target.RuleID,
		ProviderBaseURL: providerBaseURL,
	})
	cancel()

	r.store(ctx, hash, target.RuleID, output)

	// Return the stored probe.
	var probe SecretProbe
	r.db.WithContext(ctx).Where("secret_hash = ?", hash).First(&probe)
	return &probe, nil
}

// ProbeByHash probes a secret directly by its value and stores the result.
func (r *Runner) ProbeByHash(ctx context.Context, secret, ruleID, providerBaseURL string) (*SecretProbe, error) {
	ctx = WithAuditLogger(ctx, r.logger)
	hash := SecretHash(secret)

	prober := Lookup(ruleID)
	if prober == nil {
		r.store(ctx, hash, ruleID, ProbeOutput{
			Status: StatusUnknown,
			Reason: "no prober registered for " + ruleID,
		})
		probe := &SecretProbe{SecretHash: hash, RuleID: ruleID, Status: StatusUnknown}
		return probe, nil
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	probeCtx = WithProbeIdentity(probeCtx, hash, ruleID)

	output := prober.Probe(probeCtx, ProbeContext{
		Secret:          secret,
		RuleID:          ruleID,
		ProviderBaseURL: providerBaseURL,
	})
	cancel()

	r.store(ctx, hash, ruleID, output)

	var probe SecretProbe
	r.db.WithContext(ctx).Where("secret_hash = ?", hash).First(&probe)
	return &probe, nil
}

func (r *Runner) store(ctx context.Context, hash, ruleID string, output ProbeOutput) {
	meta := "{}"
	if output.Metadata != nil {
		if b, err := json.Marshal(output.Metadata); err == nil {
			meta = string(b)
		}
	}

	probe := SecretProbe{
		SecretHash: hash,
		RuleID:     ruleID,
		Status:     output.Status,
		Reason:     output.Reason,
		Metadata:   meta,
		ProbedAt:   time.Now(),
	}

	r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "secret_hash"}},
		DoUpdates: clause.AssignmentColumns([]string{"status", "reason", "metadata", "probed_at"}),
	}).Create(&probe)
}

// PreviewItem represents a single secret that would be probed.
type PreviewItem struct {
	SecretHash      string           `json:"secret_hash"`
	Secret          string           `json:"secret"`
	RuleID          string           `json:"rule_id"`
	EffectiveRuleID string           `json:"effective_rule_id,omitempty"` // after reclassification
	Kind            string           `json:"kind"`                       // "offline" or "network"
	AlreadyProbed   bool             `json:"already_probed"`
	PreviousStatus  Status           `json:"previous_status,omitempty"`
	IsFalsy         bool             `json:"is_falsy"`
	FalsyReason     string           `json:"falsy_reason,omitempty"`
	ProbeStatus     Status           `json:"probe_status,omitempty"`  // result of offline classification
	ProbeReason     string           `json:"probe_reason,omitempty"`  // explanation
	Reclassified    bool             `json:"reclassified,omitempty"`  // true if effective differs from original
	Dismissed       bool             `json:"dismissed"`               // user-dismissed
	Requests        []RequestPreview `json:"requests,omitempty"`
}

// PreviewGroup groups preview items by rule ID.
type PreviewGroup struct {
	RuleID string        `json:"rule_id"`
	Kind   string        `json:"kind"`
	Count  int           `json:"count"`
	Items  []PreviewItem `json:"items"`
}

// PreviewOptions controls what the preview returns.
type PreviewOptions struct {
	IncludeProbed bool // if false, exclude already-probed secrets
}

// Preview returns what would be probed without actually probing anything.
// It runs offline classification concurrently for speed.
func (r *Runner) Preview(ctx context.Context, opts PreviewOptions) ([]PreviewGroup, error) {

	type row struct {
		RepoID          string
		ProviderBaseURL string
		Findings        json.RawMessage
	}

	var rows []row
	r.db.WithContext(ctx).Raw(`
		SELECT rs.repo_id,
		       COALESCE(pi.base_url, '') AS provider_base_url,
		       rs.findings
		FROM (
		  SELECT DISTINCT ON (repo_id) repo_id, findings
		  FROM run_secrets
		  WHERE repo_id IS NOT NULL AND repo_id <> ''
		  ORDER BY repo_id, created_at DESC
		) rs
		JOIN repos repo ON repo.id = rs.repo_id
		LEFT JOIN provider_instances pi ON pi.id = repo.provider_instance_id
	`).Scan(&rows)

	type flatEntry struct {
		hash            string
		secret          string
		ruleID          string
		providerBaseURL string
	}
	var allEntries []flatEntry
	seen := map[string]bool{}
	var allHashes []string

	for _, row := range rows {
		var findings []Finding
		if json.Unmarshal(row.Findings, &findings) != nil {
			continue
		}
		for _, f := range findings {
			secret := ExtractSecret(f.Match)
			if f.Secret != "" {
				secret = ExtractSecret(f.Secret)
			}
			hash := SecretHash(secret)
			if seen[hash] {
				continue
			}
			seen[hash] = true
			allHashes = append(allHashes, hash)
			allEntries = append(allEntries, flatEntry{
				hash: hash, secret: secret, ruleID: f.RuleID, providerBaseURL: row.ProviderBaseURL,
			})
		}
	}

	// Look up existing probe results and dismissals in parallel.
	existing := map[string]SecretProbe{}
	dismissed := map[string]bool{}
	if len(allHashes) > 0 {
		var probes []SecretProbe
		r.db.WithContext(ctx).Where("secret_hash IN ?", allHashes).Find(&probes)
		for _, p := range probes {
			existing[p.SecretHash] = p
		}

		var dismissedHashes []string
		r.db.WithContext(ctx).
			Model(&SecretDismissal{}).
			Where("secret_hash IN ?", allHashes).
			Pluck("secret_hash", &dismissedHashes)
		for _, h := range dismissedHashes {
			dismissed[h] = true
		}
	}

	// Run classification concurrently for all entries.
	type classifiedEntry struct {
		flatEntry
		classification Classification
		isFalsy        bool
		falsyReason    string
	}
	classified := make([]classifiedEntry, len(allEntries))

	var wg sync.WaitGroup
	sem := make(chan struct{}, 64) // limit concurrency
	for i, e := range allEntries {
		wg.Add(1)
		go func(i int, e flatEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ce := classifiedEntry{flatEntry: e}
			if falsy, reason := IsFalsy(e.secret); falsy {
				ce.isFalsy = true
				ce.falsyReason = reason
			} else {
				ce.classification = Classify(e.secret, e.ruleID)
			}
			classified[i] = ce
		}(i, e)
	}
	wg.Wait()

	// Group by effective rule ID.
	type groupKey = string
	groupItemsMap := map[groupKey][]PreviewItem{}

	for _, ce := range classified {
		_, alreadyProbed := existing[ce.hash]
		if alreadyProbed && !opts.IncludeProbed {
			continue
		}

		effectiveRule := ce.ruleID
		if ce.classification.Reclassified {
			effectiveRule = ce.classification.EffectiveRuleID
		}

		p := Lookup(ce.ruleID)
		kind := "offline" // default to offline (local classification only)
		if p != nil && p.Kind() == ProbeKindNetwork {
			kind = "network"
		}

		item := PreviewItem{
			SecretHash:      ce.hash,
			Secret:          ce.secret,
			RuleID:          ce.ruleID,
			EffectiveRuleID: effectiveRule,
			Kind:            kind,
			Reclassified:    ce.classification.Reclassified,
		}
		if alreadyProbed {
			item.AlreadyProbed = true
			item.PreviousStatus = existing[ce.hash].Status
		}
		if ce.isFalsy {
			item.IsFalsy = true
			item.FalsyReason = ce.falsyReason
			item.ProbeStatus = StatusFalsePositive
		} else {
			item.ProbeStatus = ce.classification.ProbeOutput.Status
			item.ProbeReason = ce.classification.ProbeOutput.Reason
		}
		item.Dismissed = dismissed[ce.hash]
		// Get request preview from the prober.
		if p != nil {
			item.Requests = p.Describe(ProbeContext{
				Secret:          ce.secret,
				RuleID:          ce.ruleID,
				ProviderBaseURL: ce.providerBaseURL,
			})
		}
		groupItemsMap[effectiveRule] = append(groupItemsMap[effectiveRule], item)
	}

	// Build grouped output.
	result := []PreviewGroup{}
	for ruleID, items := range groupItemsMap {
		p := Lookup(ruleID)
		kind := "offline"
		if p != nil && p.Kind() == ProbeKindNetwork {
			kind = "network"
		}
		result = append(result, PreviewGroup{
			RuleID: ruleID,
			Kind:   kind,
			Count:  len(items),
			Items:  items,
		})
	}

	return result, nil
}

// Stats returns aggregate counts of probe results.
func Stats(ctx context.Context, db *gorm.DB) (map[Status]int64, int64, error) {
	type row struct {
		Status Status
		Count  int64
	}
	var rows []row
	if err := db.WithContext(ctx).
		Model(&SecretProbe{}).
		Select("status, count(*) as count").
		Group("status").
		Scan(&rows).Error; err != nil {
		return nil, 0, err
	}

	counts := map[Status]int64{}
	var total int64
	for _, r := range rows {
		counts[r.Status] = r.Count
		total += r.Count
	}
	return counts, total, nil
}
