package secretprobe

import "context"

// ProbeContext provides the probe function with everything it needs.
type ProbeContext struct {
	Secret          string // the extracted secret value
	RuleID          string
	ProviderBaseURL string // for provider-scoped tokens (GitLab, Gitea)
}

// ProbeKind indicates whether a probe requires network access.
type ProbeKind int

const (
	// ProbeKindOffline probes run locally (JWT decode, key parsing).
	// Safe to auto-run after every scan.
	ProbeKindOffline ProbeKind = iota
	// ProbeKindNetwork probes make HTTP calls to external services.
	// Only run on manual trigger.
	ProbeKindNetwork
)

// RequestPreview describes an HTTP request a probe would make.
type RequestPreview struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Prober validates whether a secret is live.
type Prober interface {
	// Probe checks the secret and returns the result.
	Probe(ctx context.Context, pc ProbeContext) ProbeOutput
	// Kind returns whether this probe is offline or network-based.
	Kind() ProbeKind
	// Describe returns a preview of what HTTP requests this probe would make.
	// Returns nil for offline probes that don't make network calls.
	Describe(pc ProbeContext) []RequestPreview
}

// ProberFunc adapts a plain function to the Prober interface.
type ProberFunc struct {
	Fn        func(ctx context.Context, pc ProbeContext) ProbeOutput
	DescFn    func(pc ProbeContext) []RequestPreview // nil for offline probes
	ProbeKind ProbeKind
}

func (f ProberFunc) Probe(ctx context.Context, pc ProbeContext) ProbeOutput {
	return f.Fn(ctx, pc)
}
func (f ProberFunc) Kind() ProbeKind { return f.ProbeKind }
func (f ProberFunc) Describe(pc ProbeContext) []RequestPreview {
	if f.DescFn != nil {
		return f.DescFn(pc)
	}
	return nil
}

type registryEntry struct {
	prober Prober
}

var registry = map[string]registryEntry{}

// Register adds a prober for a rule ID.
func Register(ruleID string, p Prober) {
	registry[ruleID] = registryEntry{prober: p}
}

// RegisterOffline registers an offline (no network) probe function.
func RegisterOffline(ruleID string, f func(ctx context.Context, pc ProbeContext) ProbeOutput) {
	registry[ruleID] = registryEntry{prober: ProberFunc{Fn: f, ProbeKind: ProbeKindOffline}}
}

// RegisterNetwork registers a network-based probe function with a describe function
// that returns the HTTP requests it would make.
func RegisterNetwork(ruleID string, f func(ctx context.Context, pc ProbeContext) ProbeOutput, desc func(pc ProbeContext) []RequestPreview) {
	registry[ruleID] = registryEntry{prober: ProberFunc{Fn: f, DescFn: desc, ProbeKind: ProbeKindNetwork}}
}

// Lookup returns the prober for a rule ID, or nil if none is registered.
func Lookup(ruleID string) Prober {
	if e, ok := registry[ruleID]; ok {
		return e.prober
	}
	return nil
}

// RegisteredRuleIDs returns all rule IDs that have a registered prober.
func RegisteredRuleIDs() []string {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	return ids
}

// OfflineRuleIDs returns rule IDs for probes that don't require network access.
func OfflineRuleIDs() []string {
	var ids []string
	for id, e := range registry {
		if e.prober.Kind() == ProbeKindOffline {
			ids = append(ids, id)
		}
	}
	return ids
}
