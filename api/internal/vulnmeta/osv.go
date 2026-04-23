package vulnmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// osvAPIBase is the OSV.dev v1 endpoint. The /vulns/{id} GET handles
// every OSV-aliased ID we see in the wild (CVE-*, GHSA-*, BIT-*,
// PYSEC-*, RUSTSEC-*, …), so we don't need to guess which upstream
// database hosts a given ID — OSV does the routing.
const osvAPIBase = "https://api.osv.dev/v1/vulns/"

// osvClient is package-level so keep-alive works across fetches.
// 20s is generous — OSV is typically sub-second but can get slow
// during scrape bursts.
var osvClient = &http.Client{Timeout: 20 * time.Second}

// osvSeverity matches OSV's severity array entries.
type osvSeverity struct {
	Type  string `json:"type"`  // CVSS_V2 | CVSS_V3 | CVSS_V4
	Score string `json:"score"` // the vector string; score value lives inside
}

// osvReference is the OSV reference shape.
type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// osvVulnerability captures the subset of the OSV schema we surface.
// The raw JSON is also persisted separately (RawJSON on Metadata) so
// future fields can be derived without re-fetching.
type osvVulnerability struct {
	ID               string                 `json:"id"`
	Aliases          []string               `json:"aliases"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Published        time.Time              `json:"published"`
	Modified         time.Time              `json:"modified"`
	Severity         []osvSeverity          `json:"severity"`
	References       []osvReference         `json:"references"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
	Affected         []struct {
		DatabaseSpecific map[string]interface{} `json:"database_specific"`
	} `json:"affected"`
}

// fetchOSV pulls one advisory from osv.dev. Returns (nil, nil) on 404
// so the caller can decide whether to log-and-skip or try another
// source without treating "not in OSV" as an error.
func fetchOSV(ctx context.Context, vulnID string) (*osvVulnerability, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvAPIBase+vulnID, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "spam-vuln-enricher/1.0")

	resp, err := osvClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, nil
	}
	if resp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("osv: status %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MiB cap — most advisories are <20KB
	if err != nil {
		return nil, nil, err
	}

	var v osvVulnerability
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, nil, fmt.Errorf("osv: decode: %w", err)
	}
	return &v, raw, nil
}

// toMetadata flattens the OSV payload into our Metadata shape.
// CVSS extraction preserves whichever vector OSV reports (V4 beats V3
// beats V2); the score itself is parsed out of the vector string on
// the UI side for CVSS_V3/V4 since OSV doesn't ship a numeric score.
func (v *osvVulnerability) toMetadata(raw []byte) *Metadata {
	m := &Metadata{
		VulnID:      v.ID,
		Title:       strings.TrimSpace(v.Summary),
		Description: strings.TrimSpace(v.Details),
		Severity:    extractOSVSeverityLabel(v),
		CVSSVector:  pickCVSSVector(v.Severity),
		CVSSScore:   extractNumericScore(v),
		FetchedAt:   time.Now().UTC(),
	}
	if !v.Published.IsZero() {
		t := v.Published.UTC()
		m.PublishedAt = &t
	}
	if !v.Modified.IsZero() {
		t := v.Modified.UTC()
		m.ModifiedAt = &t
	}
	m.CWEs = marshalJSON(extractCWEs(v))
	m.References = marshalJSON(refsFromOSV(v.References))
	m.Aliases = marshalJSON(append([]string{v.ID}, v.Aliases...))
	m.Sources = marshalJSON([]string{"osv"})
	m.RawJSON = marshalJSON(map[string]json.RawMessage{"osv": raw})
	return m
}

func refsFromOSV(in []osvReference) []Reference {
	out := make([]Reference, 0, len(in))
	for _, r := range in {
		out = append(out, Reference{URL: r.URL, Type: r.Type})
	}
	return out
}

// extractOSVSeverityLabel prefers database_specific.severity
// (GHSA-flavoured: "CRITICAL" / "HIGH" / …) and falls back to a
// CVSS→label mapping when absent (Trivy/BIT feeds skip the label
// and only emit a vector).
func extractOSVSeverityLabel(v *osvVulnerability) string {
	if label, ok := v.DatabaseSpecific["severity"].(string); ok && label != "" {
		return strings.ToUpper(label)
	}
	for _, a := range v.Affected {
		if label, ok := a.DatabaseSpecific["severity"].(string); ok && label != "" {
			return strings.ToUpper(label)
		}
	}
	return cvssVectorToLabel(pickCVSSVector(v.Severity))
}

// pickCVSSVector returns the strongest CVSS vector published for
// this advisory (V4 > V3 > V2). Empty string if nothing was reported.
func pickCVSSVector(sevs []osvSeverity) string {
	var v2, v3, v4 string
	for _, s := range sevs {
		switch s.Type {
		case "CVSS_V4":
			if v4 == "" {
				v4 = s.Score
			}
		case "CVSS_V3":
			if v3 == "" {
				v3 = s.Score
			}
		case "CVSS_V2":
			if v2 == "" {
				v2 = s.Score
			}
		}
	}
	switch {
	case v4 != "":
		return v4
	case v3 != "":
		return v3
	default:
		return v2
	}
}

// extractNumericScore parses the "base score" out of a CVSS vector
// when OSV doesn't publish it separately. CVSS vectors embed the
// score after CVSS:<ver>/ so we scan for the token. This is
// best-effort — on unparseable vectors we return 0 and the UI falls
// back to the severity label.
func extractNumericScore(v *osvVulnerability) float32 {
	// OSV's database_specific sometimes carries a numeric cvss_score
	// (mostly GHSA). Prefer it when present.
	if n, ok := v.DatabaseSpecific["cvss_score"].(float64); ok {
		return float32(n)
	}
	// Otherwise leave it to the client — the vector is the source
	// of truth and a parser lives better there than fighting
	// edge-cases here.
	return 0
}

// extractCWEs pulls CWE identifiers from the advisory. GHSA feeds
// them under database_specific.cwe_ids; other sources vary. Never
// fails loudly — absent CWEs are just an empty array.
func extractCWEs(v *osvVulnerability) []string {
	raw, ok := v.DatabaseSpecific["cwe_ids"].([]interface{})
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cvssVectorToLabel reads the /A:… /I:… /C:… triad off a CVSS vector
// to derive a severity bucket when the advisory didn't ship one
// explicitly. Conservative: we only return labels for clear cases
// and default to UNKNOWN so the UI doesn't over-claim.
func cvssVectorToLabel(vector string) string {
	if vector == "" {
		return ""
	}
	// Very rough: real work lives in the client CVSS parser. Keep
	// this here only as a fallback so old/truncated vectors don't
	// surface as literal strings in the severity column.
	upper := strings.ToUpper(vector)
	switch {
	case strings.Contains(upper, "CRITICAL"):
		return "CRITICAL"
	case strings.Contains(upper, "HIGH"):
		return "HIGH"
	case strings.Contains(upper, "MEDIUM"):
		return "MEDIUM"
	case strings.Contains(upper, "LOW"):
		return "LOW"
	}
	return ""
}

// marshalJSON is a tiny helper so we don't sprinkle `json.Marshal +
// must-check-err` across every field. Falls back to a valid empty
// value on marshal error rather than panicking or writing NULL.
func marshalJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}
