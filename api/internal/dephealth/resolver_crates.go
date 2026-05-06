package dephealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// cratesResolver hits crates.io/api/v1/crates/{name}. The
// `crate.repository` field is reliable — crates.io has had it as a
// first-class concept since launch — and `crate.max_stable_version`
// is the right "latest" pointer for dependency-graph purposes
// (consumers default to stable, not pre-release).
type cratesResolver struct {
	httpClient *http.Client
}

func newCratesResolver() *cratesResolver {
	return &cratesResolver{
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (cratesResolver) Ecosystem() string { return "cargo" }

func (r *cratesResolver) Fetch(ctx context.Context, packageName string) (Resolution, error) {
	endpoint := "https://crates.io/api/v1/crates/" + url.PathEscape(packageName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Resolution{}, err
	}
	// crates.io requires a User-Agent.
	req.Header.Set("User-Agent", "spam-monitor (dephealth/1.0)")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return Resolution{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Resolution{}, fmt.Errorf("crate not found")
	}
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("crates.io: HTTP %d", resp.StatusCode)
	}

	var doc struct {
		Crate struct {
			Repository       string `json:"repository"`
			Homepage         string `json:"homepage"`
			MaxStableVersion string `json:"max_stable_version"`
			MaxVersion       string `json:"max_version"`
		} `json:"crate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Resolution{}, fmt.Errorf("decode crates payload: %w", err)
	}

	latest := doc.Crate.MaxStableVersion
	if latest == "" {
		latest = doc.Crate.MaxVersion
	}
	out := Resolution{LatestVersion: latest}

	raw := doc.Crate.Repository
	if raw == "" {
		// Homepage as fallback only when it points at a known git
		// host — many crates use a docs.rs link as the homepage.
		if _, prov := NormalizeRepoURL(doc.Crate.Homepage); prov != "" {
			raw = doc.Crate.Homepage
		}
	}
	if raw != "" {
		out.SourceURL, out.SourceProvider = NormalizeRepoURL(raw)
	}
	return out, nil
}
