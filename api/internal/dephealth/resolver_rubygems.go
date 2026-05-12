package dephealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// rubygemsResolver hits rubygems.org/api/v1/gems/{name}.json.
// `source_code_uri` is the canonical field — RubyGems flagged it
// for source-of-truth in 2020 — falling back to `homepage_uri` only
// when the gem author didn't fill it in.
type rubygemsResolver struct {
	httpClient *http.Client
}

func newRubygemsResolver() *rubygemsResolver {
	return &rubygemsResolver{
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (rubygemsResolver) Ecosystem() string { return "rubygems" }

func (r *rubygemsResolver) Fetch(ctx context.Context, packageName string) (Resolution, error) {
	endpoint := "https://rubygems.org/api/v1/gems/" + url.PathEscape(packageName) + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Resolution{}, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return Resolution{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Resolution{}, fmt.Errorf("gem not found")
	}
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("rubygems: HTTP %d", resp.StatusCode)
	}

	var doc struct {
		Version       string `json:"version"`
		SourceCodeURI string `json:"source_code_uri"`
		HomepageURI   string `json:"homepage_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Resolution{}, fmt.Errorf("decode rubygems payload: %w", err)
	}

	out := Resolution{LatestVersion: doc.Version}
	raw := doc.SourceCodeURI
	if raw == "" {
		// Homepage often points at the docs site rather than the
		// source — only accept it when it normalises to a known
		// git host.
		if _, prov := NormalizeRepoURL(doc.HomepageURI); prov != "" {
			raw = doc.HomepageURI
		}
	}
	if raw != "" {
		out.SourceURL, out.SourceProvider = NormalizeRepoURL(raw)
	}
	return out, nil
}
