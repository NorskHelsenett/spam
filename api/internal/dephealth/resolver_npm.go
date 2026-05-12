package dephealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// npmResolver hits registry.npmjs.org for the package manifest and
// extracts the source repository URL + latest version. The `dist-
// tags.latest` pointer is authoritative for "what version a fresh
// install would pull" — we use it for the versions_behind delta.
//
// `repository` field shape varies across maintainers: sometimes a
// plain string, sometimes an object {url, type}, sometimes the
// "github:foo/bar" shorthand. NormalizeRepoURL handles all three.
//
// `deprecated` on the latest version means the maintainer has
// formally announced the package is no longer supported (npm shows
// a banner). Distinct from "archived on GitHub" — both are signals,
// neither implies the other, so dep_health stores them separately.
type npmResolver struct {
	httpClient *http.Client
}

func newNpmResolver() *npmResolver {
	return &npmResolver{
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (npmResolver) Ecosystem() string { return "npm" }

func (r *npmResolver) Fetch(ctx context.Context, packageName string) (Resolution, error) {
	endpoint := "https://registry.npmjs.org/" + url.PathEscape(packageName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Resolution{}, err
	}
	// Slim payload — we only need repository + dist-tags + the
	// latest version's `deprecated` flag, not every published
	// version's tarball metadata.
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return Resolution{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return Resolution{}, fmt.Errorf("package not found in npm registry")
	}
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("npm registry: HTTP %d", resp.StatusCode)
	}

	// repository can be either a string or {url, type}; decode it
	// raw and parse with a small switch so both shapes work without
	// a custom UnmarshalJSON.
	var doc struct {
		DistTags map[string]string          `json:"dist-tags"`
		Repository json.RawMessage          `json:"repository"`
		Versions   map[string]npmVersionDoc `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Resolution{}, fmt.Errorf("decode npm payload: %w", err)
	}

	out := Resolution{}
	if latest, ok := doc.DistTags["latest"]; ok && latest != "" {
		out.LatestVersion = latest
		if v, ok := doc.Versions[latest]; ok && v.Deprecated != "" {
			out.IsDeprecated = true
		}
	}

	if rawURL := extractNpmRepoURL(doc.Repository); rawURL != "" {
		out.SourceURL, out.SourceProvider = NormalizeRepoURL(rawURL)
	}
	return out, nil
}

type npmVersionDoc struct {
	Deprecated string `json:"deprecated,omitempty"`
}

// extractNpmRepoURL handles both `repository: "foo/bar"` strings and
// `repository: {type, url}` objects.
func extractNpmRepoURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString
	}
	var asObj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &asObj); err == nil {
		return asObj.URL
	}
	return ""
}
