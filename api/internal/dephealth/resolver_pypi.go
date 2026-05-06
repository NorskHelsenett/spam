package dephealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// pypiResolver hits pypi.org/pypi/{name}/json. PyPI publishes a
// `project_urls` map alongside the legacy `home_page` and the docs
// in PEP 621 say to prefer canonical labels there. We try Source /
// Repository / Code (in priority order) before falling back to the
// homepage so e.g. a project's docs site doesn't get treated as the
// source repo.
type pypiResolver struct {
	httpClient *http.Client
}

func newPypiResolver() *pypiResolver {
	return &pypiResolver{
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (pypiResolver) Ecosystem() string { return "pypi" }

func (r *pypiResolver) Fetch(ctx context.Context, packageName string) (Resolution, error) {
	endpoint := "https://pypi.org/pypi/" + url.PathEscape(packageName) + "/json"
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
		return Resolution{}, fmt.Errorf("package not found in PyPI")
	}
	if resp.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("pypi: HTTP %d", resp.StatusCode)
	}

	var doc struct {
		Info struct {
			Version     string            `json:"version"`
			HomePage    string            `json:"home_page"`
			ProjectURLs map[string]string `json:"project_urls"`
			// PyPI exposes a `yanked` flag per release but no
			// package-wide deprecation. We map yanked latest to
			// IsDeprecated since the effect (don't use this) is the
			// same.
			Yanked bool `json:"yanked"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return Resolution{}, fmt.Errorf("decode pypi payload: %w", err)
	}

	out := Resolution{
		LatestVersion: doc.Info.Version,
		IsDeprecated:  doc.Info.Yanked,
	}

	// Priority order — `Source` is the convention canonical projects
	// use; `Repository` and `Code` are common alternates. Each label
	// is matched case-insensitively because PyPI doesn't normalise.
	rawURL := pickPypiSourceURL(doc.Info.ProjectURLs, doc.Info.HomePage)
	if rawURL != "" {
		out.SourceURL, out.SourceProvider = NormalizeRepoURL(rawURL)
	}
	return out, nil
}

func pickPypiSourceURL(projectURLs map[string]string, homePage string) string {
	prefs := []string{"source", "repository", "code", "source code"}
	for _, want := range prefs {
		for k, v := range projectURLs {
			if strings.EqualFold(strings.TrimSpace(k), want) && v != "" {
				return v
			}
		}
	}
	// Fall back to the homepage, but only if it points to a known
	// git host — a docs site doesn't help us measure activity.
	if _, prov := NormalizeRepoURL(homePage); prov != "" {
		return homePage
	}
	for _, k := range []string{"homepage", "documentation"} {
		for label, v := range projectURLs {
			if strings.EqualFold(strings.TrimSpace(label), k) && v != "" {
				if _, prov := NormalizeRepoURL(v); prov != "" {
					return v
				}
			}
		}
	}
	return ""
}
