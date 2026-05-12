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

// nugetResolver pulls latest version + repository URL via NuGet's
// V3 API. Two round trips are typical for NuGet: the flatcontainer
// `index.json` lists every version (cheap, served from CDN), and
// the registration `index.json` carries each version's catalog
// entry (where `repository` and `projectUrl` live). We pick the
// most recent stable version from flatcontainer, then read its
// catalog entry to get the repo URL.
//
// NuGet IDs are case-insensitive but the API expects lowercase paths
// — we normalize before constructing the URL.
type nugetResolver struct {
	httpClient *http.Client
}

func newNugetResolver() *nugetResolver {
	return &nugetResolver{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (nugetResolver) Ecosystem() string { return "nuget" }

func (r *nugetResolver) Fetch(ctx context.Context, packageName string) (Resolution, error) {
	id := strings.ToLower(packageName)

	versions, err := r.fetchVersions(ctx, id)
	if err != nil {
		return Resolution{}, err
	}
	latest := pickLatestStable(versions)
	if latest == "" {
		return Resolution{}, fmt.Errorf("no stable versions for %s", packageName)
	}

	out := Resolution{LatestVersion: latest}

	// Catalog entry for repository URL. Best-effort — many older
	// NuGet packages don't have a `repository` field. When that's
	// the case, the package's projectUrl can be a github.com URL
	// (popular convention) and we fall back to that.
	repo, projectURL := r.fetchCatalogEntry(ctx, id, latest)
	raw := repo
	if raw == "" {
		// Only accept projectUrl when it normalizes to a known git
		// host — otherwise we'd mis-attribute random org sites.
		if _, prov := NormalizeRepoURL(projectURL); prov != "" {
			raw = projectURL
		}
	}
	if raw != "" {
		out.SourceURL, out.SourceProvider = NormalizeRepoURL(raw)
	}
	return out, nil
}

func (r *nugetResolver) fetchVersions(ctx context.Context, id string) ([]string, error) {
	endpoint := fmt.Sprintf("https://api.nuget.org/v3-flatcontainer/%s/index.json", url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nuget flatcontainer: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Versions []string `json:"versions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode nuget versions: %w", err)
	}
	return doc.Versions, nil
}

// fetchCatalogEntry walks the registration semver2 index until it
// finds the leaf for the requested version, then reads the catalog
// entry (which has the repository/projectUrl fields). Returns
// (repositoryURL, projectURL) — either may be empty.
func (r *nugetResolver) fetchCatalogEntry(ctx context.Context, id, version string) (string, string) {
	endpoint := fmt.Sprintf("https://api.nuget.org/v3/registration5-gz-semver2/%s/index.json", url.PathEscape(id))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}

	var doc struct {
		Items []struct {
			Items []struct {
				CatalogEntry struct {
					Version       string `json:"version"`
					ProjectURL    string `json:"projectUrl"`
					RepositoryURL string `json:"repository"`
				} `json:"catalogEntry"`
			} `json:"items"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", ""
	}
	for _, page := range doc.Items {
		for _, leaf := range page.Items {
			if leaf.CatalogEntry.Version == version {
				return leaf.CatalogEntry.RepositoryURL, leaf.CatalogEntry.ProjectURL
			}
		}
	}
	return "", ""
}

// pickLatestStable returns the highest non-prerelease version using a
// crude string comparison that handles canonical SemVer ("1.2.3")
// well enough for NuGet's typical inputs. Versions containing a
// hyphen (e.g. "1.2.3-rc.1") are pre-release and skipped. NuGet
// returns versions in ascending order, so we walk from the back.
func pickLatestStable(versions []string) string {
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		if !strings.Contains(v, "-") {
			return v
		}
	}
	if len(versions) > 0 {
		return versions[len(versions)-1]
	}
	return ""
}
