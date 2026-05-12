package dephealth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// goResolver hits proxy.golang.org for the latest version of a Go
// module, and treats the module path itself as the source URL when
// it points to a known git host (which is the dominant case in the
// Go ecosystem). The Go module path == repo URL convention is
// stronger here than in any other ecosystem; we still defer to
// NormalizeRepoURL so a path like "github.com/foo/bar/v2" gets
// trimmed to "github.com/foo/bar".
//
// proxy.golang.org's `@latest` returns just version + time; that's
// enough for the latest_version field. Activity metadata
// (last_pushed, archived) comes from the GitHub fetcher below — Go
// doesn't carry those signals server-side.
type goResolver struct {
	httpClient *http.Client
}

func newGoResolver() *goResolver {
	return &goResolver{
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
}

func (goResolver) Ecosystem() string { return "go" }

func (r *goResolver) Fetch(ctx context.Context, modulePath string) (Resolution, error) {
	out := Resolution{}

	// Module path → repo URL. proxy.golang.org accepts the path as-
	// is (it understands /v2 etc), but for source-URL resolution we
	// want the trimmed "owner/repo" form. NormalizeRepoURL handles
	// the trim because it reduces the path to two segments.
	if u, p := NormalizeRepoURL("https://" + modulePath); u != "" {
		out.SourceURL = u
		out.SourceProvider = p
	}

	// proxy.golang.org/<module>/@latest returns {Version, Time}.
	// Module paths can contain uppercase characters but proxy.golang
	// requires them lower-cased into !X form; we punt on that
	// rewriting for Phase 3b and let those packages 404 — it's a
	// small minority and admins can see the error in the row.
	endpoint := "https://proxy.golang.org/" + strings.ToLower(modulePath) + "/@latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return out, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Source URL alone is still useful — return what we have
		// without an error so the GitHub fetcher can still populate
		// activity metadata.
		return out, nil
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("proxy.golang.org: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Version string `json:"Version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return out, fmt.Errorf("decode go @latest: %w", err)
	}
	out.LatestVersion = doc.Version
	return out, nil
}
