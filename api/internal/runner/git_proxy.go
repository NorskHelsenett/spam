package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"github.com/go-chi/chi/v5"
)

const (
	gitSmartHTTPInfoRefs   = "info/refs"
	gitSmartHTTPUploadPack = "git-upload-pack"
)

// handleGitProxy proxies read-only git smart-HTTP traffic from the runner to
// the single upstream repository allowed for the run identified by the bearer
// token. This keeps runner egress pinned to the worker service.
func (s *Server) handleGitProxy(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		http.Error(w, "missing authorization", http.StatusUnauthorized)
		return
	}

	claims, err := ValidateRunToken(s.cfg.HMACKey, token)
	if err != nil {
		log.Printf("git proxy invalid token: %v", err)
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	runID := chi.URLParam(r, "run_id")
	if runID == "" || runID != claims.RunID {
		http.Error(w, "run ID mismatch", http.StatusForbidden)
		return
	}

	gitPath := strings.Trim(strings.TrimSpace(chi.URLParam(r, "*")), "/")
	if err := validateGitProxyRequest(r, gitPath); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var run Run
	if err := s.db.WithContext(r.Context()).Where("id = ?", runID).First(&run).Error; err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	var payload jobs.CreateRunPayload
	if len(run.Payload) == 0 {
		http.Error(w, "missing run payload", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(run.Payload, &payload); err != nil {
		log.Printf("git proxy: failed to unmarshal payload for run %s: %v", runID, err)
		http.Error(w, "invalid run payload", http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(payload.CloneURL) == "" {
		http.Error(w, "missing clone url", http.StatusBadRequest)
		return
	}

	upstreamURL, err := parseGitProxyCloneURL(payload.CloneURL)
	if err != nil {
		http.Error(w, "invalid clone url", http.StatusInternalServerError)
		return
	}

	expectedBaseURL, err := s.resolveGitProxyBaseURL(r.Context(), payload)
	if err != nil {
		log.Printf("git proxy: failed to resolve provider base url for run %s: %v", runID, err)
		http.Error(w, "failed to resolve provider base url", http.StatusInternalServerError)
		return
	}
	if err := ensureGitProxyUpstreamAllowed(upstreamURL, expectedBaseURL); err != nil {
		log.Printf("git proxy upstream rejected: run_id=%s clone_url=%s err=%v", runID, payload.CloneURL, err)
		http.Error(w, "clone url not allowed", http.StatusForbidden)
		return
	}

	providerToken := ""
	if strings.TrimSpace(payload.ProviderID) != "" {
		providerToken, err = providerconfig.GetActiveToken(r.Context(), s.db, payload.ProviderID, s.cfg.ProviderSecretsKey)
		if err != nil {
			log.Printf("git proxy: failed to load provider token for run %s: %v", runID, err)
			http.Error(w, "failed to load provider token", http.StatusInternalServerError)
			return
		}
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			rewriteGitProxyRequest(pr, upstreamURL, gitPath, r.URL.RawQuery, providerToken)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("git proxy upstream error: run_id=%s url=%s err=%v", runID, payload.CloneURL, err)
			http.Error(w, "git upstream request failed", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}

func (s *Server) resolveGitProxyBaseURL(ctx context.Context, payload jobs.CreateRunPayload) (string, error) {
	if providerID := strings.TrimSpace(payload.ProviderID); providerID != "" {
		var provider struct {
			BaseURL string
		}
		if err := s.db.WithContext(ctx).
			Table("provider_instances").
			Select("base_url").
			Where("id = ?", providerID).
			Scan(&provider).Error; err != nil {
			return "", err
		}
		if strings.TrimSpace(provider.BaseURL) == "" {
			return "", fmt.Errorf("provider %s has no base url", providerID)
		}
		return provider.BaseURL, nil
	}

	if baseURL := providerconfig.NormalizeBaseURL(strings.TrimSpace(payload.Provider), ""); baseURL != "" {
		return baseURL, nil
	}

	return "", nil
}

func validateGitProxyRequest(r *http.Request, gitPath string) error {
	switch gitPath {
	case gitSmartHTTPInfoRefs:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return fmt.Errorf("git info/refs only allows GET or HEAD")
		}
		service := r.URL.Query().Get("service")
		if service != gitSmartHTTPUploadPack {
			return fmt.Errorf("git service not allowed")
		}
		if len(r.URL.Query()) != 1 {
			return fmt.Errorf("unexpected git query parameters")
		}
		return nil
	case gitSmartHTTPUploadPack:
		if r.Method != http.MethodPost {
			return fmt.Errorf("git-upload-pack only allows POST")
		}
		if r.URL.RawQuery != "" {
			return fmt.Errorf("unexpected git upload-pack query parameters")
		}
		return nil
	default:
		return fmt.Errorf("git path not allowed")
	}
}

func parseGitProxyCloneURL(raw string) (*url.URL, error) {
	upstreamURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if upstreamURL.Scheme != "https" || upstreamURL.Host == "" {
		return nil, fmt.Errorf("clone url must use https")
	}
	if upstreamURL.User != nil {
		return nil, fmt.Errorf("clone url must not include credentials")
	}
	if upstreamURL.RawQuery != "" || upstreamURL.Fragment != "" {
		return nil, fmt.Errorf("clone url must not include query or fragment")
	}
	if path := strings.TrimSpace(upstreamURL.EscapedPath()); path == "" || !strings.HasSuffix(path, ".git") {
		return nil, fmt.Errorf("clone url must target a git repository path")
	}
	return upstreamURL, nil
}

func ensureGitProxyUpstreamAllowed(cloneURL *url.URL, expectedBaseURL string) error {
	if cloneURL == nil {
		return fmt.Errorf("missing clone url")
	}
	if strings.TrimSpace(expectedBaseURL) == "" {
		return nil
	}

	baseURL, err := url.Parse(expectedBaseURL)
	if err != nil {
		return fmt.Errorf("invalid provider base url: %w", err)
	}
	if baseURL.Scheme != "https" || baseURL.Host == "" {
		return fmt.Errorf("provider base url must use https")
	}
	if baseURL.User != nil {
		return fmt.Errorf("provider base url must not include credentials")
	}
	if !sameURLOrigin(cloneURL, baseURL) {
		return fmt.Errorf("clone url host does not match provider base url")
	}
	return nil
}

func sameURLOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func buildGitProxyUpstreamURL(base *url.URL, gitPath, rawQuery string) *url.URL {
	target := *base
	target.Path = strings.TrimRight(base.Path, "/")
	if gitPath != "" {
		target.Path += "/" + strings.TrimLeft(gitPath, "/")
	}
	target.RawPath = ""
	target.RawQuery = rawQuery
	return &target
}

func rewriteGitProxyRequest(pr *httputil.ProxyRequest, upstreamBase *url.URL, gitPath, rawQuery, providerToken string) {
	target := buildGitProxyUpstreamURL(upstreamBase, gitPath, rawQuery)
	pr.Out.URL.Scheme = target.Scheme
	pr.Out.URL.Host = target.Host
	pr.Out.URL.Path = target.Path
	pr.Out.URL.RawPath = target.RawPath
	pr.Out.URL.RawQuery = target.RawQuery
	pr.Out.Host = target.Host
	pr.Out.Header.Del("Authorization")
	pr.Out.Header.Del("Proxy-Authorization")
	if providerToken != "" {
		pr.Out.SetBasicAuth("token", providerToken)
	}
}
