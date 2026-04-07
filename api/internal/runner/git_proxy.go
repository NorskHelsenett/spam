package runner

import (
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

	upstreamURL, err := url.Parse(payload.CloneURL)
	if err != nil || upstreamURL.Scheme == "" || upstreamURL.Host == "" {
		http.Error(w, "invalid clone url", http.StatusInternalServerError)
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
			target := buildGitProxyUpstreamURL(upstreamURL, gitPath, r.URL.RawQuery)
			pr.SetURL(target)
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Proxy-Authorization")
			if providerToken != "" {
				pr.Out.SetBasicAuth("token", providerToken)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("git proxy upstream error: run_id=%s url=%s err=%v", runID, payload.CloneURL, err)
			http.Error(w, "git upstream request failed", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
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
