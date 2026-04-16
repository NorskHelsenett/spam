package scam

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
)

type hostMeta struct {
	Title          string `json:"title"`
	FaviconURL     string `json:"favicon_url,omitempty"`
	HasFavicon     bool   `json:"has_favicon"`
	FaviconType    string `json:"favicon_type,omitempty"`
	faviconBytes   []byte // not serialized to JSON, stored separately
}

var (
	// (?s) enables dotall so . matches newlines — titles can span lines
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// Match any <link> with rel containing "icon" (covers icon, shortcut icon, apple-touch-icon, mask-icon)
	faviconRe = regexp.MustCompile(`(?i)<link[^>]+rel\s*=\s*["'][^"']*icon[^"']*["'][^>]*>`)
	hrefRe    = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
)

const (
	metaCachePrefix    = "hostmeta:"
	faviconCachePrefix = "hostfav:"
	metaTTL            = 24 * time.Hour
	fetchTimeout       = 8 * time.Second
	maxHTMLBytes       = 256 << 10 // 256 KiB — only need the <head>
	maxFaviconBytes    = 512 << 10 // 512 KiB
)

var httpClient = &http.Client{
	Timeout: fetchTimeout,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// HostMetaHandler returns the title and whether a favicon exists for a host.
// Results are cached for 24h.
func HostMetaHandler(cs cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host parameter", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		cacheKey := metaCachePrefix + host

		if cached, ok, _ := cache.GetJSON[hostMeta](ctx, cs, cacheKey); ok {
			writeJSON(w, http.StatusOK, cached)
			return
		}

		meta := fetchHostMeta(ctx, host)

		_ = cache.SetJSON(ctx, cs, cacheKey, meta, metaTTL)
		if meta.HasFavicon && meta.faviconBytes != nil {
			_ = cs.Set(ctx, faviconCachePrefix+host, meta.faviconBytes, metaTTL)
		}

		writeJSON(w, http.StatusOK, meta)
	}
}

// HostFaviconHandler serves the cached favicon bytes for a host.
func HostFaviconHandler(cs cache.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" {
			http.Error(w, "missing host parameter", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		data, ok, _ := cs.Get(ctx, faviconCachePrefix+host)
		if !ok || len(data) == 0 {
			meta := fetchHostMeta(ctx, host)
			_ = cache.SetJSON(ctx, cs, metaCachePrefix+host, meta, metaTTL)
			if meta.HasFavicon && meta.faviconBytes != nil {
				_ = cs.Set(ctx, faviconCachePrefix+host, meta.faviconBytes, metaTTL)
				data = meta.faviconBytes
			}
			if len(data) == 0 {
				http.NotFound(w, r)
				return
			}
		}

		contentType := http.DetectContentType(data)
		// DetectContentType doesn't recognize SVG
		if strings.Contains(string(data[:min(len(data), 512)]), "<svg") {
			contentType = "image/svg+xml"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}
}

func fetchHostMeta(ctx context.Context, host string) hostMeta {
	meta := hostMeta{}

	// Try HTTPS first, fall back to HTTP
	baseURL := "https://" + host
	htmlBody, err := fetchBody(ctx, baseURL, maxHTMLBytes)
	if err != nil {
		baseURL = "http://" + host
		htmlBody, err = fetchBody(ctx, baseURL, maxHTMLBytes)
		if err != nil {
			return meta
		}
	}

	html := string(htmlBody)

	// Extract <title>
	if m := titleRe.FindStringSubmatch(html); len(m) > 1 {
		title := strings.TrimSpace(m[1])
		// Strip HTML entities and tags that might be inside <title>
		title = regexp.MustCompile(`<[^>]*>`).ReplaceAllString(title, "")
		title = strings.ReplaceAll(title, "&amp;", "&")
		title = strings.ReplaceAll(title, "&lt;", "<")
		title = strings.ReplaceAll(title, "&gt;", ">")
		title = strings.ReplaceAll(title, "&#39;", "'")
		title = strings.ReplaceAll(title, "&quot;", "\"")
		meta.Title = title
	}

	// Extract all favicon candidates from <link> tags, prefer rel="icon" over apple-touch-icon
	faviconHrefs := extractFaviconHrefs(html)

	// Build candidate URLs: parsed hrefs first, then common fallbacks
	var candidates []string
	for _, href := range faviconHrefs {
		candidates = append(candidates, resolveURL(baseURL, href))
	}
	// Always try common fallback paths
	candidates = append(candidates,
		baseURL+"/favicon.ico",
		baseURL+"/favicon.png",
		baseURL+"/favicon.svg",
	)
	// Deduplicate while preserving order
	candidates = dedupStrings(candidates)

	// Try each candidate until one works
	for _, u := range candidates {
		favBytes, fetchErr := fetchBody(ctx, u, maxFaviconBytes)
		if fetchErr != nil || len(favBytes) == 0 {
			continue
		}
		if !looksLikeImage(favBytes) {
			continue
		}
		meta.FaviconURL = u
		meta.HasFavicon = true
		meta.FaviconType = detectImageType(favBytes)
		meta.faviconBytes = favBytes
		break
	}

	return meta
}

// extractFaviconHrefs returns all href values from <link> tags with rel containing "icon",
// ordered with rel="icon" first, then apple-touch-icon, etc.
func extractFaviconHrefs(html string) []string {
	matches := faviconRe.FindAllString(html, -1)
	var preferred, fallback []string
	for _, m := range matches {
		hm := hrefRe.FindStringSubmatch(m)
		if len(hm) < 2 || hm[1] == "" {
			continue
		}
		lower := strings.ToLower(m)
		if strings.Contains(lower, `rel="icon"`) || strings.Contains(lower, `rel='icon'`) ||
			strings.Contains(lower, `rel="shortcut icon"`) || strings.Contains(lower, `rel='shortcut icon'`) {
			preferred = append(preferred, hm[1])
		} else {
			fallback = append(fallback, hm[1])
		}
	}
	return append(preferred, fallback...)
}

func looksLikeImage(data []byte) bool {
	ct := http.DetectContentType(data)
	if strings.HasPrefix(ct, "image/") {
		return true
	}
	// DetectContentType misses SVGs (detected as text/xml or text/plain)
	prefix := string(data[:min(len(data), 512)])
	return strings.Contains(prefix, "<svg")
}

func detectImageType(data []byte) string {
	ct := http.DetectContentType(data)
	if strings.HasPrefix(ct, "image/") {
		return ct
	}
	prefix := string(data[:min(len(data), 512)])
	if strings.Contains(prefix, "<svg") {
		return "image/svg+xml"
	}
	return ct
}

func fetchBody(ctx context.Context, targetURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SPAM-Monitor/1.0)")
	req.Header.Set("Accept", "text/html,image/*,*/*")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func resolveURL(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}
	return baseURL.ResolveReference(ref).String()
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
