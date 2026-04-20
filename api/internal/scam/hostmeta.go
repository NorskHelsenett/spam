package scam

import (
	"context"
	"fmt"
	"io"
	"net"
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
	// Match any <link> with rel containing "icon" (covers icon, shortcut icon, apple-touch-icon, mask-icon).
	// Handles both quoted (rel="icon") and unquoted (rel=icon) attribute values.
	faviconRe = regexp.MustCompile(`(?i)<link[^>]+rel\s*=\s*(?:["'][^"']*icon[^"']*["']|[^\s>"']*icon[^\s>"']*)[^>]*>`)
	hrefRe    = regexp.MustCompile(`(?i)href\s*=\s*(?:["']([^"']+)["']|([^\s>"']+))`)
)

const (
	metaCachePrefix    = "hostmeta:"
	faviconCachePrefix = "hostfav:"
	metaTTL            = 24 * time.Hour
	fetchTimeout       = 8 * time.Second
	maxHTMLBytes       = 256 << 10 // 256 KiB — only need the <head>
	maxFaviconBytes    = 512 << 10 // 512 KiB
)

var safeDialer = &net.Dialer{Timeout: fetchTimeout}

// safeDialContext resolves the target hostname, rejects any address that
// belongs to a private / loopback / link-local / metadata range, and dials
// the resolved IP directly so DNS rebinding can't swap it after the check.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("blocked address: %s", ip)
		}
	}
	return safeDialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

var httpClient = &http.Client{
	Timeout: fetchTimeout,
	Transport: &http.Transport{
		DialContext: safeDialContext,
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

		// Only serve content that DetectContentType classifies as a safe
		// raster image type. SVG is rejected outright — it can carry
		// inline script that executes when loaded as a top-level document
		// from our origin.
		contentType := http.DetectContentType(data)
		if !isSafeImageType(contentType) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}
}

func fetchHostMeta(ctx context.Context, host string) hostMeta {
	meta := hostMeta{}

	// Try HTTPS first, fall back to HTTP. Use the final URL after redirects
	// as the base for resolving relative hrefs (e.g., Jellyfin 302→/web/).
	baseURL := "https://" + host
	htmlBody, finalURL, err := fetchBody(ctx, baseURL, maxHTMLBytes)
	if err != nil {
		baseURL = "http://" + host
		htmlBody, finalURL, err = fetchBody(ctx, baseURL, maxHTMLBytes)
		if err != nil {
			return meta
		}
	}
	baseURL = finalURL

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
		if u := resolveURL(baseURL, href); u != "" {
			candidates = append(candidates, u)
		}
	}
	// Always try common fallback paths
	candidates = append(candidates,
		baseURL+"/favicon.ico",
		baseURL+"/favicon.png",
	)
	// Deduplicate while preserving order
	candidates = dedupStrings(candidates)

	// Try each candidate until one works
	for _, u := range candidates {
		favBytes, _, fetchErr := fetchBody(ctx, u, maxFaviconBytes)
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
		if len(hm) < 2 {
			continue
		}
		// hm[1] is the quoted capture, hm[2] is the unquoted capture
		href := hm[1]
		if href == "" && len(hm) > 2 {
			href = hm[2]
		}
		if href == "" {
			continue
		}
		// Strip any trailing > that might leak into unquoted values
		href = strings.TrimRight(href, ">")
		lower := strings.ToLower(m)
		if strings.Contains(lower, `rel="icon"`) || strings.Contains(lower, `rel='icon'`) ||
			strings.Contains(lower, `rel="shortcut icon"`) || strings.Contains(lower, `rel='shortcut icon'`) ||
			strings.Contains(lower, `rel=icon`) {
			preferred = append(preferred, href)
		} else {
			fallback = append(fallback, href)
		}
	}
	return append(preferred, fallback...)
}

// isSafeImageType returns true for raster image types we are willing to
// proxy through HostFaviconHandler. SVG is intentionally excluded — it is
// an active content format (can contain <script>) and serving it at our
// origin would expose us to stored XSS via attacker-controlled favicons.
func isSafeImageType(ct string) bool {
	switch strings.SplitN(ct, ";", 2)[0] {
	case "image/png", "image/jpeg", "image/gif", "image/webp",
		"image/x-icon", "image/vnd.microsoft.icon", "image/bmp":
		return true
	}
	return false
}

func looksLikeImage(data []byte) bool {
	return isSafeImageType(http.DetectContentType(data))
}

func detectImageType(data []byte) string {
	ct := http.DetectContentType(data)
	if isSafeImageType(ct) {
		return ct
	}
	return ""
}

// fetchBody fetches a URL and returns the body bytes and the final URL after
// any redirects. The final URL is needed to correctly resolve relative hrefs
// (e.g., a favicon path) when the server redirected to a different path.
func fetchBody(ctx context.Context, targetURL string, maxBytes int64) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, targetURL, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SPAM-Monitor/1.0)")
	req.Header.Set("Accept", "text/html,image/*,*/*")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, targetURL, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	if resp.StatusCode >= 400 {
		return nil, finalURL, fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	return body, finalURL, err
}

// resolveURL resolves a favicon href against the base URL. Absolute hrefs are
// only honored when they point at the same host as the base, so a page served
// by an attacker can't redirect our fetch to an arbitrary origin.
func resolveURL(base, href string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	if ref.IsAbs() {
		if !strings.EqualFold(ref.Host, baseURL.Host) {
			return ""
		}
		return ref.String()
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
