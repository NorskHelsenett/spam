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
	FaviconURL     string `json:"favicon_url,omitempty"`     // original URL for reference
	HasFavicon     bool   `json:"has_favicon"`
	FaviconType    string `json:"favicon_type,omitempty"`
	faviconBytes   []byte // not serialized to JSON, stored separately
}

var (
	titleRe   = regexp.MustCompile(`(?i)<title[^>]*>\s*(.*?)\s*</title>`)
	faviconRe = regexp.MustCompile(`(?i)<link[^>]+rel\s*=\s*["'](?:shortcut )?icon["'][^>]*>`)
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
			// Try fetching if not cached yet
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
		meta.Title = strings.TrimSpace(m[1])
	}

	// Extract favicon URL from <link rel="icon" href="...">
	faviconHref := ""
	if m := faviconRe.FindString(html); m != "" {
		if hm := hrefRe.FindStringSubmatch(m); len(hm) > 1 {
			faviconHref = hm[1]
		}
	}

	// Resolve favicon URL
	faviconURL := ""
	if faviconHref != "" {
		faviconURL = resolveURL(baseURL, faviconHref)
	} else {
		faviconURL = baseURL + "/favicon.ico"
	}
	meta.FaviconURL = faviconURL

	// Fetch the favicon
	favBytes, err := fetchBody(ctx, faviconURL, maxFaviconBytes)
	if err != nil || len(favBytes) == 0 {
		return meta
	}

	ct := http.DetectContentType(favBytes)
	if !strings.HasPrefix(ct, "image/") {
		return meta
	}

	meta.HasFavicon = true
	meta.FaviconType = ct
	meta.faviconBytes = favBytes

	return meta
}

func fetchBody(ctx context.Context, targetURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SPAM-Monitor/1.0")

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
