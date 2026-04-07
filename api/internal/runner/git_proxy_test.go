package runner

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestValidateGitProxyRequest(t *testing.T) {
	t.Run("allows info refs upload pack", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/runner/git/run/info/refs?service=git-upload-pack", nil)
		if err := validateGitProxyRequest(req, gitSmartHTTPInfoRefs); err != nil {
			t.Fatalf("validateGitProxyRequest returned error: %v", err)
		}
	})

	t.Run("allows upload pack post", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/runner/git/run/git-upload-pack", nil)
		if err := validateGitProxyRequest(req, gitSmartHTTPUploadPack); err != nil {
			t.Fatalf("validateGitProxyRequest returned error: %v", err)
		}
	})

	t.Run("rejects receive pack", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/runner/git/run/git-receive-pack", nil)
		if err := validateGitProxyRequest(req, "git-receive-pack"); err == nil {
			t.Fatal("expected git-receive-pack to be rejected")
		}
	})

	t.Run("rejects unexpected query params", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/runner/git/run/info/refs?service=git-upload-pack&foo=bar", nil)
		if err := validateGitProxyRequest(req, gitSmartHTTPInfoRefs); err == nil {
			t.Fatal("expected unexpected query params to be rejected")
		}
	})
}

func TestBuildGitProxyUpstreamURL(t *testing.T) {
	base, err := url.Parse("https://github.example.com/org/repo.git")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	target := buildGitProxyUpstreamURL(base, gitSmartHTTPInfoRefs, "service=git-upload-pack")
	if got, want := target.String(), "https://github.example.com/org/repo.git/info/refs?service=git-upload-pack"; got != want {
		t.Fatalf("unexpected upstream URL: got %q want %q", got, want)
	}
}

func TestRewriteGitProxyRequest(t *testing.T) {
	in := httptest.NewRequest(http.MethodGet, "http://worker/runner/git/run-123/info/refs?service=git-upload-pack", nil)
	out := in.Clone(in.Context())
	base, err := url.Parse("https://git.example.com/org/repo.git")
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	pr := &httputil.ProxyRequest{In: in, Out: out}
	rewriteGitProxyRequest(pr, base, gitSmartHTTPInfoRefs, "service=git-upload-pack", "secret-token")

	if got, want := pr.Out.URL.String(), "https://git.example.com/org/repo.git/info/refs?service=git-upload-pack"; got != want {
		t.Fatalf("unexpected rewritten URL: got %q want %q", got, want)
	}
	if got, want := pr.Out.Host, "git.example.com"; got != want {
		t.Fatalf("unexpected host: got %q want %q", got, want)
	}
	username, password, ok := pr.Out.BasicAuth()
	if !ok || username != "token" || password != "secret-token" {
		t.Fatalf("expected basic auth to be set, got ok=%v username=%q password=%q", ok, username, password)
	}
}
