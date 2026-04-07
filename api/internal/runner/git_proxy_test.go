package runner

import (
	"net/http"
	"net/http/httptest"
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
