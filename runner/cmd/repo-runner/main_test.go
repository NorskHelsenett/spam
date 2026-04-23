package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestBuildGitProxyCloneURL(t *testing.T) {
	got := buildGitProxyCloneURL("http://worker:8081/", "run-123")
	want := "http://worker:8081/runner/git/run-123"
	if got != want {
		t.Fatalf("buildGitProxyCloneURL() = %q, want %q", got, want)
	}
}

func TestEnsureExternalEgressBlocked(t *testing.T) {
	t.Run("returns error when tcp probe succeeds", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err == nil {
				conn.Close()
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := ensureExternalEgressBlocked(ctx, listener.Addr().String()); err == nil {
			t.Fatal("expected reachable probe URL to fail the self-test")
		}
	})

	t.Run("passes when probe is unreachable", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		addr := listener.Addr().String()
		listener.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := ensureExternalEgressBlocked(ctx, "http://"+addr); err != nil {
			t.Fatalf("expected unreachable probe URL to pass, got %v", err)
		}
	})
}

func TestParseEgressProbeAddress(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "https://github.com", want: "github.com:443"},
		{in: "http://example.com/path", want: "example.com:80"},
		{in: "github.com", want: "github.com:443"},
		{in: "github.com:8443", want: "github.com:8443"},
	}

	for _, tt := range tests {
		got, err := parseEgressProbeAddress(tt.in)
		if err != nil {
			t.Fatalf("parseEgressProbeAddress(%q) returned error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("parseEgressProbeAddress(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestClearRunEnv(t *testing.T) {
	t.Setenv("WORKER_URL", "http://worker:8081")
	t.Setenv("RUN_TOKEN", "token")
	t.Setenv("REPO_CLONE_URL", "https://git.example.com/org/repo.git")

	clearRunEnv()

	for _, key := range []string{"WORKER_URL", "RUN_TOKEN", "REPO_CLONE_URL"} {
		if got := os.Getenv(key); got != "" {
			t.Fatalf("expected %s to be cleared, got %q", key, got)
		}
	}
}
