package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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
	t.Run("returns error when probe succeeds", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := ensureExternalEgressBlocked(ctx, server.URL); err == nil {
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
