// spam-image-scanner leases IMAGE_SCAN jobs from the worker API, runs a
// pluggable set of scanners (grype, syft, cosign, crane, betterleaks;
// trivy opt-in per category) against each image digest, and uploads the
// results. It mirrors the trivy-scanner's "init-container downloads DB once,
// main loops until queue empty" shape so the vuln DB stays warm across all
// scans in a single CronJob tick.
//
// Environment:
//
//	SPAM_API_URL        base URL of the worker (e.g. http://spam-worker:8081)
//	RUNNER_HMAC_KEY     shared HMAC secret (base64 or raw) for lease/complete
//	WORK_DIR            scratch dir for rootfs + artifacts (default /work)
//	GRYPE_DB_CACHE_DIR  grype DB cache (default /grype-cache)
//	SCAN_DEADLINE_SECONDS per-scan deadline (default 900)
//
// Exit codes:
//
//	0 — queue drained cleanly
//	2 — configuration error
//	3 — DB download failed (cannot scan without a DB)
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NorskHelsenett/spam/runner/imagescan"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("image-scanner: %v", err)
	}
}

func run() error {
	apiURL := strings.TrimRight(os.Getenv("SPAM_API_URL"), "/")
	if apiURL == "" {
		return fail(2, "SPAM_API_URL is required")
	}
	hmacKey, err := parseHMACKey(os.Getenv("RUNNER_HMAC_KEY"))
	if err != nil {
		return fail(2, "RUNNER_HMAC_KEY: %v", err)
	}

	workDir := getenv("WORK_DIR", "/work")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fail(2, "mkdir WORK_DIR: %v", err)
	}

	scanDeadline := time.Duration(parseIntEnv("SCAN_DEADLINE_SECONDS", 900)) * time.Second

	// Graceful shutdown: finish current scan, don't start a new one.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Probe the worker BEFORE the 30–60s grype DB download so a cron tick
	// into an empty queue exits in seconds instead of minutes. The count
	// is allowed to drift — if work arrives between probe and exit the
	// next worker-triggered burst (or the next cron tick) picks it up.
	pending, err := fetchPending(ctx, apiURL, hmacKey)
	if err != nil {
		// Don't treat a probe failure as fatal — log and proceed as if
		// work exists. Worst case: one wasted DB download.
		log.Printf("WARN: pending probe failed: %v (proceeding anyway)", err)
	} else if pending == 0 {
		log.Printf("queue empty — nothing to scan, exiting before DB download")
		return nil
	} else {
		log.Printf("queue has %d pending scan(s) — downloading DB", pending)
	}

	log.Printf("downloading vulnerability database (grype) …")
	if err := grypeDBUpdate(ctx); err != nil {
		return fail(3, "grype db update: %v", err)
	}
	log.Printf("grype DB ready; entering lease loop")

	scans := 0
	for {
		if err := ctx.Err(); err != nil {
			log.Printf("shutting down: %v", err)
			return nil
		}

		lease, err := fetchNext(ctx, apiURL, hmacKey)
		if err != nil {
			return fmt.Errorf("fetch next: %w", err)
		}
		if lease == nil {
			log.Printf("queue drained after %d scan(s) — exiting", scans)
			return nil
		}
		scans++

		scanCtx, cancel := context.WithTimeout(ctx, scanDeadline)
		scanErr := runOne(scanCtx, apiURL, hmacKey, workDir, lease)
		cancel()

		status, errMsg := "succeeded", ""
		if scanErr != nil {
			status = "failed"
			errMsg = scanErr.Error()
			log.Printf("scan %s FAILED: %v", lease.JobID, scanErr)
		} else {
			log.Printf("scan %s succeeded", lease.JobID)
		}
		if err := postComplete(ctx, apiURL, hmacKey, lease.JobID, status, errMsg); err != nil {
			// We don't abort the loop for completion failures — the worker's
			// stale-job timer will eventually reclaim the job. Log and move on.
			log.Printf("WARN: mark complete %s failed: %v", lease.JobID, err)
		}
	}
}

// lease is the subset of the lease response this binary cares about.
type lease struct {
	JobID         string            `json:"job_id"`
	ImageDigestID string            `json:"image_digest_id"`
	Registry      string            `json:"registry"`
	Repository    string            `json:"repository"`
	Digest        string            `json:"digest"`
	Scanners      map[string]string `json:"scanners,omitempty"`
	RunToken      string            `json:"run_token"`
	WorkerURL     string            `json:"worker_url"`
}

// fetchPending is a cheap non-claiming probe of the queue. Returns the
// count of IMAGE_SCAN jobs ready to be claimed (QUEUED or RETRY with
// run_at <= now). Used to short-circuit DB download on empty queues.
func fetchPending(ctx context.Context, apiURL string, hmacKey []byte) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/image-scans/pending", nil)
	if err != nil {
		return 0, err
	}
	signRequest(req, nil, hmacKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return 0, fmt.Errorf("pending probe failed: %d %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var body struct {
		Pending int64 `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, fmt.Errorf("decode pending: %w", err)
	}
	return body.Pending, nil
}

func fetchNext(ctx context.Context, apiURL string, hmacKey []byte) (*lease, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/image-scans/next", nil)
	if err != nil {
		return nil, err
	}
	signRequest(req, nil, hmacKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("lease failed: %d %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var l lease
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return nil, fmt.Errorf("decode lease: %w", err)
	}
	if l.JobID == "" || l.Digest == "" {
		return nil, errors.New("lease missing required fields")
	}
	// Default worker_url to the one we already know, so scanner keeps working
	// even if the API forgot to set it.
	if l.WorkerURL == "" {
		l.WorkerURL = apiURL
	}
	return &l, nil
}

func runOne(ctx context.Context, apiURL string, hmacKey []byte, workBase string, l *lease) error {
	scanWorkDir, cleanup, err := imagescan.NewWorkDir(workBase, l.JobID)
	if err != nil {
		return fmt.Errorf("new work dir: %w", err)
	}
	defer cleanup()

	log.Printf("scanning %s/%s@%s (job=%s)", l.Registry, l.Repository, l.Digest, l.JobID)
	res, err := imagescan.Scan(ctx,
		imagescan.ImageRef{Registry: l.Registry, Repository: l.Repository, Digest: l.Digest},
		l.Scanners,
		scanWorkDir,
		imagescan.StdoutLogger(),
	)
	if err != nil {
		return fmt.Errorf("scan pipeline: %w", err)
	}
	if len(res.Artifacts) == 0 {
		// If everything failed, surface the *first* category error so the
		// job's error field is actionable rather than a generic "no output".
		for cat, e := range res.Failed {
			return fmt.Errorf("no artifacts produced; %s: %v", cat, e)
		}
		return errors.New("no artifacts produced")
	}

	sent, err := imagescan.Upload(ctx, imagescan.UploadOpts{
		WorkerURL:     l.WorkerURL,
		RunToken:      l.RunToken,
		JobID:         l.JobID,
		ImageDigestID: l.ImageDigestID,
	}, res.Artifacts)
	if err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	log.Printf("uploaded %d artifact(s) for job %s", sent, l.JobID)

	if len(res.Failed) > 0 {
		// Partial success — log warnings but don't fail the job. Artifacts
		// that did upload are still useful downstream.
		for cat, e := range res.Failed {
			log.Printf("WARN: %s: %v", cat, e)
		}
	}
	return nil
}

func postComplete(ctx context.Context, apiURL string, hmacKey []byte, jobID, status, errMsg string) error {
	body, err := json.Marshal(map[string]string{"status": status, "error": errMsg})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		apiURL+"/api/image-scans/"+jobID+"/complete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	signRequest(req, body, hmacKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("complete failed: %d %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// -----------------------------------------------------------------------------
// DB warmup
// -----------------------------------------------------------------------------

// grypeDBUpdate runs `grype db update` once at startup. If GRYPE_DB_UPDATE_URL
// is set, grype will pull from the in-cluster mirror rather than the public
// CDN — that's how operators opt into an offline or air-gapped setup.
func grypeDBUpdate(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "grype", "db", "update")
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// signRequest attaches X-Scanner-Signature matching the API's
// auth.HMACMiddleware: a hex-encoded HMAC-SHA256 of the raw request body.
// For GET requests body is nil and the signature is over an empty payload.
func signRequest(req *http.Request, body []byte, key []byte) {
	if len(key) == 0 {
		return
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	req.Header.Set("X-Scanner-Signature", hex.EncodeToString(mac.Sum(nil)))
}

// parseHMACKey accepts either raw or base64 key material; mirrors the API's
// parsing so operators can configure either form interchangeably.
func parseHMACKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty key")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if len(raw) < 32 {
		return nil, errors.New("key must be at least 32 bytes")
	}
	return []byte(raw), nil
}

// -----------------------------------------------------------------------------
// tiny helpers
// -----------------------------------------------------------------------------

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func parseIntEnv(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func fail(code int, format string, args ...any) error {
	log.Printf(format, args...)
	os.Exit(code)
	return nil
}
