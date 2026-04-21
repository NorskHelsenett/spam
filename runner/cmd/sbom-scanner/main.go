// sbom-scanner loops through unscanned SBOMs and uploads vulnerability
// results. Today the only tool wired in is trivy; grype support is planned
// and will be selected at runtime via SBOM_SCANNER once the backend
// ingest can parse grype output.
//
// Environment variables:
//
//	SPAM_API_URL     - base URL of the worker API (e.g. http://spam-worker:8081)
//	RUNNER_HMAC_KEY  - shared secret for request signing
//	TRIVY_CACHE_DIR  - trivy database cache dir (default: /trivy-cache)
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type toolVersion struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	BinaryDigest string `json:"binary_digest"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("sbom-scanner: %v", err)
	}
}

func run() error {
	apiURL := strings.TrimRight(os.Getenv("SPAM_API_URL"), "/")
	if apiURL == "" {
		return fmt.Errorf("SPAM_API_URL is required")
	}
	hmacKey := parseHMACKey(os.Getenv("RUNNER_HMAC_KEY"))
	runStartedAt := time.Now().UTC()

	// Report tool version + binary digest for auditability
	reportToolVersion(apiURL, hmacKey)

	log.Printf("downloading grype vulnerability database …")
	if err := grypeDBUpdate(); err != nil {
		return fmt.Errorf("grype db download: %w", err)
	}

	log.Printf("starting scan loop …")
	for {
		job, ok, err := fetchNextJob(apiURL, hmacKey, runStartedAt)
		if err != nil {
			return fmt.Errorf("fetch next job: %w", err)
		}
		if !ok {
			log.Printf("queue empty — exiting")
			return nil
		}

		assetLabel := job.RepoSlug
		if job.AssetType == "IMAGE_DIGEST" {
			assetLabel = "image:" + job.AssetRefID
		}
		log.Printf("scanning sbom_id=%s asset_type=%s target=%s", job.SBOMID, job.AssetType, assetLabel)
		if err := scanSBOM(apiURL, hmacKey, job); err != nil {
			log.Printf("WARNING: scan failed sbom_id=%s: %v (continuing)", job.SBOMID, err)
		}
	}
}

// nextJobResponse mirrors the JSON returned by GET /api/sbom-scan/next.
type nextJobResponse struct {
	SBOMID     string `json:"sbom_id"`
	RepoID     string `json:"repo_id"`
	Format     string `json:"format"`
	RepoSlug   string `json:"repo_slug"`
	AssetType  string `json:"asset_type"`
	AssetRefID string `json:"asset_ref_id"`
}

func fetchNextJob(apiURL string, hmacKey []byte, runStartedAt time.Time) (*nextJobResponse, bool, error) {
	params := url.Values{}
	params.Set("run_started_at", runStartedAt.Format(time.RFC3339))
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/sbom-scan/next?"+params.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	signRequest(req, nil, hmacKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var job nextJobResponse
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, false, fmt.Errorf("decode job: %w", err)
	}
	return &job, true, nil
}

func scanSBOM(apiURL string, hmacKey []byte, job *nextJobResponse) error {
	// Create temp directory for this scan.
	tmpDir, err := os.MkdirTemp("", "sbom-scan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Download the SBOM content.
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	if _, err := downloadSBOM(apiURL, hmacKey, job.SBOMID, sbomPath); err != nil {
		return fmt.Errorf("download sbom: %w", err)
	}

	// Grype handles both paths — same tool, different upload endpoint.
	// IMAGE_DIGEST writes image_vuln_findings; REPO_COMMIT writes
	// trivy_scan_results (with format=grype) for the dashboard.
	switch job.AssetType {
	case "IMAGE_DIGEST":
		return scanImageSBOM(apiURL, hmacKey, tmpDir, sbomPath, job)
	default:
		return scanRepoSBOM(apiURL, hmacKey, tmpDir, sbomPath, job)
	}
}

func scanRepoSBOM(apiURL string, hmacKey []byte, tmpDir, sbomPath string, job *nextJobResponse) error {
	// Grype against the SBOM. Dropped the previous "fs manifest fallback"
	// for ≤1-component SBOMs — that was trivy-specific. A hollow SBOM
	// yields zero findings, which is the honest answer; the upstream fix
	// is better SBOM generation, not re-scanning manifests on every tick.
	resultPath := filepath.Join(tmpDir, "grype.json")
	if err := grypeScanSBOM(sbomPath, resultPath); err != nil {
		return fmt.Errorf("grype scan: %w", err)
	}

	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		return fmt.Errorf("read grype result: %w", err)
	}

	// The /api/sbom-scan/result endpoint dispatches on root shape
	// (Results[] for trivy, matches[] for grype) so the same path
	// accepts either tool's output.
	url := fmt.Sprintf("%s/api/sbom-scan/result/%s?repo_id=%s", apiURL, job.SBOMID, job.RepoID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(resultBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	signRequest(req, resultBytes, hmacKey)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload result: status %d: %s", resp.StatusCode, body)
	}

	log.Printf("stored grype result for sbom_id=%s repo=%s", job.SBOMID, job.RepoSlug)
	return nil
}

func scanImageSBOM(apiURL string, hmacKey []byte, tmpDir, sbomPath string, job *nextJobResponse) error {
	resultPath := filepath.Join(tmpDir, "grype.json")
	if err := grypeScanSBOM(sbomPath, resultPath); err != nil {
		return fmt.Errorf("grype scan: %w", err)
	}

	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		return fmt.Errorf("read grype result: %w", err)
	}

	url := fmt.Sprintf("%s/api/sbom-scan/image-result/%s", apiURL, job.SBOMID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(resultBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	signRequest(req, resultBytes, hmacKey)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload grype result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload grype result: status %d: %s", resp.StatusCode, body)
	}

	log.Printf("stored grype result for image sbom_id=%s image_digest_id=%s", job.SBOMID, job.AssetRefID)
	return nil
}

func downloadSBOM(apiURL string, hmacKey []byte, sbomID, destPath string) ([]byte, error) {
	url := apiURL + "/api/sboms/" + sbomID + "/download"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	signRequest(req, nil, hmacKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return nil, err
	}
	return data, nil
}


func grypeDBUpdate() error {
	cmd := exec.Command("grype", "db", "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// grypeScanSBOM runs grype against a stored SBOM and writes the JSON
// result to resultPath. No image pull, no network call to a registry —
// all grype needs is the vuln DB (grype db update runs at container
// startup) and the SBOM file.
func grypeScanSBOM(sbomPath, resultPath string) error {
	out, err := os.OpenFile(resultPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.Command("grype", "sbom:"+sbomPath, "-o", "json")
	cmd.Stdout = out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// signRequest adds the X-Scanner-Signature header to r.
// For GET requests body should be nil; the signature is over an empty body.
func signRequest(r *http.Request, body []byte, hmacKey []byte) {
	if len(hmacKey) == 0 {
		return
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(body)
	r.Header.Set("X-Scanner-Signature", hex.EncodeToString(mac.Sum(nil)))
}

func binaryDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "unknown"
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func reportToolVersion(apiURL string, hmacKey []byte) {
	version := "unknown"
	if out, err := exec.Command("grype", "version", "-o", "text").Output(); err == nil {
		// grype emits its version on the first line.
		if idx := strings.IndexByte(string(out), '\n'); idx > 0 {
			version = strings.TrimSpace(string(out[:idx]))
		} else {
			version = strings.TrimSpace(string(out))
		}
	}
	digest := binaryDigest("/usr/local/bin/grype")
	log.Printf("Tool: grype | %s | %s", version, digest)

	payload, _ := json.Marshal(map[string]interface{}{
		"source": "sbom-scanner",
		"versions": []toolVersion{
			{Name: "grype", Version: version, BinaryDigest: digest},
		},
	})

	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/tool-versions", bytes.NewReader(payload))
	if err != nil {
		log.Printf("failed to report tool version: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	signRequest(req, payload, hmacKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("failed to report tool version: %v", err)
		return
	}
	resp.Body.Close()
}

func parseHMACKey(value string) []byte {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return key
	}
	return []byte(value)
}
