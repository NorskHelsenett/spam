// trivy-scanner loops through unscanned SBOMs and uploads Trivy results.
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

func main() {
	if err := run(); err != nil {
		log.Fatalf("trivy-scanner: %v", err)
	}
}

func run() error {
	apiURL := strings.TrimRight(os.Getenv("SPAM_API_URL"), "/")
	if apiURL == "" {
		return fmt.Errorf("SPAM_API_URL is required")
	}
	hmacKey := parseHMACKey(os.Getenv("RUNNER_HMAC_KEY"))
	runStartedAt := time.Now().UTC()

	cacheDir := os.Getenv("TRIVY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/trivy-cache"
	}

	log.Printf("downloading trivy vulnerability database …")
	if err := trivyDownloadDB(cacheDir); err != nil {
		return fmt.Errorf("trivy db download: %w", err)
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

		log.Printf("scanning sbom_id=%s repo=%s", job.SBOMID, job.RepoSlug)
		if err := scanSBOM(apiURL, hmacKey, cacheDir, job); err != nil {
			log.Printf("WARNING: scan failed sbom_id=%s: %v (continuing)", job.SBOMID, err)
		}
	}
}

// nextJobResponse mirrors the JSON returned by GET /api/trivy/next.
type nextJobResponse struct {
	SBOMID   string `json:"sbom_id"`
	RepoID   string `json:"repo_id"`
	Format   string `json:"format"`
	RepoSlug string `json:"repo_slug"`
}

func fetchNextJob(apiURL string, hmacKey []byte, runStartedAt time.Time) (*nextJobResponse, bool, error) {
	params := url.Values{}
	params.Set("run_started_at", runStartedAt.Format(time.RFC3339))
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/trivy/next?"+params.Encode(), nil)
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

func scanSBOM(apiURL string, hmacKey []byte, cacheDir string, job *nextJobResponse) error {
	// Create temp directory for this scan.
	tmpDir, err := os.MkdirTemp("", "trivy-scan-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Download the SBOM content.
	sbomPath := filepath.Join(tmpDir, "sbom.json")
	sbomBytes, err := downloadSBOM(apiURL, hmacKey, job.SBOMID, sbomPath)
	if err != nil {
		return fmt.Errorf("download sbom: %w", err)
	}

	// Run trivy — fall back to filesystem scan when the SBOM is a leaf (0 or 1 components).
	resultPath := filepath.Join(tmpDir, "result.json")
	if countSBOMComponents(sbomBytes) <= 1 && job.RepoID != "" {
		log.Printf("sbom_id=%s has ≤1 components, fetching manifests for fs scan", job.SBOMID)
		manifestDir := filepath.Join(tmpDir, "manifests")
		if err := fetchAndWriteManifests(apiURL, hmacKey, job.RepoID, manifestDir); err != nil {
			log.Printf("WARNING: could not fetch manifests, falling back to sbom scan: %v", err)
			if err := trivyScanSBOM(cacheDir, sbomPath, resultPath); err != nil {
				return fmt.Errorf("trivy scan: %w", err)
			}
		} else if err := trivyScanFS(cacheDir, manifestDir, resultPath); err != nil {
			return fmt.Errorf("trivy fs scan: %w", err)
		}
	} else {
		if err := trivyScanSBOM(cacheDir, sbomPath, resultPath); err != nil {
			return fmt.Errorf("trivy scan: %w", err)
		}
	}

	// Upload result.
	resultBytes, err := os.ReadFile(resultPath)
	if err != nil {
		return fmt.Errorf("read result: %w", err)
	}

	url := fmt.Sprintf("%s/api/trivy/result/%s?repo_id=%s", apiURL, job.SBOMID, job.RepoID)
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

	log.Printf("stored result for sbom_id=%s", job.SBOMID)
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

// countSBOMComponents returns the number of components in a CycloneDX or SPDX SBOM.
func countSBOMComponents(data []byte) int {
	var cdx struct {
		Metadata struct {
			Component struct {
				BomRef string `json:"bom-ref"`
				Purl   string `json:"purl"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			BomRef string `json:"bom-ref"`
			Purl   string `json:"purl"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &cdx); err == nil && cdx.Components != nil {
		rootRef := firstNonEmpty(cdx.Metadata.Component.BomRef, cdx.Metadata.Component.Purl)
		if rootRef == "" && isImplicitCycloneDXRoot(cdx.Components, cdx.Dependencies) {
			rootRef = firstNonEmpty(cdx.Components[0].BomRef, cdx.Components[0].Purl)
		}
		count := 0
		for _, component := range cdx.Components {
			componentRef := firstNonEmpty(component.BomRef, component.Purl)
			if rootRef == "" || componentRef != rootRef {
				count++
			}
		}
		return count
	}
	// SPDX fallback: count packages (excluding DESCRIBES relationship root)
	var spdx struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &spdx); err == nil {
		if len(spdx.Packages) > 0 {
			return len(spdx.Packages) - 1
		}
		return 0
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func isImplicitCycloneDXRoot(
	components []struct {
		BomRef string `json:"bom-ref"`
		Purl   string `json:"purl"`
	},
	dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	},
) bool {
	if len(components) != 1 || len(dependencies) != 1 {
		return false
	}
	componentRef := firstNonEmpty(components[0].BomRef, components[0].Purl)
	if componentRef == "" || dependencies[0].Ref != componentRef {
		return false
	}
	return len(dependencies[0].DependsOn) == 0
}

type manifestFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// fetchAndWriteManifests downloads the repo's manifest files from the API and
// writes them into dir so Trivy can scan them with `trivy fs`.
func fetchAndWriteManifests(apiURL string, hmacKey []byte, repoID, dir string) error {
	url := apiURL + "/api/trivy/manifests/" + repoID
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	signRequest(req, nil, hmacKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var files []manifestFile
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return fmt.Errorf("decode manifests: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no manifest files available for repo %s", repoID)
	}

	for _, f := range files {
		dest := filepath.Join(dir, f.Path)
		if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(dest, []byte(f.Content), 0644); err != nil {
			return err
		}
	}
	log.Printf("wrote %d manifest file(s) to %s", len(files), dir)
	return nil
}

func trivyDownloadDB(cacheDir string) error {
	cmd := exec.Command("trivy", "image", "--download-db-only", "--cache-dir", cacheDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func trivyScanSBOM(cacheDir, sbomPath, resultPath string) error {
	cmd := exec.Command(
		"trivy", "sbom", sbomPath,
		"--skip-db-update",
		"--cache-dir", cacheDir,
		"--format", "json",
		"--output", resultPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func trivyScanFS(cacheDir, dir, resultPath string) error {
	cmd := exec.Command(
		"trivy", "fs", dir,
		"--skip-db-update",
		"--cache-dir", cacheDir,
		"--format", "json",
		"--output", resultPath,
	)
	cmd.Stdout = os.Stdout
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
