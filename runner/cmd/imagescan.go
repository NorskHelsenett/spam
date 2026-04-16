package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"nhooyr.io/websocket"
)

// ImageScanRunner runs all enabled scanners against one OCI image digest and
// uploads artifacts to the worker. It is independent of the repo-clone Runner
// because the env contract, workdir layout, and scanner set differ enough
// that shared state would be more confusing than helpful.
type ImageScanRunner struct {
	workerURL       string
	jobID           string
	token           string
	imageDigestID   string
	imageRegistry   string
	imageRepository string
	imageDigest     string
	scanners        map[string]string

	workDir     string // /work/<jobID>
	artifactDir string // /tmp/spam-runner/<jobID>/out
	rootfsDir   string // /work/<jobID>/rootfs (populated by crane export for fs scanners)

	ctx    context.Context
	cancel context.CancelFunc
	wsConn *websocket.Conn
	logCh  chan string
}

const (
	categoryVuln      = "vuln"
	categorySBOM      = "sbom"
	categorySecrets   = "secrets"
	categorySignature = "signature"
	categoryLabels    = "labels"
)

// defaultScanners mirrors api/internal/imagescan.DefaultScanner and stays in
// sync manually; the two packages are in different modules so a shared
// constant is not practical today.
var defaultScanners = map[string]string{
	categoryVuln:      "grype",
	categorySBOM:      "syft",
	categorySecrets:   "betterleaks",
	categorySignature: "cosign",
	categoryLabels:    "crane",
}

// runImageScanMode is the entrypoint for RUNNER_MODE=scan-image. It reads the
// image-scan env contract, runs each enabled scanner, uploads artifacts, and
// returns the process exit code.
func runImageScanMode() int {
	r, err := newImageScanRunner()
	if err != nil {
		log.Printf("imagescan: %v", err)
		return 2
	}
	defer r.cleanup()

	// Signal handling — same semantics as the repo Runner.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		<-sigCh
		r.log("Cancellation signal received")
		r.cancel()
	}()

	if err := r.connectWebSocket(); err != nil {
		log.Printf("imagescan: websocket connect failed: %v", err)
		return 3
	}
	defer r.wsConn.Close(websocket.StatusNormalClosure, "")

	go r.streamLogs()
	go r.monitorCancellation()

	r.log(fmt.Sprintf("Starting image scan: %s", r.jobID))
	r.log(fmt.Sprintf("Target: %s", r.imageRef()))

	exitCode := r.runPipeline()
	r.sendDone(exitCode)
	return exitCode
}

func newImageScanRunner() (*ImageScanRunner, error) {
	workerURL := os.Getenv("WORKER_URL")
	jobID := os.Getenv("RUN_ID")
	token := os.Getenv("RUN_TOKEN")
	imageDigestID := os.Getenv("IMAGE_DIGEST_ID")
	imageRegistry := os.Getenv("IMAGE_REGISTRY")
	imageRepository := os.Getenv("IMAGE_REPOSITORY")
	imageDigest := os.Getenv("IMAGE_DIGEST")
	scannersJSON := os.Getenv("IMAGE_SCANNERS")

	if workerURL == "" || jobID == "" || imageDigestID == "" ||
		imageRegistry == "" || imageRepository == "" || imageDigest == "" {
		return nil, fmt.Errorf("missing required env: WORKER_URL, RUN_ID, IMAGE_DIGEST_ID, IMAGE_REGISTRY, IMAGE_REPOSITORY, IMAGE_DIGEST")
	}
	if !strings.HasPrefix(imageDigest, "sha256:") {
		return nil, fmt.Errorf("IMAGE_DIGEST must be a full digest starting with sha256:, got %q", imageDigest)
	}

	scanners := map[string]string{}
	if scannersJSON != "" {
		if err := json.Unmarshal([]byte(scannersJSON), &scanners); err != nil {
			return nil, fmt.Errorf("invalid IMAGE_SCANNERS json: %w", err)
		}
	}
	// Clear sensitive env so we don't leak tokens into scanner subprocesses.
	for _, k := range []string{"WORKER_URL", "RUN_ID", "RUN_TOKEN", "IMAGE_DIGEST_ID", "IMAGE_SCANNERS"} {
		_ = os.Unsetenv(k)
	}

	workDir := filepath.Join("/work", jobID)
	artifactDir := filepath.Join(os.TempDir(), "spam-runner", jobID, "out")
	rootfsDir := filepath.Join(workDir, "rootfs")

	ctx, cancel := context.WithCancel(context.Background())
	return &ImageScanRunner{
		workerURL:       workerURL,
		jobID:           jobID,
		token:           token,
		imageDigestID:   imageDigestID,
		imageRegistry:   imageRegistry,
		imageRepository: imageRepository,
		imageDigest:     imageDigest,
		scanners:        scanners,
		workDir:         workDir,
		artifactDir:     artifactDir,
		rootfsDir:       rootfsDir,
		ctx:             ctx,
		cancel:          cancel,
		logCh:           make(chan string, 100),
	}, nil
}

func (r *ImageScanRunner) imageRef() string {
	return fmt.Sprintf("%s/%s@%s", r.imageRegistry, r.imageRepository, r.imageDigest)
}

func (r *ImageScanRunner) cleanup() {
	if r.workDir != "" && r.workDir != "/" {
		_ = os.RemoveAll(r.workDir)
	}
	if r.artifactDir != "" && r.artifactDir != "/" {
		_ = os.RemoveAll(r.artifactDir)
	}
}

func (r *ImageScanRunner) connectWebSocket() error {
	wsURL := strings.Replace(r.workerURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = fmt.Sprintf("%s/runner/ws?token=%s", wsURL, r.token)
	conn, _, err := websocket.Dial(r.ctx, wsURL, nil)
	if err != nil {
		return err
	}
	r.wsConn = conn
	return nil
}

func (r *ImageScanRunner) log(line string) {
	fmt.Println(line)
	select {
	case r.logCh <- line:
	case <-r.ctx.Done():
	}
}

func (r *ImageScanRunner) streamLogs() {
	for {
		select {
		case line := <-r.logCh:
			msg := LogMessage{Type: "log", Line: line, Ts: time.Now().UTC().Format(time.RFC3339)}
			if err := r.wsConn.Write(r.ctx, websocket.MessageText, mustJSON(msg)); err != nil {
				return
			}
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *ImageScanRunner) monitorCancellation() {
	for {
		_, data, err := r.wsConn.Read(r.ctx)
		if err != nil {
			return
		}
		var msg LogMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		if msg.Type == "cancel" {
			r.log("Cancellation requested")
			r.cancel()
			return
		}
	}
}

func (r *ImageScanRunner) sendDone(exitCode int) {
	msg := LogMessage{Type: "done", ExitCode: exitCode}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.wsConn.Write(ctx, websocket.MessageText, mustJSON(msg))
	time.Sleep(1 * time.Second)
}

// resolve returns the scanner name to use for a category, falling back to the
// default when unset.
func (r *ImageScanRunner) resolve(category string) string {
	if name, ok := r.scanners[category]; ok && name != "" {
		return name
	}
	return defaultScanners[category]
}

// runPipeline runs each scanner category. Per-category failures are logged
// but do not abort the run — partial results are still useful and the scan
// as a whole succeeds if we got through all categories.
func (r *ImageScanRunner) runPipeline() int {
	r.logToolVersions()

	if err := os.MkdirAll(r.artifactDir, 0o755); err != nil {
		r.log(fmt.Sprintf("Failed to create artifact dir: %v", err))
		return 1
	}
	r.log(fmt.Sprintf("Artifact directory: %s", r.artifactDir))

	results := map[string]string{} // field name -> file path

	// Run scanners. Order is chosen so filesystem-based scanners run after
	// `crane export` has populated the rootfs, and so that cheap metadata
	// lookups (labels, signature) come first for fast feedback.
	steps := []struct {
		category string
		run      func() (field string, path string, err error)
	}{
		{categoryLabels, r.scanLabels},
		{categorySignature, r.scanSignature},
		{categoryVuln, r.scanVuln},
		{categorySBOM, r.scanSBOM},
		{categorySecrets, r.scanSecrets},
	}
	for _, step := range steps {
		field, path, err := step.run()
		if err != nil {
			r.log(fmt.Sprintf("[%s] FAILED: %v", step.category, err))
			continue
		}
		if path == "" {
			continue
		}
		results[field] = path
		r.log(fmt.Sprintf("[%s] ok -> %s", step.category, filepath.Base(path)))
	}

	if len(results) == 0 {
		r.log("No scanner produced output — nothing to upload")
		return 1
	}

	if err := r.uploadArtifacts(results); err != nil {
		r.log(fmt.Sprintf("Upload failed: %v", err))
		return 1
	}
	r.log("Image scan completed successfully")
	return 0
}

// -----------------------------------------------------------------------------
// Scanner implementations. Each returns (uploadFieldName, outputFilePath, err).
// An empty outputFilePath means "nothing to upload for this category" and is
// not an error.
// -----------------------------------------------------------------------------

func (r *ImageScanRunner) scanLabels() (string, string, error) {
	name := r.resolve(categoryLabels)
	switch name {
	case "crane":
		out := filepath.Join(r.artifactDir, "labels.json")
		// `crane config` prints the raw OCI config JSON. We upload it whole;
		// the API extracts .config.Labels server-side.
		raw, err := r.captureCommand("crane", "config", r.imageRef())
		if err != nil {
			return "", "", err
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			return "", "", err
		}
		return "labels", out, nil
	default:
		return "", "", fmt.Errorf("unknown labels scanner %q", name)
	}
}

func (r *ImageScanRunner) scanSignature() (string, string, error) {
	name := r.resolve(categorySignature)
	switch name {
	case "cosign":
		out := filepath.Join(r.artifactDir, "cosign.json")
		// Keyless verification needs an identity policy; without one, cosign
		// verify fails for unsigned images. We run in `tree` mode which
		// always returns metadata (signed-or-not) so we can record the
		// verdict without crashing the pipeline.
		raw, err := r.captureCommand("cosign", "tree", r.imageRef())
		// cosign tree exits 0 even when nothing is attached. Failure here is
		// truly exceptional (network, auth).
		if err != nil {
			// Record the failure as a negative verdict rather than erroring.
			payload := map[string]any{
				"image":    r.imageRef(),
				"verifier": "cosign",
				"verified": false,
				"error":    err.Error(),
			}
			_ = writeJSON(out, payload)
			return "signature", out, nil
		}
		payload := map[string]any{
			"image":    r.imageRef(),
			"verifier": "cosign",
			"verified": len(raw) > 0,
			"tree_raw": string(raw),
		}
		if err := writeJSON(out, payload); err != nil {
			return "", "", err
		}
		return "signature", out, nil
	default:
		return "", "", fmt.Errorf("unknown signature scanner %q", name)
	}
}

func (r *ImageScanRunner) scanVuln() (string, string, error) {
	name := r.resolve(categoryVuln)
	switch name {
	case "grype":
		out := filepath.Join(r.artifactDir, "grype.json")
		if err := r.runCommand(out, "grype", r.imageRef(), "-o", "json"); err != nil {
			return "", "", err
		}
		return "grype", out, nil
	case "trivy":
		out := filepath.Join(r.artifactDir, "trivy-vuln.json")
		if err := r.runCommand(out, "trivy", "image", "--quiet", "--format", "json", r.imageRef()); err != nil {
			return "", "", err
		}
		return "trivy_vuln", out, nil
	default:
		return "", "", fmt.Errorf("unknown vuln scanner %q", name)
	}
}

func (r *ImageScanRunner) scanSBOM() (string, string, error) {
	name := r.resolve(categorySBOM)
	switch name {
	case "syft":
		out := filepath.Join(r.artifactDir, "sbom.json")
		if err := r.runCommand("", "syft", "scan", "-q", "-o", "cyclonedx-json="+out, r.imageRef()); err != nil {
			return "", "", err
		}
		return "sbom", out, nil
	case "trivy":
		out := filepath.Join(r.artifactDir, "sbom.json")
		if err := r.runCommand("", "trivy", "image", "--quiet", "--format", "cyclonedx", "--output", out, r.imageRef()); err != nil {
			return "", "", err
		}
		return "sbom", out, nil
	default:
		return "", "", fmt.Errorf("unknown sbom scanner %q", name)
	}
}

func (r *ImageScanRunner) scanSecrets() (string, string, error) {
	name := r.resolve(categorySecrets)
	// Filesystem-based secret scanners need an extracted rootfs.
	if name == "betterleaks" || name == "trivy" {
		if err := r.exportRootfs(); err != nil {
			return "", "", fmt.Errorf("rootfs export: %w", err)
		}
	}
	switch name {
	case "betterleaks":
		out := filepath.Join(r.artifactDir, "betterleaks.json")
		err := r.runCommand("", "betterleaks", "dir", r.rootfsDir,
			"--report-path", out, "--report-format", "json", "--no-banner")
		if err != nil {
			// betterleaks exits 1 when findings are present — not a failure.
			var ee *exec.ExitError
			if !isExitCode(err, &ee, 1) {
				return "", "", err
			}
		}
		if _, statErr := os.Stat(out); os.IsNotExist(statErr) {
			// No findings: write an empty array so the upload handler can
			// distinguish "ran, nothing found" from "did not run".
			_ = os.WriteFile(out, []byte("[]"), 0o644)
		}
		return "secrets", out, nil
	case "trivy":
		out := filepath.Join(r.artifactDir, "trivy-secrets.json")
		if err := r.runCommand("", "trivy", "fs", "--quiet", "--scanners", "secret", "--format", "json", "--output", out, r.rootfsDir); err != nil {
			return "", "", err
		}
		return "trivy_secrets", out, nil
	default:
		return "", "", fmt.Errorf("unknown secrets scanner %q", name)
	}
}

// exportRootfs streams `crane export <ref>` into a tar reader that unpacks
// into r.rootfsDir. Running it at most once per pipeline keeps downstream
// filesystem scanners cheap.
func (r *ImageScanRunner) exportRootfs() error {
	if _, err := os.Stat(r.rootfsDir); err == nil {
		return nil // already populated
	}
	if err := os.MkdirAll(r.rootfsDir, 0o755); err != nil {
		return err
	}
	r.log(fmt.Sprintf("Exporting image rootfs via crane to %s", r.rootfsDir))
	cmd := exec.CommandContext(r.ctx, "crane", "export", r.imageRef(), "-")
	cmd.Env = imageScanEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = &prefixWriter{prefix: "crane: ", cb: r.log}
	if err := cmd.Start(); err != nil {
		return err
	}
	tarCmd := exec.CommandContext(r.ctx, "tar", "-x", "-C", r.rootfsDir)
	tarCmd.Stdin = stdout
	tarCmd.Stderr = &prefixWriter{prefix: "tar: ", cb: r.log}
	if err := tarCmd.Run(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("tar extract: %w", err)
	}
	return cmd.Wait()
}

// -----------------------------------------------------------------------------
// Command helpers
// -----------------------------------------------------------------------------

// runCommand runs an external scanner and streams stdout/stderr to the log.
// If outPath is non-empty, stdout is also written to that file (for scanners
// that print results to stdout rather than taking an output path flag).
func (r *ImageScanRunner) runCommand(outPath string, name string, args ...string) error {
	cmd := exec.CommandContext(r.ctx, name, args...)
	cmd.Env = imageScanEnv()

	var outFile *os.File
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		outFile = f
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		sc := bufio.NewScanner(stdout)
		// Larger buffer to tolerate scanners that dump big JSON to stdout.
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if outFile != nil {
				fmt.Fprintln(outFile, line)
			} else {
				r.log(line)
			}
		}
	}()
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			r.log(fmt.Sprintf("%s: %s", name, sc.Text()))
		}
	}()
	return cmd.Wait()
}

// captureCommand runs a command and returns its stdout as bytes.
func (r *ImageScanRunner) captureCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(r.ctx, name, args...)
	cmd.Env = imageScanEnv()
	cmd.Stderr = &prefixWriter{prefix: name + ": ", cb: r.log}
	return cmd.Output()
}

// logToolVersions records versions of the image-scan toolchain so audit
// trails match what actually produced each artifact.
func (r *ImageScanRunner) logToolVersions() {
	tools := []struct{ name, path string }{
		{"grype", "/usr/local/bin/grype"},
		{"syft", "/usr/local/bin/syft"},
		{"cosign", "/usr/local/bin/cosign"},
		{"crane", "/usr/local/bin/crane"},
		{"betterleaks", "/usr/local/bin/betterleaks"},
		{"trivy", "/usr/local/bin/trivy"},
	}
	var versions []ToolVersion
	for _, t := range tools {
		digest := binaryDigest(t.path)
		version := "unknown"
		if out, err := exec.CommandContext(r.ctx, t.path, "--version").Output(); err == nil {
			first := strings.SplitN(string(out), "\n", 2)[0]
			version = strings.TrimSpace(first)
		}
		versions = append(versions, ToolVersion{Name: t.name, Version: version, BinaryDigest: digest})
		r.log(fmt.Sprintf("Tool: %s | %s | %s", t.name, version, digest))
	}
	if r.wsConn != nil {
		msg := LogMessage{Type: "tool_versions", ToolVersions: versions}
		_ = r.wsConn.Write(r.ctx, websocket.MessageText, mustJSON(msg))
	}
}

// uploadArtifacts POSTs all produced files to /runner/image-results in a
// single multipart request. The form fields are keyed by category
// (sbom, grype, cosign, betterleaks, labels, trivy_vuln, trivy_secrets).
func (r *ImageScanRunner) uploadArtifacts(files map[string]string) error {
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	if err := w.WriteField("image_digest_id", r.imageDigestID); err != nil {
		return err
	}
	if err := w.WriteField("scan_run_id", r.jobID); err != nil {
		return err
	}

	for field, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		part, err := w.CreateFormFile(field, filepath.Base(path))
		if err != nil {
			return err
		}
		if _, err := part.Write(data); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(r.ctx, "POST", r.workerURL+"/runner/image-results", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("upload failed: %d %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// imageScanEnv builds the subprocess env for image-scan scanners. It strips
// credentials (mirroring cleanEnv) but, unlike cleanEnv, does NOT disable
// vuln-database updates — image vuln scanning requires the grype/trivy DB.
// The cluster is expected to host in-cluster DB servers (grype-db-server /
// trivy-db-server); the operator points GRYPE_DB_UPDATE_URL and
// TRIVY_DB_REPOSITORY at those services via the pod spec, and those values
// are passed through here.
func imageScanEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"SYFT_CHECK_FOR_APP_UPDATE=false",
	}
	for _, k := range []string{
		"GRYPE_DB_UPDATE_URL",
		"GRYPE_DB_AUTO_UPDATE",
		"GRYPE_DB_VALIDATE_AGE",
		"TRIVY_DB_REPOSITORY",
		"TRIVY_JAVA_DB_REPOSITORY",
		"COSIGN_EXPERIMENTAL",
		// Registry auth pass-through for future private-registry support.
		"DOCKER_CONFIG",
		"REGISTRY_AUTH_FILE",
	} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// -----------------------------------------------------------------------------
// Tiny helpers
// -----------------------------------------------------------------------------

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// isExitCode reports whether err is an *exec.ExitError with the given code.
// The caller supplies the pointer receiver so errors.As can do its thing.
func isExitCode(err error, ee **exec.ExitError, code int) bool {
	if err == nil {
		return false
	}
	if xe, ok := err.(*exec.ExitError); ok {
		*ee = xe
		return xe.ExitCode() == code
	}
	return false
}

// prefixWriter is an io.Writer that splits on newlines and calls cb for each
// line with a prefix. Used to route scanner stderr into the main log stream.
type prefixWriter struct {
	prefix string
	cb     func(string)
	buf    []byte
}

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if line != "" {
			w.cb(w.prefix + line)
		}
	}
	return len(p), nil
}
