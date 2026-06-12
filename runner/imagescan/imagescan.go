// Package imagescan runs a pluggable set of container-image scanners
// against a single OCI digest and uploads the resulting artifacts to the
// spam worker. It is consumed by the spam-image-scanner pod, which leases
// IMAGE_SCAN jobs from the worker API in a loop and invokes Run() once per
// lease.
//
// The package is self-contained: all state is passed in, no globals beyond
// the scanner binary registry. Scanner names map to external binaries that
// must be present on $PATH in the caller's image.
package imagescan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Category identifies what a scanner produces.
type Category string

const (
	CategoryVuln      Category = "vuln"
	CategorySBOM      Category = "sbom"
	CategorySecrets   Category = "secrets"
	CategorySignature Category = "signature"
	CategoryLabels    Category = "labels"
)

// DefaultScanner returns the binary used when the payload leaves a category
// unset. Keeps the defaults in one place (the API-side imagescan package
// mirrors this list; changes here require a matching update there).
func DefaultScanner(c Category) string {
	switch c {
	case CategoryVuln:
		return "grype"
	case CategorySBOM:
		return "syft"
	case CategorySecrets:
		return "betterleaks"
	case CategorySignature:
		return "cosign"
	case CategoryLabels:
		return "crane"
	}
	return ""
}

// ImageRef addresses an image by immutable digest.
type ImageRef struct {
	Registry   string
	Repository string
	Digest     string
}

func (r ImageRef) String() string {
	return fmt.Sprintf("%s/%s@%s", r.Registry, r.Repository, r.Digest)
}

// LogFunc is the caller-supplied sink for human-readable progress lines.
// Typically wired to stdout for CronJob logs.
type LogFunc func(string)

// Pipeline holds inputs that are constant across a single scan run.
type Pipeline struct {
	Ref      ImageRef
	Scanners map[string]string // category -> scanner name; empty = defaults
	WorkDir  string            // scratch dir, writable
	Log      LogFunc

	// SigningPolicy, when non-nil, makes runSignature call `cosign
	// verify` against the configured identity (Sigstore keyless or a
	// pinned key) and report a real verdict. Without a policy, the
	// scanner only runs `cosign tree` and reports verified=false.
	SigningPolicy *SigningPolicy
}

// SigningPolicy is the runtime-shaped subset of the admin-configured
// cosign verification policy. Type is one of "keyless" or "key".
//
// The four endpoint URLs map to cosign flags: SignatureRepository →
// --signature-repository, FulcioURL → --fulcio-url, RekorURL →
// --rekor-url, TUFMirrorURL → --tuf-mirror. Empty = cosign default.
type SigningPolicy struct {
	Type           string
	Issuer         string
	SubjectPattern string
	KeyPEM         string

	SignatureRepository string
	FulcioURL           string
	RekorURL            string
	TUFMirrorURL        string
}

// Artifact is the output of one scanner invocation. Field is the multipart
// form field name the upload handler expects.
type Artifact struct {
	Category Category
	Scanner  string
	Field    string
	Path     string
}

// Result aggregates artifacts produced by a pipeline run.
type Result struct {
	Artifacts []Artifact
	Failed    map[Category]error // per-category failure; nil on success
}

// Run executes all enabled scanner categories against the image. Per-scanner
// failures are captured in Result.Failed rather than aborting the run —
// partial results are still useful downstream (e.g. an SBOM without a vuln
// scan still populates /app/components).
func (p Pipeline) Run(ctx context.Context) (Result, error) {
	if p.Log == nil {
		p.Log = func(string) {}
	}
	if p.WorkDir == "" {
		return Result{}, fmt.Errorf("pipeline: WorkDir required")
	}
	artifactDir := filepath.Join(p.WorkDir, "out")
	rootfsDir := filepath.Join(p.WorkDir, "rootfs")
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("mkdir artifact dir: %w", err)
	}
	if err := os.MkdirAll(p.tmpDir(), 0o755); err != nil {
		return Result{}, fmt.Errorf("mkdir tmp dir: %w", err)
	}

	res := Result{Failed: map[Category]error{}}

	// Order matters: cheap metadata first (labels, signature), then image
	// filesystem extraction (via secrets path) so subsequent filesystem
	// scanners don't each re-export.
	steps := []struct {
		cat Category
		run func(ctx context.Context) (Artifact, error)
	}{
		{CategoryLabels, func(ctx context.Context) (Artifact, error) { return p.runLabels(ctx, artifactDir) }},
		{CategorySignature, func(ctx context.Context) (Artifact, error) { return p.runSignature(ctx, artifactDir) }},
		{CategoryVuln, func(ctx context.Context) (Artifact, error) { return p.runVuln(ctx, artifactDir) }},
		{CategorySBOM, func(ctx context.Context) (Artifact, error) { return p.runSBOM(ctx, artifactDir) }},
		{CategorySecrets, func(ctx context.Context) (Artifact, error) { return p.runSecrets(ctx, artifactDir, rootfsDir) }},
	}
	for _, step := range steps {
		art, err := step.run(ctx)
		if err != nil {
			p.Log(fmt.Sprintf("[%s] FAILED: %v", step.cat, err))
			res.Failed[step.cat] = err
			continue
		}
		if art.Path == "" {
			continue
		}
		res.Artifacts = append(res.Artifacts, art)
		p.Log(fmt.Sprintf("[%s] ok -> %s", step.cat, filepath.Base(art.Path)))
	}
	return res, nil
}

func (p Pipeline) resolve(cat Category) string {
	if name, ok := p.Scanners[string(cat)]; ok && name != "" {
		return name
	}
	return DefaultScanner(cat)
}

// -----------------------------------------------------------------------------
// Per-category scanners
// -----------------------------------------------------------------------------

func (p Pipeline) runLabels(ctx context.Context, outDir string) (Artifact, error) {
	name := p.resolve(CategoryLabels)
	out := filepath.Join(outDir, "labels.json")
	switch name {
	case "crane":
		raw, err := p.capture(ctx, "crane", "config", p.Ref.String())
		if err != nil {
			return Artifact{}, err
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategoryLabels, Scanner: name, Field: "labels", Path: out}, nil
	}
	return Artifact{}, fmt.Errorf("unknown labels scanner %q", name)
}

func (p Pipeline) runSignature(ctx context.Context, outDir string) (Artifact, error) {
	name := p.resolve(CategorySignature)
	out := filepath.Join(outDir, "cosign.json")
	switch name {
	case "cosign":
		// `cosign tree` lists what's attached without requiring a signer
		// identity. It returns non-empty output even for unsigned images
		// (it prints a "No Supply Chain Security Related Artifacts found"
		// banner), so "output exists" cannot be used as "image is signed".
		// We parse the known marker explicitly.
		treeRaw, treeErr := p.capture(ctx, "cosign", "tree", p.Ref.String())
		payload := map[string]any{
			"image":    p.Ref.String(),
			"verifier": "cosign",
			"verified": false,
		}
		if treeErr != nil {
			payload["signed"] = false
			payload["error"] = treeErr.Error()
		} else {
			rawStr := string(treeRaw)
			payload["signed"] = !strings.Contains(rawStr, "No Supply Chain Security Related Artifacts found")
			payload["tree_raw"] = rawStr
		}

		// When a policy is configured, run `cosign verify` against the
		// identity it specifies and record the real verdict. Without a
		// policy, behaviour stays as-is — verified=false unconditionally
		// — so deployments without admin-configured signing are not
		// disrupted.
		if p.SigningPolicy != nil {
			verified, verifierErr := p.cosignVerify(ctx)
			payload["verified"] = verified
			if p.SigningPolicy.Type != "" {
				payload["verification_method"] = "cosign-" + p.SigningPolicy.Type
			}
			if p.SigningPolicy.Issuer != "" {
				payload["verification_issuer"] = p.SigningPolicy.Issuer
			}
			if p.SigningPolicy.SubjectPattern != "" {
				payload["verification_subject_pattern"] = p.SigningPolicy.SubjectPattern
			}
			if verifierErr != nil {
				// Verification failure is information, not a pipeline
				// error — record it so the upload handler can decide
				// whether to flip verified_source on image_digests.
				payload["verification_error"] = verifierErr.Error()
			}
		}

		if err := writeJSON(out, payload); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategorySignature, Scanner: name, Field: "cosign", Path: out}, nil
	}
	return Artifact{}, fmt.Errorf("unknown signature scanner %q", name)
}

// cosignVerify runs `cosign verify` against the configured policy and
// returns (true, nil) only when the binary exits 0. Any non-zero exit
// or unconfigured policy returns (false, err) so the caller records
// the failure verbatim — better than silently falling through.
//
// For keyless mode, --certificate-identity-regexp + --certificate-
// oidc-issuer match the Sigstore Fulcio cert chain. For key mode,
// the public key is written to a temp file (`cosign verify` only
// accepts a path, not stdin/env) and removed after the call.
func (p Pipeline) cosignVerify(ctx context.Context) (bool, error) {
	pol := p.SigningPolicy
	if pol == nil {
		return false, fmt.Errorf("no signing policy")
	}
	args := []string{"verify"}

	// Endpoint overrides come first so they apply to identity flags
	// resolved later in the same invocation. Empty = let cosign use
	// its bundled defaults (public Sigstore).
	if pol.FulcioURL != "" {
		args = append(args, "--fulcio-url", pol.FulcioURL)
	}
	if pol.RekorURL != "" {
		args = append(args, "--rekor-url", pol.RekorURL)
	}
	if pol.TUFMirrorURL != "" {
		args = append(args, "--tuf-mirror", pol.TUFMirrorURL)
	}
	if pol.SignatureRepository != "" {
		// --signature-repository is a top-level cosign flag; it lives
		// before the verb on some versions, after on others. Recent
		// cosign accepts it as a verify subcommand flag, which is the
		// path we take here. If your fleet pins an older cosign that
		// requires the env var instead, COSIGN_REPOSITORY=<url> in the
		// scanner pod's env achieves the same thing.
		args = append(args, "--signature-repository", pol.SignatureRepository)
	}

	switch pol.Type {
	case "keyless":
		if pol.Issuer == "" || pol.SubjectPattern == "" {
			return false, fmt.Errorf("keyless policy requires issuer and subject_pattern")
		}
		args = append(args,
			"--certificate-oidc-issuer", pol.Issuer,
			"--certificate-identity-regexp", pol.SubjectPattern,
		)
	case "key":
		if pol.KeyPEM == "" {
			return false, fmt.Errorf("key policy requires key_pem")
		}
		keyPath := filepath.Join(p.WorkDir, "cosign-pub.pem")
		if err := os.WriteFile(keyPath, []byte(pol.KeyPEM), 0o600); err != nil {
			return false, fmt.Errorf("write public key: %w", err)
		}
		defer os.Remove(keyPath)
		args = append(args, "--key", keyPath)
	default:
		return false, fmt.Errorf("unknown policy type %q", pol.Type)
	}
	args = append(args, p.Ref.String())
	if _, err := p.capture(ctx, "cosign", args...); err != nil {
		return false, err
	}
	return true, nil
}

func (p Pipeline) runVuln(ctx context.Context, outDir string) (Artifact, error) {
	name := p.resolve(CategoryVuln)
	switch name {
	case "grype":
		out := filepath.Join(outDir, "grype.json")
		if err := p.runTo(ctx, out, "grype", p.Ref.String(), "-o", "json"); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategoryVuln, Scanner: name, Field: "grype", Path: out}, nil
	case "trivy":
		out := filepath.Join(outDir, "trivy-vuln.json")
		if err := p.runDirect(ctx, "trivy", "image", "--quiet", "--format", "json", "--output", out, p.Ref.String()); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategoryVuln, Scanner: name, Field: "trivy_vuln", Path: out}, nil
	}
	return Artifact{}, fmt.Errorf("unknown vuln scanner %q", name)
}

func (p Pipeline) runSBOM(ctx context.Context, outDir string) (Artifact, error) {
	name := p.resolve(CategorySBOM)
	out := filepath.Join(outDir, "sbom.json")
	switch name {
	case "syft":
		if err := p.runDirect(ctx, "syft", "scan", "-q", "-o", "cyclonedx-json="+out, p.Ref.String()); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategorySBOM, Scanner: name, Field: "sbom", Path: out}, nil
	case "trivy":
		if err := p.runDirect(ctx, "trivy", "image", "--quiet", "--format", "cyclonedx", "--output", out, p.Ref.String()); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategorySBOM, Scanner: name, Field: "sbom", Path: out}, nil
	}
	return Artifact{}, fmt.Errorf("unknown sbom scanner %q", name)
}

func (p Pipeline) runSecrets(ctx context.Context, outDir, rootfsDir string) (Artifact, error) {
	name := p.resolve(CategorySecrets)
	if name == "betterleaks" || name == "trivy" {
		if err := p.exportRootfs(ctx, rootfsDir); err != nil {
			return Artifact{}, fmt.Errorf("rootfs export: %w", err)
		}
	}
	switch name {
	case "betterleaks":
		out := filepath.Join(outDir, "betterleaks.json")
		err := p.runDirect(ctx, "betterleaks", "dir", rootfsDir,
			"--report-path", out, "--report-format", "json", "--no-banner")
		if err != nil {
			// betterleaks exit=1 signals findings present — not a failure.
			if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
				return Artifact{}, err
			}
		}
		// Ensure the file exists so upload distinguishes "ran, no findings"
		// from "did not run".
		if _, statErr := os.Stat(out); os.IsNotExist(statErr) {
			_ = os.WriteFile(out, []byte("[]"), 0o644)
		}
		return Artifact{Category: CategorySecrets, Scanner: name, Field: "secrets", Path: out}, nil
	case "trivy":
		out := filepath.Join(outDir, "trivy-secrets.json")
		if err := p.runDirect(ctx, "trivy", "fs", "--quiet", "--scanners", "secret", "--format", "json", "--output", out, rootfsDir); err != nil {
			return Artifact{}, err
		}
		return Artifact{Category: CategorySecrets, Scanner: name, Field: "trivy_secrets", Path: out}, nil
	}
	return Artifact{}, fmt.Errorf("unknown secrets scanner %q", name)
}

// exportRootfs streams `crane export` into a tar extractor. It's idempotent
// — if the directory already has content, exportRootfs is a no-op.
func (p Pipeline) exportRootfs(ctx context.Context, rootfsDir string) error {
	if entries, _ := os.ReadDir(rootfsDir); len(entries) > 0 {
		return nil
	}
	if err := os.MkdirAll(rootfsDir, 0o755); err != nil {
		return err
	}
	p.Log(fmt.Sprintf("crane export -> %s", rootfsDir))
	cmd := exec.CommandContext(ctx, "crane", "export", p.Ref.String(), "-")
	cmd.Env = p.env()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = &lineWriter{prefix: "crane: ", log: p.Log}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Skip dev/* — mknod requires CAP_MKNOD which the scanner pod lacks,
	// and device files aren't useful for secrets/SBOM scanning anyway.
	tarCmd := exec.CommandContext(ctx, "tar", "-x", "--exclude=dev/*", "-C", rootfsDir)
	tarCmd.Stdin = stdout
	tarCmd.Stderr = &lineWriter{prefix: "tar: ", log: p.Log}
	if err := tarCmd.Run(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("tar extract: %w", err)
	}
	return cmd.Wait()
}

// -----------------------------------------------------------------------------
// Command helpers
// -----------------------------------------------------------------------------

// runDirect runs a scanner whose own --output flag handles file creation.
// stdout/stderr are streamed to p.Log.
func (p Pipeline) runDirect(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = p.env()
	cmd.Stdout = &lineWriter{prefix: name + ": ", log: p.Log}
	cmd.Stderr = &lineWriter{prefix: name + ": ", log: p.Log}
	return cmd.Run()
}

// runTo runs a scanner that dumps its result to stdout, redirecting stdout
// to outPath. stderr is streamed to p.Log.
func (p Pipeline) runTo(ctx context.Context, outPath string, name string, args ...string) error {
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = p.env()
	cmd.Stdout = f
	cmd.Stderr = &lineWriter{prefix: name + ": ", log: p.Log}
	return cmd.Run()
}

// capture runs a command and returns stdout bytes; stderr -> p.Log.
func (p Pipeline) capture(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = p.env()
	cmd.Stderr = &lineWriter{prefix: name + ": ", log: p.Log}
	return cmd.Output()
}

// tmpDir is the per-job temp directory handed to subprocesses via
// TMPDIR. syft/grype pull and unpack image layers under TMPDIR; with
// the process default (/tmp) those multi-GB dirs leak when a scan
// deadline SIGKILLs the tool mid-extraction, and a lingering pod
// accumulates them across digests until the kubelet evicts it for
// exceeding the tmp emptyDir's sizeLimit. Keeping temp inside WorkDir
// means the per-job cleanup in NewWorkDir removes leftovers even
// after a kill.
func (p Pipeline) tmpDir() string {
	return filepath.Join(p.WorkDir, "tmp")
}

// env builds the subprocess env. Strips secrets from the parent
// environment and passes through the scanner-specific vars the operator
// configured (GRYPE_DB_UPDATE_URL, etc.).
func (p Pipeline) env() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + p.tmpDir(),
		"SYFT_CHECK_FOR_APP_UPDATE=false",
	}
	for _, k := range []string{
		"GRYPE_DB_UPDATE_URL",
		"GRYPE_DB_AUTO_UPDATE",
		"GRYPE_DB_VALIDATE_AGE",
		"GRYPE_DB_CACHE_DIR",
		"TRIVY_CACHE_DIR",
		"TRIVY_DB_REPOSITORY",
		"TRIVY_JAVA_DB_REPOSITORY",
		"COSIGN_EXPERIMENTAL",
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
// Uploader
// -----------------------------------------------------------------------------

// UploadOpts addresses the worker endpoint and identifies the scan run.
type UploadOpts struct {
	WorkerURL     string
	RunToken      string
	JobID         string
	ImageDigestID string
	HTTPClient    *http.Client // optional; defaults to http.DefaultClient
}

// UploadErrorKind classifies upload failures so callers can decide
// between "mark the job FAILED" (permanent — 4xx, malformed payload,
// corrupt token) and "retry the whole job later" (transient — network
// timeout, 5xx, connection refused).
type UploadErrorKind int

const (
	UploadOK UploadErrorKind = iota
	UploadTransient
	UploadPermanent
)

// UploadError is returned from Upload alongside a regular error so the
// caller can check .Kind() without string-sniffing.
type UploadError struct {
	Err  error
	kind UploadErrorKind
}

func (e *UploadError) Error() string       { return e.Err.Error() }
func (e *UploadError) Unwrap() error       { return e.Err }
func (e *UploadError) Kind() UploadErrorKind { return e.kind }

// Upload POSTs all artifacts to /runner/image-results as one multipart
// request. Returns the count of files sent.
func Upload(ctx context.Context, opts UploadOpts, artifacts []Artifact) (int, error) {
	if opts.WorkerURL == "" || opts.RunToken == "" || opts.JobID == "" || opts.ImageDigestID == "" {
		return 0, fmt.Errorf("upload: WorkerURL, RunToken, JobID, ImageDigestID required")
	}
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	if err := w.WriteField("image_digest_id", opts.ImageDigestID); err != nil {
		return 0, err
	}
	if err := w.WriteField("scan_run_id", opts.JobID); err != nil {
		return 0, err
	}

	sent := 0
	for _, art := range artifacts {
		data, err := os.ReadFile(art.Path)
		if err != nil {
			return sent, fmt.Errorf("read %s: %w", art.Path, err)
		}
		part, err := w.CreateFormFile(art.Field, filepath.Base(art.Path))
		if err != nil {
			return sent, err
		}
		if _, err := part.Write(data); err != nil {
			return sent, err
		}
		sent++
	}
	if err := w.Close(); err != nil {
		return sent, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(opts.WorkerURL, "/")+"/runner/image-results", body)
	if err != nil {
		return sent, err
	}
	req.Header.Set("Authorization", "Bearer "+opts.RunToken)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		// Network-level failure (timeout, connection refused, DNS, TLS).
		// All transient from our POV — the worker may be rolling, a
		// NetworkPolicy may not have propagated yet, etc.
		return sent, &UploadError{Err: err, kind: UploadTransient}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		wrapped := fmt.Errorf("upload failed: %d %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
		// 5xx and 429 are worth retrying; 4xx (except 429) signals a
		// permanent problem with the request (bad token, bad payload).
		kind := UploadPermanent
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			kind = UploadTransient
		}
		return sent, &UploadError{Err: wrapped, kind: kind}
	}
	return sent, nil
}

// UploadWithRetry wraps Upload with exponential backoff for transient
// failures. Permanent errors return immediately. Returns the final
// (*UploadError) so the caller can still check .Kind().
func UploadWithRetry(ctx context.Context, opts UploadOpts, artifacts []Artifact, attempts int, log LogFunc) (int, error) {
	if attempts < 1 {
		attempts = 1
	}
	if log == nil {
		log = func(string) {}
	}
	var (
		sent int
		err  error
	)
	backoff := 2 * time.Second
	for i := 1; i <= attempts; i++ {
		sent, err = Upload(ctx, opts, artifacts)
		if err == nil {
			return sent, nil
		}
		var ue *UploadError
		if errors.As(err, &ue) && ue.Kind() == UploadPermanent {
			return sent, err
		}
		if i == attempts {
			return sent, err
		}
		log(fmt.Sprintf("upload attempt %d/%d failed: %v — retrying in %s", i, attempts, err, backoff))
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return sent, ctx.Err()
		}
		backoff *= 2
	}
	return sent, err
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// lineWriter splits writes on newlines and forwards each line to a logger.
// Used to route scanner stdout/stderr through the pod's structured log
// without interleaving mid-line with other subprocesses.
type lineWriter struct {
	prefix string
	log    LogFunc
	buf    []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := bytes.IndexByte(w.buf, '\n')
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if line == "" {
			continue
		}
		if w.log != nil {
			w.log(w.prefix + line)
		}
	}
	return len(p), nil
}

// NewWorkDir creates a scratch work directory under /work. Returns a cleanup
// function the caller should defer.
func NewWorkDir(base, jobID string) (string, func(), error) {
	dir := filepath.Join(base, jobID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	return dir, func() { _ = os.RemoveAll(dir) }, nil
}

// Scan once against the given image with sensible defaults. Intended as the
// one-shot helper the scanner pod calls per lease. Pass a non-nil policy to
// have the signature step actually verify identity rather than just running
// `cosign tree`.
func Scan(ctx context.Context, ref ImageRef, scanners map[string]string, workDir string, log LogFunc, policy *SigningPolicy) (Result, error) {
	p := Pipeline{
		Ref:           ref,
		Scanners:      scanners,
		WorkDir:       workDir,
		Log:           log,
		SigningPolicy: policy,
	}
	return p.Run(ctx)
}

// StdoutLogger is a convenience LogFunc for the scanner pod's main loop —
// prefixes each line with a UTC timestamp so CronJob logs are easy to read.
func StdoutLogger() LogFunc {
	return func(line string) {
		fmt.Printf("%s %s\n", time.Now().UTC().Format("15:04:05"), line)
	}
}

