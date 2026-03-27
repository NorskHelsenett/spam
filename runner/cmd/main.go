package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type LogMessage struct {
	Type       string `json:"type"`
	Line       string `json:"line,omitempty"`
	Ts         string `json:"ts,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	CommitHash string `json:"commit_hash,omitempty"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type Runner struct {
	workerURL     string
	runID         string
	runToken      string
	repoCloneURL  string
	repoRef       string
	repoCommitSHA string
	workDir       string
	artifactDir   string
	ctx           context.Context
	cancel        context.CancelFunc
	wsConn        *websocket.Conn
	logChan       chan string
	localMode     bool
	sbomScanner   string // "trivy" or "syft"
	commitHash    string
	runnerMode    string // "clone", "scan", or "" (legacy)
}

func main() {
	workerURL := os.Getenv("WORKER_URL")
	runID := os.Getenv("RUN_ID")
	runToken := os.Getenv("RUN_TOKEN")
	repoCloneURL := os.Getenv("REPO_CLONE_URL")
	repoRef := os.Getenv("REPO_REF")
	repoCommitSHA := os.Getenv("REPO_COMMIT_SHA")
	sbomScanner := os.Getenv("SBOM_SCANNER")

	runnerMode := os.Getenv("RUNNER_MODE")

	if workerURL == "" || runID == "" || repoCloneURL == "" {
		log.Fatal("Missing required environment variables")
	}

	// Clone mode: init container that clones the repo and exits
	if runnerMode == "clone" {
		os.Exit(runCloneMode(workerURL, runID, runToken, repoCloneURL, repoRef, repoCommitSHA))
	}

	// Default to syft if not specified
	if sbomScanner == "" {
		sbomScanner = "syft"
	}

	// Extract repo name from clone URL
	repoName := strings.TrimSuffix(filepath.Base(repoCloneURL), ".git")
	workDir := filepath.Join("/work", repoName)
	artifactDir := filepath.Join(os.TempDir(), "spam-runner", runID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &Runner{
		workerURL:     workerURL,
		runID:         runID,
		runToken:      runToken,
		repoCloneURL:  repoCloneURL,
		repoRef:       repoRef,
		repoCommitSHA: repoCommitSHA,
		workDir:       workDir,
		artifactDir:   artifactDir,
		ctx:           ctx,
		cancel:        cancel,
		logChan:       make(chan string, 100),
		localMode:     workerURL == "local",
		sbomScanner:   sbomScanner,
		runnerMode:    runnerMode,
	}

	// Setup cleanup
	defer r.cleanup()

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	go func() {
		<-sigChan
		r.log("Cancellation signal received")
		cancel()
	}()

	// Connect WebSocket if not in local mode
	if !r.localMode {
		if err := r.connectWebSocket(); err != nil {
			log.Fatalf("Failed to connect WebSocket: %v", err)
		}
		defer r.wsConn.Close(websocket.StatusNormalClosure, "")

		// Start log streaming goroutine
		go r.streamLogs()
		// Start cancellation monitor
		go r.monitorCancellation()
	}

	r.log(fmt.Sprintf("Starting run: %s", runID))

	// Run the pipeline
	exitCode := r.runPipeline()

	// Send done message
	r.sendDone(exitCode)

	os.Exit(exitCode)
}

func (r *Runner) cleanup() {
	// Work dir is read-only in scan mode (mounted from init container)
	if r.runnerMode != "scan" {
		if err := os.RemoveAll(r.workDir); err != nil {
			log.Printf("Failed to clean work dir: %v", err)
		}
	}
	if r.artifactDir != "" && r.artifactDir != "/" {
		if err := os.RemoveAll(r.artifactDir); err != nil {
			log.Printf("Failed to clean artifact dir: %v", err)
		}
	}
}

func (r *Runner) connectWebSocket() error {
	wsURL := strings.Replace(r.workerURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = fmt.Sprintf("%s/runner/ws?token=%s", wsURL, r.runToken)

	conn, _, err := websocket.Dial(r.ctx, wsURL, nil)
	if err != nil {
		return err
	}
	r.wsConn = conn
	return nil
}

func (r *Runner) log(line string) {
	fmt.Println(line)
	if !r.localMode {
		select {
		case r.logChan <- line:
		case <-r.ctx.Done():
		}
	}
}

func (r *Runner) streamLogs() {
	for {
		select {
		case line := <-r.logChan:
			msg := LogMessage{
				Type: "log",
				Line: line,
				Ts:   time.Now().UTC().Format(time.RFC3339),
			}
			if err := r.wsConn.Write(r.ctx, websocket.MessageText, mustJSON(msg)); err != nil {
				log.Printf("Failed to send log: %v", err)
				return
			}
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *Runner) monitorCancellation() {
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

func (r *Runner) sendDone(exitCode int) {
	if r.localMode {
		return
	}
	msg := LogMessage{
		Type:     "done",
		ExitCode: exitCode,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.wsConn.Write(ctx, websocket.MessageText, mustJSON(msg))
	time.Sleep(1 * time.Second) // Allow flush
}

func (r *Runner) runPipeline() int {
	if r.runnerMode != "scan" {
		// Prepare work directory
		if err := os.RemoveAll(r.workDir); err != nil {
			r.log(fmt.Sprintf("Failed to clean work dir: %v", err))
		}
		if err := os.MkdirAll(r.workDir, 0755); err != nil {
			r.log(fmt.Sprintf("Failed to create work dir: %v", err))
			return 1
		}
	}

	// Prepare artifacts directory outside the repository clone.
	if err := os.RemoveAll(r.artifactDir); err != nil {
		r.log(fmt.Sprintf("Failed to clean artifact dir: %v", err))
	}
	if err := os.MkdirAll(r.artifactDir, 0755); err != nil {
		r.log(fmt.Sprintf("Failed to create artifact dir: %v", err))
		return 1
	}
	r.log(fmt.Sprintf("Artifact directory: %s", r.artifactDir))

	if r.runnerMode != "scan" {
		// Request PAT for private repos
		pat := ""
		if !r.localMode {
			r.log("Requesting access token...")
			var err error
			pat, err = r.requestToken()
			if err != nil {
				r.log(fmt.Sprintf("Failed to get token: %v", err))
				// Continue anyway - might be public repo
			}
		}

		// Build clone args — pass auth via http.extraHeader so the PAT
		// never touches .git/config
		buildArgs := func(depth bool) []string {
			args := []string{"clone", "-c", "credential.helper="}
			if pat != "" {
				basicAuth := base64.StdEncoding.EncodeToString([]byte("token:" + pat))
				args = append(args, "-c", fmt.Sprintf("http.extraHeader=Authorization: Basic %s", basicAuth))
			}
			if depth {
				args = append(args, "--depth=1")
			} else {
				args = append(args, "--no-tags")
			}
			if r.repoRef != "" {
				args = append(args, "--branch", r.repoRef)
			}
			args = append(args, r.repoCloneURL, r.workDir)
			return args
		}

		// Clone repository
		r.log(fmt.Sprintf("Cloning %s...", r.repoCloneURL))
		if r.repoCommitSHA != "" {
			// Pinned-commit mode: full clone, then checkout exact SHA
			if err := r.runCommand("git", buildArgs(false)...); err != nil {
				r.log(fmt.Sprintf("Git clone failed: %v", err))
				return 1
			}
			r.log(fmt.Sprintf("Checking out pinned commit %s...", r.repoCommitSHA))
			checkoutCmd := exec.CommandContext(r.ctx, "git", "-C", r.workDir, "checkout", r.repoCommitSHA)
			if out, err := checkoutCmd.CombinedOutput(); err != nil {
				r.log(fmt.Sprintf("Git checkout failed: %v\n%s", err, string(out)))
				return 1
			}
		} else {
			// Standard shallow clone
			if err := r.runCommand("git", buildArgs(true)...); err != nil {
				r.log(fmt.Sprintf("Git clone failed: %v", err))
				return 1
			}
		}
	}

	// Capture the actual commit hash that was cloned
	commitHashCmd := exec.CommandContext(r.ctx, "git", "-C", r.workDir, "rev-parse", "HEAD")
	commitHashOut, commitErr := commitHashCmd.Output()
	if commitErr == nil {
		r.commitHash = strings.TrimSpace(string(commitHashOut))
		r.log(fmt.Sprintf("Commit hash: %s", r.commitHash))
		// Send commit hash via WebSocket
		if !r.localMode {
			msg := LogMessage{
				Type:       "commit_hash",
				CommitHash: r.commitHash,
			}
			if err := r.wsConn.Write(r.ctx, websocket.MessageText, mustJSON(msg)); err != nil {
				r.log(fmt.Sprintf("Failed to send commit hash: %v", err))
			}
		}
	}

	// Run SBOM generation
	r.log(fmt.Sprintf("Running %s for SBOM generation...", r.sbomScanner))
	sbomPath := filepath.Join(r.artifactDir, "sbom.json")
	betterleaksPath := filepath.Join(r.artifactDir, "betterleaks.json")
	manifestsPath := filepath.Join(r.artifactDir, "manifests.json")

	var sbomErr error
	if r.sbomScanner == "trivy" {
		sbomErr = r.runCommand("trivy", "fs", "--quiet", "--format", "cyclonedx", "--output", sbomPath, r.workDir)
	} else {
		sbomErr = r.runCommand("syft", "scan", "-q", "-o", "cyclonedx-json="+sbomPath, r.workDir)
	}

	if sbomErr != nil {
		r.log(fmt.Sprintf("SBOM generation failed: %v", sbomErr))
		return 1
	}

	// Collect dependency manifest files for upload
	r.log("Collecting dependency manifest files...")
	manifestFiles := r.findDependencyManifests()
	if len(manifestFiles) > 0 {
		r.log(fmt.Sprintf("Found %d dependency manifest file(s)", len(manifestFiles)))
		if err := r.createManifestsArchive(manifestFiles, manifestsPath); err != nil {
			r.log(fmt.Sprintf("Warning: failed to create manifests archive: %v", err))
		}
	}

	// Run secret scan
	r.log("Running BetterLeaks for secret detection...")
	if err := r.runCommand("betterleaks", "dir", r.workDir, "--report-path", betterleaksPath, "--report-format", "json", "--no-banner"); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			r.log("BetterLeaks: Potential secrets detected")
		} else {
			r.log(fmt.Sprintf("BetterLeaks scan failed: %v", err))
			return 1
		}
	} else {
		r.log("BetterLeaks: No secrets detected")
	}

	// Ensure betterleaks.json exists (create empty array if no secrets found)
	if _, err := os.Stat(betterleaksPath); os.IsNotExist(err) {
		if err := os.WriteFile(betterleaksPath, []byte("[]"), 0644); err != nil {
			r.log(fmt.Sprintf("Failed to create empty BetterLeaks file: %v", err))
		}
	}

	// Upload results if not in local mode, otherwise copy to output dir
	if !r.localMode {
		r.log("Uploading SBOM...")
		if err := r.uploadFile(sbomPath, "sbom"); err != nil {
			r.log(fmt.Sprintf("Failed to upload SBOM: %v", err))
			return 1
		}

		r.log("Uploading BetterLeaks results...")
		if err := r.uploadFile(betterleaksPath, "secrets"); err != nil {
			r.log(fmt.Sprintf("Failed to upload BetterLeaks results: %v", err))
			return 1
		}

		// Upload manifests if they exist
		if _, err := os.Stat(manifestsPath); err == nil {
			r.log("Uploading dependency manifests...")
			if err := r.uploadFile(manifestsPath, "manifests"); err != nil {
				r.log(fmt.Sprintf("Failed to upload manifests: %v", err))
				return 1
			}
		}
	} else {
		// Local mode: copy results to output directory
		outputDir := os.Getenv("OUTPUT_DIR")
		if outputDir != "" {
			r.log(fmt.Sprintf("Copying results to %s...", outputDir))
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				r.log(fmt.Sprintf("Failed to create output dir: %v", err))
				return 1
			}

			// Copy SBOM
			if err := r.copyFile(sbomPath, filepath.Join(outputDir, "sbom.json")); err != nil {
				r.log(fmt.Sprintf("Failed to copy SBOM: %v", err))
			} else {
				r.log("✓ SBOM saved")
			}

			// Copy BetterLeaks results
			if err := r.copyFile(betterleaksPath, filepath.Join(outputDir, "betterleaks.json")); err != nil {
				r.log(fmt.Sprintf("Failed to copy BetterLeaks results: %v", err))
			} else {
				r.log("✓ BetterLeaks results saved")
			}

			// Copy manifests if they exist
			if _, err := os.Stat(manifestsPath); err == nil {
				if err := r.copyFile(manifestsPath, filepath.Join(outputDir, "manifests.json")); err != nil {
					r.log(fmt.Sprintf("Failed to copy manifests: %v", err))
				} else {
					r.log("✓ Dependency manifests saved")
				}
			}
		}
	}

	r.log("Run completed successfully")
	return 0
}

// cleanEnv returns a minimal environment for running external tools.
// This prevents sensitive variables (tokens, secrets) from leaking to
// third-party analyzers like syft, trivy, or betterleaks.
func cleanEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GIT_TERMINAL_PROMPT=0",
		"SYFT_CHECK_FOR_APP_UPDATE=false",
		"TRIVY_SKIP_DB_UPDATE=true",
		"TRIVY_SKIP_JAVA_DB_UPDATE=true",
		"TRIVY_OFFLINE_SCAN=true",
	}
}

func (r *Runner) runCommand(name string, args ...string) error {
	cmd := exec.CommandContext(r.ctx, name, args...)
	cmd.Dir = r.workDir
	cmd.Env = cleanEnv()

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

	// Stream output in real-time
	go r.streamOutput(stdout)
	go r.streamOutput(stderr)

	return cmd.Wait()
}

func (r *Runner) streamOutput(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		r.log(scanner.Text())
	}
}

func (r *Runner) requestToken() (string, error) {
	reqBody, _ := json.Marshal(map[string]string{"run_id": r.runID})
	req, err := http.NewRequestWithContext(r.ctx, "POST", r.workerURL+"/runner/token", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+r.runToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.Token, nil
}

func (r *Runner) uploadFile(filePath, fileType string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add run_id field
	if err := writer.WriteField("run_id", r.runID); err != nil {
		return err
	}

	// Add commit_hash field if available
	if r.commitHash != "" {
		if err := writer.WriteField("commit_hash", r.commitHash); err != nil {
			return err
		}
	}

	fieldName := fileType

	part, err := writer.CreateFormFile(fieldName, filepath.Base(filePath))
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(r.ctx, "POST", r.workerURL+"/runner/results", body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.runToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed: %d", resp.StatusCode)
	}
	return nil
}

func (r *Runner) findCsprojFiles() []string {
	var csprojFiles []string

	err := filepath.Walk(r.workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".csproj") {
			csprojFiles = append(csprojFiles, path)
		}
		return nil
	})

	if err != nil {
		r.log(fmt.Sprintf("Error searching for .csproj files: %v", err))
	}

	return csprojFiles
}

func (r *Runner) findDependencyManifests() []string {
	var manifests []string

	// Patterns for dependency manifest files.
	// We intentionally collect broadly so manifests are available for search and
	// incremental parser improvements even when dependency extraction is partial.
	patterns := []string{
		"*.csproj", "packages.config", "*.fsproj", "*.vbproj", "Directory.Packages.props", // .NET
		"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", // Node.js
		"bun.lock", "bun.lockb", // Bun
		"pom.xml", "build.gradle", "build.gradle.kts", "gradle.lock", "gradle.properties", "settings.gradle", "settings.gradle.kts", "libs.versions.toml", "build.sbt", "project/build.properties", "project/plugins.sbt", // Java/Kotlin/Scala
		"requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml", // Python
		"go.mod", "go.sum", // Go
		"Cargo.toml", "Cargo.lock", // Rust
		"Gemfile", "Gemfile.lock", // Ruby
		"composer.json", "composer.lock", // PHP
		"pubspec.yaml", "pubspec.lock", // Dart
		"mix.exs", "mix.lock", // Elixir
		"Package.swift", "Podfile", "Podfile.lock", "Cartfile", "Cartfile.resolved", "*.xcodeproj/project.pbxproj", // Swift/iOS
		"CMakeLists.txt", "conanfile.txt", "conanfile.py", "vcpkg.json", "BUILD", "WORKSPACE", "MODULE.bazel", // C/C++/Bazel
		"stack.yaml", "*.cabal", "cabal.project", // Haskell
		"DESCRIPTION", "renv.lock", "packrat.lock", "install.R", // R
		"dune", "dune-project", "opam", "opam.locked", // OCaml
		"Project.toml", "Manifest.toml", // Julia
		"rebar.config", "rebar.lock", // Erlang/Rebar
		"*.rockspec", "luarocks.lock", // Lua
		"cpanfile", "META.json", "META.yml", // Perl
	}

	err := filepath.Walk(r.workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// Skip common directories that shouldn't have manifests
			name := info.Name()
			if name == "node_modules" || name == "vendor" || name == ".git" ||
				name == "bin" || name == "obj" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}

		fileName := info.Name()
		for _, pattern := range patterns {
			// For patterns containing a path separator (e.g. "*.xcodeproj/project.pbxproj",
			// "project/build.properties"), match against "parentDir/filename" so the
			// directory component is checked. Plain filename patterns match as before.
			matchTarget := fileName
			if strings.Contains(pattern, string(filepath.Separator)) {
				matchTarget = filepath.Join(filepath.Base(filepath.Dir(path)), fileName)
			}
			matched, _ := filepath.Match(pattern, matchTarget)
			if matched {
				manifests = append(manifests, path)
				break
			}
		}
		return nil
	})

	if err != nil {
		r.log(fmt.Sprintf("Error searching for manifest files: %v", err))
	}

	return manifests
}

func (r *Runner) createManifestsArchive(files []string, outputPath string) error {
	// Create JSON structure with file paths and contents
	type ManifestFile struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}

	var manifests []ManifestFile
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			r.log(fmt.Sprintf("Warning: failed to read %s: %v", file, err))
			continue
		}

		// Make path relative to workDir
		relPath, _ := filepath.Rel(r.workDir, file)
		manifests = append(manifests, ManifestFile{
			Path:    relPath,
			Content: string(content),
		})
	}

	// Write as JSON
	data, err := json.MarshalIndent(manifests, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

func (r *Runner) copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func mustJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

// runCloneMode runs in init-container mode: requests PAT, clones the repo,
// and exits. Auth is passed via http.extraHeader so the PAT is never written
// to .git/config — the cloned repo is identical to a public clone.
// The main container then mounts the work volume read-only.
func runCloneMode(workerURL, runID, runToken, cloneURL, ref, commitSHA string) int {
	repoName := strings.TrimSuffix(filepath.Base(cloneURL), ".git")
	workDir := filepath.Join("/work", repoName)

	// Clean and create work dir
	os.RemoveAll(workDir)
	if err := os.MkdirAll(workDir, 0755); err != nil {
		log.Printf("Failed to create work dir: %v", err)
		return 1
	}

	// Request PAT for private repos
	pat := ""
	if workerURL != "local" {
		log.Printf("Requesting access token...")
		var err error
		pat, err = requestPAT(workerURL, runID, runToken)
		if err != nil {
			log.Printf("Failed to get token: %v (continuing for public repos)", err)
		}
	}

	// Build git args — pass auth via http.extraHeader so the PAT never
	// touches .git/config. The resulting repo is identical to a public clone.
	gitEnv := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "GIT_TERMINAL_PROMPT=0"}
	buildCloneArgs := func(depth string) []string {
		args := []string{"clone", "-c", "credential.helper="}
		if pat != "" {
			basicAuth := base64.StdEncoding.EncodeToString([]byte("token:" + pat))
			args = append(args, "-c", fmt.Sprintf("http.extraHeader=Authorization: Basic %s", basicAuth))
		}
		if depth != "" {
			args = append(args, "--depth=1")
		} else {
			args = append(args, "--no-tags")
		}
		if ref != "" {
			args = append(args, "--branch", ref)
		}
		args = append(args, cloneURL, workDir)
		return args
	}

	ctx := context.Background()

	// Clone repository
	log.Printf("Cloning %s...", cloneURL)
	if commitSHA != "" {
		// Pinned-commit mode: full clone, then checkout exact SHA
		cmd := exec.CommandContext(ctx, "git", buildCloneArgs("")...)
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Git clone failed: %v\n%s", err, string(out))
			return 1
		}
		log.Printf("Checking out pinned commit %s...", commitSHA)
		checkout := exec.CommandContext(ctx, "git", "-C", workDir, "checkout", commitSHA)
		checkout.Env = gitEnv
		if out, err := checkout.CombinedOutput(); err != nil {
			log.Printf("Git checkout failed: %v\n%s", err, string(out))
			return 1
		}
	} else {
		// Standard shallow clone
		cmd := exec.CommandContext(ctx, "git", buildCloneArgs("1")...)
		cmd.Env = gitEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Git clone failed: %v\n%s", err, string(out))
			return 1
		}
	}

	log.Printf("Clone completed successfully")
	return 0
}

// requestPAT requests a PAT token from the worker service.
func requestPAT(workerURL, runID, runToken string) (string, error) {
	reqBody, _ := json.Marshal(map[string]string{"run_id": runID})
	req, err := http.NewRequest("POST", workerURL+"/runner/token", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+runToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.Token, nil
}
