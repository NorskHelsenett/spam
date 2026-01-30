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

type LogMessage struct {
	Type     string `json:"type"`
	Line     string `json:"line,omitempty"`
	Ts       string `json:"ts,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

type Runner struct {
	workerURL    string
	runID        string
	runToken     string
	repoCloneURL string
	repoRef      string
	workDir      string
	ctx          context.Context
	cancel       context.CancelFunc
	wsConn       *websocket.Conn
	logChan      chan string
	localMode    bool
}

func main() {
	workerURL := os.Getenv("WORKER_URL")
	runID := os.Getenv("RUN_ID")
	runToken := os.Getenv("RUN_TOKEN")
	repoCloneURL := os.Getenv("REPO_CLONE_URL")
	repoRef := os.Getenv("REPO_REF")

	if workerURL == "" || runID == "" || repoCloneURL == "" {
		log.Fatal("Missing required environment variables")
	}

	// Extract repo name from clone URL
	repoName := strings.TrimSuffix(filepath.Base(repoCloneURL), ".git")
	workDir := filepath.Join("/work", repoName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r := &Runner{
		workerURL:    workerURL,
		runID:        runID,
		runToken:     runToken,
		repoCloneURL: repoCloneURL,
		repoRef:      repoRef,
		workDir:      workDir,
		ctx:          ctx,
		cancel:       cancel,
		logChan:      make(chan string, 100),
		localMode:    workerURL == "local",
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
	if err := os.RemoveAll(r.workDir); err != nil {
		log.Printf("Failed to clean work dir: %v", err)
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
	// Prepare work directory
	if err := os.RemoveAll(r.workDir); err != nil {
		r.log(fmt.Sprintf("Failed to clean work dir: %v", err))
	}
	if err := os.MkdirAll(r.workDir, 0755); err != nil {
		r.log(fmt.Sprintf("Failed to create work dir: %v", err))
		return 1
	}

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

	// Build clone URL with auth if needed
	cloneURL := r.repoCloneURL
	if pat != "" {
		cloneURL = strings.Replace(r.repoCloneURL, "https://", fmt.Sprintf("https://token:%s@", pat), 1)
	}

	// Clone repository
	r.log(fmt.Sprintf("Cloning %s...", r.repoCloneURL))
	cloneArgs := []string{"clone", "--depth=1"}
	if r.repoRef != "" {
		cloneArgs = append(cloneArgs, "--branch", r.repoRef)
	}
	cloneArgs = append(cloneArgs, cloneURL, r.workDir)

	if err := r.runCommand("git", cloneArgs...); err != nil {
		r.log(fmt.Sprintf("Git clone failed: %v", err))
		return 1
	}

	// Run SBOM generation
	r.log("Running syft for SBOM generation...")
	sbomPath := filepath.Join(r.workDir, "sbom.json")
	if err := r.runCommand("syft", "scan", "-q", "-o", "cyclonedx-json="+sbomPath, r.workDir); err != nil {
		r.log(fmt.Sprintf("Syft failed: %v", err))
		return 1
	}

	// Run secret scan
	r.log("Running gitleaks for secret detection...")
	gitleaksPath := filepath.Join(r.workDir, "gitleaks.json")
	if err := r.runCommand("gitleaks", "detect", "--source", r.workDir, "--report-path", gitleaksPath, "--report-format", "json", "--no-git"); err != nil {
		// Gitleaks exits 1 if secrets found, but that's expected
		r.log("Gitleaks scan completed")
	}

	// Ensure gitleaks.json exists (create empty array if no secrets found)
	if _, err := os.Stat(gitleaksPath); os.IsNotExist(err) {
		if err := os.WriteFile(gitleaksPath, []byte("[]"), 0644); err != nil {
			r.log(fmt.Sprintf("Failed to create empty gitleaks file: %v", err))
		}
	}

	// Upload results if not in local mode, otherwise copy to output dir
	if !r.localMode {
		r.log("Uploading SBOM...")
		if err := r.uploadFile(sbomPath, "sbom"); err != nil {
			r.log(fmt.Sprintf("Failed to upload SBOM: %v", err))
			return 1
		}

		r.log("Uploading gitleaks results...")
		if err := r.uploadFile(gitleaksPath, "gitleaks"); err != nil {
			r.log(fmt.Sprintf("Failed to upload gitleaks: %v", err))
			return 1
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

			// Copy gitleaks results
			if err := r.copyFile(gitleaksPath, filepath.Join(outputDir, "gitleaks.json")); err != nil {
				r.log(fmt.Sprintf("Failed to copy gitleaks: %v", err))
			} else {
				r.log("✓ Gitleaks results saved")
			}
		}
	}

	r.log("Run completed successfully")
	return 0
}

func (r *Runner) runCommand(name string, args ...string) error {
	cmd := exec.CommandContext(r.ctx, name, args...)
	cmd.Dir = r.workDir

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

	// Add file field (use "sbom" or "secrets" based on fileType)
	fieldName := fileType
	if fileType == "gitleaks" {
		fieldName = "secrets"
	}

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
