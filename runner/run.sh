#!/bin/sh
set -e

# Required env: WORKER_URL, RUN_ID, RUN_TOKEN, REPO_CLONE_URL
# Optional env: REPO_REF

# Extract repo name from clone URL (e.g., https://github.com/org/repo.git -> repo)
REPO_NAME=$(basename "$REPO_CLONE_URL" .git)
WORK_DIR="/work/$REPO_NAME"
CANCELLED=0

cleanup() {
    rm -rf "$WORK_DIR"
    [ -n "$WS_PID" ] && kill "$WS_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Clean any previous run
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

handle_cancel() {
    CANCELLED=1
    echo "Cancellation signal received"
    cleanup
    exit 130
}
trap handle_cancel USR1

# Create named pipe for WebSocket output
WS_OUT="$WORK_DIR/ws_out.fifo"
WS_IN="$WORK_DIR/ws_in.fifo"
mkfifo "$WS_OUT" "$WS_IN"

# Helper: send log line to stdout and WebSocket
log() {
    local line="$1"
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo "$line"
    if [ -p "$WS_OUT" ] && [ "$WORKER_URL" != "local" ]; then
        # Escape special characters for JSON
        local escaped
        escaped=$(printf '%s' "$line" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g')
        printf '{"type":"log","line":"%s","ts":"%s"}\n' "$escaped" "$ts" > "$WS_OUT" 2>/dev/null || true
    fi
}

# Helper: send done message
send_done() {
    local exit_code="$1"
    if [ -p "$WS_OUT" ] && [ "$WORKER_URL" != "local" ]; then
        printf '{"type":"done","exit_code":%d}\n' "$exit_code" > "$WS_OUT" 2>/dev/null || true
        sleep 1  # Allow WebSocket to flush
    fi
}

# Monitor WebSocket for cancellation signals (background)
monitor_ws() {
    while read -r msg; do
        case "$msg" in
            *'"type":"cancel"'*)
                kill -USR1 $$ 2>/dev/null || true
                break
                ;;
        esac
    done < "$WS_IN"
}

# Connect WebSocket for log streaming (background)
if [ "$WORKER_URL" != "local" ]; then
    WS_URL=$(echo "$WORKER_URL" | sed 's|^http|ws|')/runner/ws?token="$RUN_TOKEN"

    # Start WebSocket connection: read from WS_OUT pipe, write responses to WS_IN
    cat "$WS_OUT" | websocat -n "$WS_URL" > "$WS_IN" 2>/dev/null &
    WS_PID=$!

    # Start cancellation monitor
    monitor_ws &
    MONITOR_PID=$!
fi

log "Starting run: $RUN_ID"

# Request PAT for private repos (returns empty for public)
PAT=""
if [ "$WORKER_URL" != "local" ]; then
    log "Requesting access token..."
    PAT=$(curl -sf "$WORKER_URL/runner/token" \
        -H "Authorization: Bearer $RUN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"run_id":"'"$RUN_ID"'"}' 2>/dev/null | jq -r '.token // empty' || true)
fi

# Build clone URL with authentication if PAT provided
CLONE_URL="$REPO_CLONE_URL"
if [ -n "$PAT" ]; then
    # Provider-agnostic: https://token:PAT@host/repo.git
    CLONE_URL=$(echo "$REPO_CLONE_URL" | sed "s|https://|https://token:${PAT}@|")
fi

# Clone repository
log "Cloning repository..."
CLONE_ARGS="--depth=1 --no-tags"
if [ -n "$REPO_REF" ]; then
    CLONE_ARGS="$CLONE_ARGS --branch $REPO_REF"
fi

if ! git clone $CLONE_ARGS "$CLONE_URL" "$WORK_DIR/src" 2>&1 | while IFS= read -r line; do
    log "$line"
done; then
    log "ERROR: Failed to clone repository"
    send_done 1
    exit 1
fi

[ $CANCELLED -eq 1 ] && exit 130

cd "$WORK_DIR/src"

# Run SBOM scan (trivy or syft)
SBOM_TOOL="${SBOM_TOOL:-syft}"
SBOM_FAILED=0

log "Running SBOM scan with $SBOM_TOOL..."
case "$SBOM_TOOL" in
    syft)
        {
            syft . -o cyclonedx-json="$WORK_DIR/sbom.json" 2>&1
            echo $? > "$WORK_DIR/sbom_exit"
        } | while IFS= read -r line; do
            log "$line"
        done
        ;;
    trivy|*)
        TRIVY_ARGS=""
        [ -n "$TRIVY_SKIP_DIRS" ] && TRIVY_ARGS="--skip-dirs $TRIVY_SKIP_DIRS"
        {
            trivy fs --format cyclonedx --output "$WORK_DIR/sbom.json" $TRIVY_ARGS . 2>&1
            echo $? > "$WORK_DIR/sbom_exit"
        } | while IFS= read -r line; do
            log "$line"
        done
        ;;
esac

SBOM_EXIT=$(cat "$WORK_DIR/sbom_exit" 2>/dev/null || echo "1")
if [ "$SBOM_EXIT" -ne 0 ]; then
    log "WARNING: $SBOM_TOOL scan failed with exit code $SBOM_EXIT"
    SBOM_FAILED=1
fi

# Ensure SBOM file exists even if scan failed
if [ ! -f "$WORK_DIR/sbom.json" ] || [ ! -s "$WORK_DIR/sbom.json" ]; then
    log "Creating empty SBOM ($SBOM_TOOL failed)"
    echo '{"bomFormat":"CycloneDX","specVersion":"1.4","components":[],"dependencies":[]}' > "$WORK_DIR/sbom.json"
    SBOM_FAILED=1
fi

[ $CANCELLED -eq 1 ] && exit 130

# Run Gitleaks scan
log "Running Gitleaks scan..."
# Gitleaks returns exit code 1 when secrets are found, which is expected
if gitleaks detect --source . --report-format json --report-path "$WORK_DIR/gitleaks.json" 2>&1 | while IFS= read -r line; do
    log "$line"
done; then
    log "Gitleaks: No secrets detected"
else
    GITLEAKS_EXIT=$?
    if [ $GITLEAKS_EXIT -eq 1 ]; then
        log "Gitleaks: Potential secrets detected"
    else
        log "WARNING: Gitleaks scan encountered errors"
    fi
fi

[ $CANCELLED -eq 1 ] && exit 130

# Ensure gitleaks output file exists (empty if scan failed)
if [ ! -f "$WORK_DIR/gitleaks.json" ] || [ ! -s "$WORK_DIR/gitleaks.json" ]; then
    echo '[]' > "$WORK_DIR/gitleaks.json"
fi

# Upload results to worker
if [ "$WORKER_URL" != "local" ]; then
    log "Uploading results..."
    if ! curl -sf "$WORKER_URL/runner/results" \
        -H "Authorization: Bearer $RUN_TOKEN" \
        -F "run_id=$RUN_ID" \
        -F "sbom=@$WORK_DIR/sbom.json" \
        -F "secrets=@$WORK_DIR/gitleaks.json"; then
        log "ERROR: Failed to upload results"
        send_done 1
        exit 1
    fi
else
    # Local mode: copy results to /output if mounted
    OUTPUT_DIR="${OUTPUT_DIR:-/output}"
    if [ -d "$OUTPUT_DIR" ] && [ -w "$OUTPUT_DIR" ]; then
        cp "$WORK_DIR/sbom.json" "$OUTPUT_DIR/sbom.json"
        cp "$WORK_DIR/gitleaks.json" "$OUTPUT_DIR/gitleaks.json"
        log "Local mode: Results saved to $OUTPUT_DIR"
    else
        log "Local mode: No output directory mounted, results not saved"
        log "Mount a volume to /output or set OUTPUT_DIR to save results"
    fi
fi

# Print summary
log ""
log "========== SCAN SUMMARY =========="
if [ "$SBOM_FAILED" -eq 1 ]; then
    log "SBOM ($SBOM_TOOL): FAILED"
else
    SBOM_COMPONENTS=$(jq '.components | length // 0' "$WORK_DIR/sbom.json" 2>/dev/null || echo "0")
    SBOM_DEPS=$(jq '.dependencies | length // 0' "$WORK_DIR/sbom.json" 2>/dev/null || echo "0")
    log "SBOM Components: $SBOM_COMPONENTS"
    log "SBOM Dependencies: $SBOM_DEPS"
fi

GITLEAKS_SECRETS=$(jq 'length // 0' "$WORK_DIR/gitleaks.json" 2>/dev/null || echo "0")
if [ "$GITLEAKS_SECRETS" -gt 0 ]; then
    log "Gitleaks Secrets: $GITLEAKS_SECRETS (WARNING: secrets detected!)"
else
    log "Gitleaks Secrets: 0"
fi
log "=================================="
log ""
log "Run complete"
send_done 0
