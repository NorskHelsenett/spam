#!/bin/bash
# Test runner container locally without a worker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# Default test repository (public)
REPO_URL="${1:-https://github.com/jonasbg/picoblog.git}"
REPO_REF="${2:-}"

# Detect container runtime (podman or docker)
if command -v podman &> /dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &> /dev/null; then
    CONTAINER_CMD="docker"
else
    echo "Error: Neither podman nor docker is installed"
    exit 1
fi

echo "Using container runtime: $CONTAINER_CMD"
echo "Building runner image..."
$CONTAINER_CMD build --build-arg TARGETARCH=amd64 -t spam-runner:local "$SCRIPT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo ""
echo "Running scanner against: $REPO_URL"
echo "Reference: ${REPO_REF:-default branch}"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Set options for podman
EXTRA_OPTS=""
VOLUME_OPTS=""
if [ "$CONTAINER_CMD" = "podman" ]; then
    VOLUME_OPTS=":Z"
    EXTRA_OPTS="--userns=keep-id"
fi

$CONTAINER_CMD run --rm \
    $EXTRA_OPTS \
    -e WORKER_URL="local" \
    -e RUN_ID="test-$(date +%s)" \
    -e RUN_TOKEN="dummy" \
    -e REPO_CLONE_URL="$REPO_URL" \
    -e OUTPUT_DIR="/output" \
    ${REPO_REF:+-e REPO_REF="$REPO_REF"} \
    -v "$OUTPUT_DIR:/output${VOLUME_OPTS}" \
    spam-runner:local

echo ""
echo "=========================================="
echo "Test complete!"
echo "=========================================="
echo ""

# Check if files were created and show summary
if [ -f "$OUTPUT_DIR/sbom.json" ]; then
    SBOM_SIZE=$(du -h "$OUTPUT_DIR/sbom.json" | cut -f1)
    echo "✓ SBOM generated: $OUTPUT_DIR/sbom.json ($SBOM_SIZE)"
    
    # Show component count if jq is available
    if command -v jq &> /dev/null; then
        COMP_COUNT=$(jq '.components | length' "$OUTPUT_DIR/sbom.json" 2>/dev/null || echo "?")
        echo "  - Components found: $COMP_COUNT"
    fi
else
    echo "✗ SBOM not found: $OUTPUT_DIR/sbom.json"
fi

if [ -f "$OUTPUT_DIR/betterleaks.json" ]; then
    BETTERLEAKS_SIZE=$(du -h "$OUTPUT_DIR/betterleaks.json" | cut -f1)
    echo "✓ BetterLeaks scan: $OUTPUT_DIR/betterleaks.json ($BETTERLEAKS_SIZE)"
    
    # Show secrets count if jq is available
    if command -v jq &> /dev/null; then
        SECRET_COUNT=$(jq '. | length' "$OUTPUT_DIR/betterleaks.json" 2>/dev/null || echo "?")
        if [ "$SECRET_COUNT" = "0" ]; then
            echo "  - No secrets found ✓"
        else
            echo "  - Secrets found: $SECRET_COUNT ⚠️"
        fi
    fi
else
    echo "✓ BetterLeaks scan: No secrets file (none found)"
fi

echo ""
