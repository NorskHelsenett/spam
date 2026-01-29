#!/bin/bash
# Test runner container locally without a worker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"

# Default test repository (public)
REPO_URL="${1:-https://github.com/NorskHelsenett/prism.git}"
REPO_REF="${2:-}"

echo "Building runner image..."
docker build -t spam-runner:local "$SCRIPT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo ""
echo "Running scanner against: $REPO_URL"
echo "Reference: ${REPO_REF:-default branch}"
echo "Output directory: $OUTPUT_DIR"
echo ""

docker run --rm \
    -e WORKER_URL="local" \
    -e RUN_ID="test-$(date +%s)" \
    -e RUN_TOKEN="dummy" \
    -e REPO_CLONE_URL="$REPO_URL" \
    -e OUTPUT_DIR="/output" \
    ${REPO_REF:+-e REPO_REF="$REPO_REF"} \
    -v "$OUTPUT_DIR:/output" \
    spam-runner:local

echo ""
echo "Test complete!"
echo "Results saved to:"
echo "  - $OUTPUT_DIR/sbom.json"
echo "  - $OUTPUT_DIR/gitleaks.json"
