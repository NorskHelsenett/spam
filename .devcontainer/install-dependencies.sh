#!/usr/bin/env bash
set -e

echo "vscode ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/vscode

curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install mocc - download latest version
MOCC_ARCH="linux-arm64"
if [ "$(uname -m)" = "x86_64" ]; then
    MOCC_ARCH="linux-amd64"
fi

# Get latest release version
MOCC_VERSION=$(curl -s https://api.github.com/repos/jonasbg/mocc/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
MOCC_URL="https://github.com/jonasbg/mocc/releases/download/${MOCC_VERSION}/mocc-${MOCC_ARCH}.tar.gz"

echo "Downloading mocc ${MOCC_VERSION} for ${MOCC_ARCH}..."
wget -O /tmp/mocc.tar.gz "${MOCC_URL}"

# Extract to bin folder
mkdir -p /tmp/mocc/
tar -xzf /tmp/mocc.tar.gz -C /tmp/mocc/

sudo mv /tmp/mocc/mocc /usr/local/bin/mocc
sudo chmod a+x /usr/local/bin/mocc

# Clean up temp files
rm /tmp/mocc.tar.gz
rm -rf /tmp/mocc/

echo "mocc installed to /usr/local/bin/mocc"