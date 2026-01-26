#!/usr/bin/env bash
set -e

echo "vscode ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/vscode

curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install mocc - download latest version
MOCC_ARCH="linux-arm64"
if [ "$(uname -m)" = "x86_64" ]; then
    MOCC_ARCH="linux-amd64"
fi
