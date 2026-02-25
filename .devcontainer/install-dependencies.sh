#!/usr/bin/env bash
set -e

echo "vscode ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/vscode

curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
