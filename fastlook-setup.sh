#!/usr/bin/env bash
set -euo pipefail

echo "[fastlook-setup] Installing minimal dependencies (subfinder-only)..."

# System deps
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  git curl jq ca-certificates

# Install yq (Go version) and required Go tools
if ! command -v go >/dev/null 2>&1; then
  echo "[fastlook-setup] Go toolchain required; this script should run in builder stage"
  exit 1
fi

# Install yq via static binary to avoid Go version constraints (optional)
YQ_VERSION="v4.42.1"
ARCH="amd64"
OS="linux"
echo "[fastlook-setup] Installing yq ${YQ_VERSION} binary"
curl -sSL -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_${OS}_${ARCH}"
chmod +x /usr/local/bin/yq
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
echo "[fastlook-setup] Minimal install complete (subfinder only)"

echo "[fastlook-setup] Done. Tools installed to GOPATH/bin"


