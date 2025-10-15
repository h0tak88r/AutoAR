#!/usr/bin/env bash
set -euo pipefail

echo "[fastlook-setup] Installing minimal dependencies for fastLook..."

# System deps
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  git curl jq ca-certificates

# Install yq (Go version) and required Go tools
if ! command -v go >/dev/null 2>&1; then
  echo "[fastlook-setup] Go toolchain required; this script should run in builder stage"
  exit 1
fi

go install github.com/mikefarah/yq/v4@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/Emoe/kxss@latest
go install -v github.com/pentest-company/urlfinder@latest
go install -v github.com/kacakb/jsfinder@latest || true

echo "[fastlook-setup] Done. Tools installed to GOPATH/bin"


