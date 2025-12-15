#!/usr/bin/env bash
# Check required tools and directories; attempt installation when possible
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATH="$PATH:$HOME/go/bin:/usr/local/bin:/usr/bin"

# Optional logging helpers
if [[ -f "$ROOT_DIR/lib/logging.sh" ]]; then
  # shellcheck disable=SC1090
  # lib/logging.sh functionality in gomodules/ - functionality in gomodules/
else
  log_info(){ echo "[INFO] $*"; }
  log_success(){ echo "[OK] $*"; }
  log_warn(){ echo "[WARN] $*"; }
  log_error(){ echo "[ERR] $*"; }
fi

is_root() { [[ "$(id -u)" -eq 0 ]]; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

install_apt() {
  local pkg="$1"
  if is_root; then
    apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" || return 1
    return 0
  fi
  return 1
}

install_go_tool() {
  local bin="$1" pkg="$2"
  if has_cmd go; then
    GOFLAGS="-buildvcs=false" GOBIN=/usr/local/bin go install -v "$pkg" || go install -v "$pkg" || return 1
    has_cmd "$bin"
  else
    return 1
  fi
}

install_pip() {
  local pkg="$1"
  if has_cmd pip3; then
    pip3 install --no-cache-dir "$pkg" || pip3 install --user --no-cache-dir "$pkg" || return 1
    return 0
  fi
  return 1
}

install_curl_binary() {
  local url="$1" dest="$2"
  curl -fsSL "$url" -o "$dest" && chmod +x "$dest"
}

ensure_directories() {
  local -a dirs=(
    "$ROOT_DIR/new-results"
    "$ROOT_DIR/Wordlists"
    "$ROOT_DIR/nuclei_templates"
    "$ROOT_DIR/regexes"
  )
  for d in "${dirs[@]}"; do
    if [[ ! -d "$d" ]]; then
      mkdir -p "$d" && log_success "Created directory: $d" || log_warn "Failed to create $d"
    else
      log_success "OK directory: $d"
    fi
  done

  # Nuclei templates checkout if empty
  if [[ -d "$ROOT_DIR/nuclei_templates" && -z "$(ls -A "$ROOT_DIR/nuclei_templates" 2>/dev/null)" ]]; then
    log_info "Cloning nuclei templates..."
    if has_cmd git; then
      git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates "$ROOT_DIR/nuclei_templates" || log_warn "Failed to clone nuclei-templates"
    else
      log_warn "git not available; skip nuclei templates clone"
    fi
  fi
}

check_and_install() {
  local name="$1" check_bin="$2" how="$3"
  if has_cmd "$check_bin"; then
    log_success "✓ $name ($check_bin)"
    return 0
  fi
  log_warn "$name missing; attempting install: $how"

  case "$name" in
    dig)
      install_apt dnsutils || return 1;;
    jq)
      install_apt jq || return 1;;
    yq)
      install_curl_binary "https://github.com/mikefarah/yq/releases/download/v4.42.1/yq_linux_amd64" \
        "/usr/local/bin/yq" || return 1;;
    interlace)
      install_pip "git+https://github.com/codingo/Interlace.git" || return 1;;
    jsfinder)
      install_go_tool jsfinder github.com/kacakb/jsfinder@latest || return 1;;
    urlfinder)
      install_go_tool urlfinder github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest || return 1;;
    gf)
      install_go_tool gf github.com/tomnomnom/gf@latest || return 1;;
    anew)
      install_go_tool anew github.com/tomnomnom/anew@latest || return 1;;
    subfinder)
      install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || return 1;;
    httpx)
      install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest || return 1;;
    naabu)
      is_root && install_apt libpcap-dev || true
      install_go_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || return 1;;
    nuclei)
      install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || return 1;;
    ffuf)
      install_go_tool ffuf github.com/ffuf/ffuf/v2@latest || return 1;;
    kxss)
      install_go_tool kxss github.com/Emoe/kxss@latest || return 1;;
    qsreplace)
      install_go_tool qsreplace github.com/tomnomnom/qsreplace@latest || return 1;;
    dalfox)
      install_go_tool dalfox github.com/hahwul/dalfox/v2@latest || return 1;;
    jsleak)
      install_go_tool jsleak github.com/channyein1337/jsleak@latest || return 1;;
    dnsx)
      install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest || return 1;;
    curl)
      install_apt curl || return 1;;
    git)
      install_apt git || return 1;;
    aws)
      install_apt awscli || return 1;;
    trufflehog)
      if ! has_cmd trufflehog; then
        log_info "Installing trufflehog..."
        if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin; then
          log_success "✓ trufflehog installed successfully"
        else
          log_error "✗ Failed to install trufflehog"
          return 1
        fi
      else
        log_success "✓ trufflehog (installed)"
      fi;;
    fuzzuli)
      install_go_tool fuzzuli github.com/musana/fuzzuli@latest || return 1;;
    confused)
      install_go_tool confused2 github.com/h0tak88r/confused2/cmd/confused2@latest || return 1;;
    *)
      return 1;;
  esac

  if has_cmd "$check_bin"; then
    log_success "Installed $name"
    return 0
  fi
  return 1
}

run() {
  ensure_directories
  local -a tools=(
    subfinder httpx naabu nuclei ffuf kxss qsreplace gf dalfox urlfinder interlace jsleak jsfinder dnsx dig jq yq anew curl git aws trufflehog fuzzuli confused2
  )
  local missing=0 installed=0 total=${#tools[@]}

  for t in "${tools[@]}"; do
    if check_and_install "$t" "$t" "auto"; then
      ((installed++)) || true
    else
      log_warn "Still missing: $t"
      ((missing++)) || true
    fi
  done

  log_info "Tool check summary: $installed/$total present; $missing missing"
  [[ $missing -eq 0 ]]
}

case "${1:-}" in
  run|"" ) run ;;
  *) echo "Usage: check-tools [run]"; exit 1;;
esac


