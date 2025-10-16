#!/usr/bin/env bash
set -euo pipefail

ensure_dir() { mkdir -p "$1"; }

results_dir() {
  local d="$1"
  echo "new-results/$d"
}

domain_dir_init() {
  local domain="$1"
  local dir
  dir="$(results_dir "$domain")"
  mkdir -p "$dir"/subs "$dir"/urls "$dir"/vulnerabilities/js
  echo "$dir"
}


