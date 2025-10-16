#!/usr/bin/env bash
set -euo pipefail

log_info()    { printf "[INFO] %s\n" "$*"; }
log_warn()    { printf "[WARN] %s\n" "$*"; }
log_error()   { printf "[ERROR] %s\n" "$*" 1>&2; }
log_success() { printf "[OK] %s\n" "$*"; }


