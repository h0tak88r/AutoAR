#!/usr/bin/env bash
#
# chaos-takeover.sh — bulk subdomain-takeover hunt over the ProjectDiscovery
# Chaos dataset, fully streamed (resolve → CNAME match → verify → Discord).
#
# Pipeline (every stage runs concurrently via pipes — no save-then-wait):
#   download all program ZIPs  →  unzip -p  →  dnsx (CNAME)  →  grep fingerprints
#     →  httpx  →  nuclei takeover templates  →  notify (Discord, per confirmed hit)
#
# A CNAME match is only a CANDIDATE. nuclei verifies fingerprint + unclaimed
# target before it's alerted, so Discord only gets real, reportable takeovers.
#
# Usage:
#   ./chaos-takeover.sh [options]
#     --webhook URL     Discord webhook — writes ~/.config/notify config on first run
#     --out DIR         working dir            (default: ./chaos_takeover)
#     --resolvers FILE  dnsx trusted resolvers (recommended for scale)
#     --par N           parallel ZIP downloads (default: 4)
#     --threads N       dnsx threads           (default: 300)
#     --no-download     skip download, reuse zips/ already on disk
#     --candidates-too  also send raw CNAME candidates to Discord (batched; noisy)
#     -h | --help
#
# Note: the bulk dataset (index.json + program ZIPs) is a PUBLIC endpoint and is
# fetched WITHOUT auth — sending CHAOS_API_KEY to it returns HTTP 400. The key is
# only used by the per-domain DNS API (the AutoAR Chaos integration / chaos-client).
#
# Deps: curl jq unzip dnsx httpx nuclei notify
set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
OUT="chaos_takeover"
INDEX_URL="https://chaos-data.projectdiscovery.io/index.json"
DL_PAR=4
DNSX_T=300
RESOLVERS=""
WEBHOOK=""
DO_DOWNLOAD=1
CANDIDATES_TOO=0
NOTIFY_ID="takeover"

# Takeover-able service fingerprints matched against the CNAME target. A match is
# a candidate only; nuclei confirms. Reference: github.com/EdOverflow/can-i-take-over-xyz
FP='vercel-dns\.com|github\.io|netlify\.app|azurewebsites\.net|elasticbeanstalk\.com|webflow\.io|gitbook\.io|readme\.io|railway\.app|herokudns\.com|herokuapp\.com|fastly\.net|ghost\.io|helpscoutdocs\.com|surge\.sh|bitbucket\.io|wpengine\.com|pantheonsite\.io|zendesk\.com|statuspage\.io'

# ── args ──────────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --webhook)        WEBHOOK="$2"; shift 2 ;;
    --out)            OUT="$2"; shift 2 ;;
    --resolvers)      RESOLVERS="$2"; shift 2 ;;
    --par)            DL_PAR="$2"; shift 2 ;;
    --threads)        DNSX_T="$2"; shift 2 ;;
    --no-download)    DO_DOWNLOAD=0; shift ;;
    --candidates-too) CANDIDATES_TOO=1; shift ;;
    -h|--help)        sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# ── deps ──────────────────────────────────────────────────────────────────────
# Note: no httpx — nuclei probes hosts itself, and many systems have the Python
# httpx CLI shadowing ProjectDiscovery's, which breaks the pipeline.
for t in curl jq unzip dnsx nuclei notify; do
  command -v "$t" >/dev/null || { echo "[!] missing dependency: $t" >&2; exit 1; }
done

# ── notify config (only if --webhook given and none exists) ──────────────────
NOTIFY_CFG="${HOME}/.config/notify/provider-config.yaml"
if [ -n "$WEBHOOK" ]; then
  mkdir -p "$(dirname "$NOTIFY_CFG")"
  cat > "$NOTIFY_CFG" <<YAML
discord:
  - id: "${NOTIFY_ID}"
    discord_username: "chaos-takeover"
    discord_format: "{{data}}"
    discord_webhook_url: "${WEBHOOK}"
YAML
  echo "[*] Wrote notify config → $NOTIFY_CFG"
elif [ ! -f "$NOTIFY_CFG" ]; then
  echo "[!] No notify config at $NOTIFY_CFG and no --webhook given." >&2
  echo "    Pass --webhook https://discord.com/api/webhooks/... or create the config first." >&2
  exit 1
fi

mkdir -p "$OUT/zips"
cd "$OUT"

# NOTE: the bulk dataset (index.json + program ZIPs) is a PUBLIC endpoint and
# rejects an Authorization header with HTTP 400 — so we deliberately do NOT send
# CHAOS_API_KEY here. The key is only for the per-domain DNS API.

# ── 1. index ──────────────────────────────────────────────────────────────────
if [ "$DO_DOWNLOAD" -eq 1 ]; then
  echo "[*] Fetching Chaos index…"
  curl -fsSL --retry 4 --retry-delay 2 -A "Mozilla/5.0 (chaos-takeover)" \
       "$INDEX_URL" -o index.json
  echo "    $(jq 'length' index.json) programs"

  # ── 2. download every ZIP — hardened (retries, resumable, non-fatal) ───────
  echo "[*] Downloading ZIPs (${DL_PAR} parallel, retries, skips finished)…"
  : > download_errors.log
  jq -r '.[].URL' index.json \
    | xargs -P "$DL_PAR" -I{} bash -c '
        f="zips/$(basename "$1")"
        [ -s "$f" ] && exit 0
        curl -fsSL --retry 6 --retry-all-errors --retry-delay 2 --connect-timeout 15 \
             -A "Mozilla/5.0 (chaos-takeover)" "$1" -o "$f" \
          || { echo "$1" >> download_errors.log; rm -f "$f"; }
      ' _ {} || true

  ok=$(ls zips/*.zip 2>/dev/null | wc -l | tr -d ' ')
  fail=$(wc -l < download_errors.log 2>/dev/null | tr -d ' ' || echo 0)
  echo "    downloaded=${ok}  failed=${fail}  (failed URLs → download_errors.log)"
  [ "${ok:-0}" -gt 0 ] || {
    echo "[!] 0 ZIPs downloaded — the public bulk dataset is likely gated now." >&2
    echo "    Fall back to the per-domain API: chaos -d <domain> -key \$CHAOS_API_KEY" >&2
    exit 1
  }
  [ "${fail:-0}" -gt 0 ] && echo "    (re-run to retry the ${fail} failed downloads)"
else
  echo "[*] --no-download: reusing $(ls zips/*.zip 2>/dev/null | wc -l | tr -d ' ') existing ZIPs"
fi

# Ensure the takeover templates are installed (first run / stale index).
echo "[*] Ensuring nuclei templates are up to date…"
nuclei -update-templates -silent 2>/dev/null || nuclei -ut 2>/dev/null || true

# ── 3. streaming resolve → match → verify → notify ──────────────────────────
DNSX_ARGS=(-cname -resp -silent -t "$DNSX_T")
[ -n "$RESOLVERS" ] && DNSX_ARGS+=(-r "$RESOLVERS")

echo "[*] Streaming: unzip → dnsx → grep → nuclei(takeover) → notify"
: > candidates.txt; : > confirmed.txt

# No httpx stage: nuclei probes each host itself, and -tags takeover selects the
# takeover templates by tag (path-independent across nuclei versions).
for z in zips/*.zip; do unzip -p "$z" 2>/dev/null || true; done \
  | dnsx "${DNSX_ARGS[@]}" \
  | stdbuf -oL grep -iE "$FP" \
  | tee -a candidates.txt \
  | awk '{print $1}' \
  | nuclei -tags takeover -silent \
  | tee -a confirmed.txt \
  | while IFS= read -r hit; do
      printf '🚨 Subdomain takeover confirmed: %s\n' "$hit" | notify -silent -id "$NOTIFY_ID"
    done

# ── 4. optional: batch the raw candidates to Discord too (noisy) ────────────
if [ "$CANDIDATES_TOO" -eq 1 ] && [ -s candidates.txt ]; then
  echo "[*] Sending $(wc -l < candidates.txt | tr -d ' ') raw candidates (batched)…"
  notify -silent -id "$NOTIFY_ID" -bulk < candidates.txt || true
fi

echo "[✓] Done — candidates=$(wc -l < candidates.txt | tr -d ' ')  confirmed=$(wc -l < confirmed.txt | tr -d ' ')"
echo "    candidates.txt (all CNAME matches) · confirmed.txt (nuclei-verified)"
