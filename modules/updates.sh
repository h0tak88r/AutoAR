#!/usr/bin/env bash
set -euo pipefail

# Root dir and libs
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/config.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/logging.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/utils.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/db.sh" 2>/dev/null || true

UPDATES_DIR="${AUTOAR_RESULTS_DIR}/updates"
mkdir -p "$UPDATES_DIR"

url_slug() {
  local url="$1"
  # Use sha1 to create stable slug
  echo -n "$url" | sha1sum | awk '{print $1}'
}

target_dir() {
  local url="$1"
  local slug
  slug="$(url_slug "$url")"
  echo "$UPDATES_DIR/$slug"
}

save_meta() {
  local url="$1"; shift
  local strategy="$1"; shift
  local pattern="${1:-}"
  local dir
  dir="$(target_dir "$url")"
  mkdir -p "$dir"
  {
    echo "url=$url"
    echo "strategy=$strategy"
    # Escape special characters in pattern for safe storage
    echo "pattern=$(printf '%s' "$pattern" | sed 's/|/\\|/g')"
    echo "created_at=$(date -u +%FT%TZ)"
  } > "$dir/meta.txt"
}

load_meta() {
  local url="$1"
  local dir
  dir="$(target_dir "$url")"
  [[ -f "$dir/meta.txt" ]] || return 1
  # shellcheck disable=SC1090
  # Load metadata, handling escaped patterns
  while IFS='=' read -r key value; do
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    # Unescape pattern field
    if [[ "$key" == "pattern" ]]; then
      export pattern="${value//\\|/|}"
    else
      export "$key"="$value"
    fi
  done < "$dir/meta.txt"
}

save_state() {
  local url="$1"; shift
  local key="$1"; shift
  local value="$1"
  local dir
  dir="$(target_dir "$url")"
  mkdir -p "$dir"
  {
    echo "last_${key}=$value"
    echo "last_checked=$(date -u +%FT%TZ)"
  } > "$dir/state.txt"
}

load_state_value() {
  local url="$1"; shift
  local key="$1"
  local dir
  dir="$(target_dir "$url")"
  [[ -f "$dir/state.txt" ]] || return 1
  # shellcheck disable=SC1090
  source <(sed 's/^/export /' "$dir/state.txt")
  eval "echo \"\${last_${key}:-}\""
}

fetch_content() {
  local url="$1"
  curl -fsSL --max-time 30 "$url"
}

fetch_headers() {
  local url="$1"
  curl -fsSI --max-time 20 "$url"
}

detect_rss_feed() {
  local html="$1"
  # Grep likely RSS/Atom links (simplified)
  local link
  link=$(echo "$html" | grep -oE 'href="[^"]*"' | grep -iE 'rss|atom' | head -1 || true)
  if [[ -n "$link" ]]; then
    echo "$link" | sed 's/.*href="//; s/".*//'
  fi
}

extract_latest_date_regex() {
  local html="$1"
  local pattern="$2"

  normalize_date() {
    local s="$1"
    # Try parse with GNU date; returns YYYY-MM-DD or empty
    date -d "$s" +%Y-%m-%d 2>/dev/null || true
  }

  pick_latest() {
    local latest="" latest_norm=""
    while IFS= read -r d; do
      [[ -z "$d" ]] && continue
      local norm
      norm=$(normalize_date "$d")
      [[ -z "$norm" ]] && continue
      if [[ -z "$latest_norm" || "$norm" > "$latest_norm" ]]; then
        latest="$d"
        latest_norm="$norm"
      fi
    done
    [[ -n "$latest" ]] && echo "$latest" || true
  }

  local matches
  if [[ -n "$pattern" ]]; then
    matches=$(echo "$html" | grep -Eo "$pattern" | head -n 500 || true)
  else
    # Generic: month-name dates and ISO dates
    matches=$(echo "$html" | grep -Eo '([A-Z][a-z]{3,9} [0-9]{1,2}, [0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})' | head -n 1000 || true)
  fi
  if [[ -z "$matches" ]]; then
    return 0
  fi
  echo "$matches" | pick_latest
}

compute_hash() {
  sha256sum | awk '{print $1}'
}

print_updates_usage() {
  cat <<EOF
Usage: updates <action> [options]

Actions:
  add     -u <url> [--strategy hash|size|headers|regex] [--pattern <regex>]
  check   [-u <url>]
  list
  remove  -u <url>
  monitor start  [-u <url>] [--interval <seconds>] [--daemon] [--all]
  monitor stop   [-u <url>] [--all]
  monitor list

Notes:
  - Default strategy is 'hash' (SHA-256 of page content)
  - 'headers' uses ETag/Last-Modified from HEAD response
  - 'regex' extracts first match and tracks it (e.g., date or post id)
EOF
}

# --- Database helpers (PostgreSQL) ---
db_enabled() {
  if [[ -n "${DB_HOST:-}" ]]; then
    db_ensure_connection >/dev/null 2>&1
    return $?
  fi
  return 1
}

ensure_updates_schema() {
  if ! db_enabled; then return 0; fi
  local sql
  sql=$(cat <<'EOFSQL'
CREATE TABLE IF NOT EXISTS updates_targets (
  id SERIAL PRIMARY KEY,
  url TEXT UNIQUE NOT NULL,
  strategy TEXT NOT NULL,
  pattern TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS updates_events (
  id SERIAL PRIMARY KEY,
  target_id INTEGER REFERENCES updates_targets(id) ON DELETE CASCADE,
  change_type TEXT NOT NULL,
  value TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_updates_events_target ON updates_events(target_id);
EOFSQL
)
  db_exec "$sql"
}

db_upsert_target() {
  local url="$1" strategy="$2" pattern="$3"
  ensure_updates_schema || true
  if ! db_enabled; then return 0; fi
  local esc_url esc_strategy esc_pattern
  esc_url=${url//\'/''}
  esc_strategy=${strategy//\'/''}
  esc_pattern=${pattern//\'/''}
  local sql="INSERT INTO updates_targets (url, strategy, pattern) VALUES ('${esc_url}', '${esc_strategy}', '${esc_pattern}') ON CONFLICT (url) DO UPDATE SET strategy = EXCLUDED.strategy, pattern = EXCLUDED.pattern, updated_at = NOW();"
  db_exec "$sql"
}

db_delete_target() {
  local url="$1"
  if ! db_enabled; then return 0; fi
  local esc_url=${url//\'/''}
  db_exec "DELETE FROM updates_targets WHERE url='${esc_url}';"
}

db_get_all_targets() {
  if ! db_enabled; then return 1; fi
  db_query "SELECT url, strategy, COALESCE(pattern,'') FROM updates_targets ORDER BY url;"
}

db_insert_event() {
  local url="$1" change_type="$2" value="$3"
  if ! db_enabled; then return 0; fi
  local esc_url=${url//\'/''}
  local esc_change=${change_type//\'/''}
  local esc_value=${value//\'/''}
  local tid
  tid=$(db_query "SELECT id FROM updates_targets WHERE url='${esc_url}' LIMIT 1;" | head -1)
  [[ -z "$tid" ]] && return 0
  db_exec "INSERT INTO updates_events (target_id, change_type, value) VALUES (${tid}, '${esc_change}', '${esc_value}');"
}

notify_discord_change() {
  local url="$1" change_type="$2" summary="$3"
  if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    local msg
    printf -v msg '[Updates] Change detected (%s) for: %s | %s' "$change_type" "$url" "$summary"
    discord_send_progress "$msg"
  fi
}

# Take initial snapshot and notify (used on first add/start)
initial_snapshot() {
  local url="$1"
  load_meta "$url" || return 1
  local result summary value
  case "${strategy:-hash}" in
    hash)
      result="$(fetch_content "$url" || true)"
      if [[ -z "$result" ]]; then summary="fetch failed"; else value="$(echo -n "$result" | compute_hash)"; fi
      ;;
    size)
      result="$(fetch_content "$url" || true)"
      if [[ -z "$result" ]]; then summary="fetch failed"; else value="$(echo -n "$result" | wc -c | awk '{print $1}')"; fi
      ;;
    headers)
      result="$(fetch_headers "$url" || true)"
      local etag lm
      etag="$(echo "$result" | grep -i '^ETag:' | sed -E 's/ETag:\s*"?([^\r"]+)"?.*/\1/i' | tr -d '\r' | head -1)"
      lm="$(echo "$result" | grep -i '^Last-Modified:' | sed -E 's/Last-Modified:\s*(.*)/\1/i' | tr -d '\r' | head -1)"
      value="$etag|$lm"
      ;;
    regex)
      result="$(fetch_content "$url" || true)"
      if [[ -n "$result" ]]; then
        value="$(extract_latest_date_regex "$result" "${pattern:-}")"
      fi
      ;;
    *) ;;
  esac
  # Persist state if we have a value
  if [[ -n "${value:-}" ]]; then
    case "${strategy:-hash}" in
      hash) save_state "$url" hash "$value" ;;
      size) save_state "$url" size "$value" ;;
      headers) save_state "$url" header "$value" ;;
      regex) save_state "$url" match "$value" ;;
    esac
    db_insert_event "$url" "init:${strategy:-}" "$value" || true
    notify_discord_change "$url" "init:${strategy:-}" "initial=$value"
    echo "[OK] Initial snapshot (${strategy}) = $value"
  else
    db_insert_event "$url" "init:${strategy:-}" "" || true
    notify_discord_change "$url" "init:${strategy:-}" "no-initial-value (check pattern/URL)"
    echo "[WARN] No initial value captured (${strategy})"
  fi
}

updates_add() {
  local url="" strategy="hash" pattern=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url) url="$2"; shift 2 ;;
      --strategy) strategy="$2"; shift 2 ;;
      --pattern) pattern="$2"; shift 2 ;;
      *) log_error "Unknown option: $1"; print_updates_usage; exit 1 ;;
    esac
  done
  [[ -n "$url" ]] || { log_error "URL is required"; exit 1; }
  save_meta "$url" "$strategy" "$pattern"
  log_success "Added target: $url - strategy=$strategy"
  db_upsert_target "$url" "$strategy" "$pattern"
  # Capture and send initial snapshot right away
  initial_snapshot "$url" || true
}

updates_list() {
  shopt -s nullglob
  local count=0
  for dir in "$UPDATES_DIR"/*; do
    [[ -d "$dir" ]] || continue
    if [[ -f "$dir/meta.txt" ]]; then
      load_meta "$(grep '^url=' "$dir/meta.txt" | cut -d'=' -f2-)" || continue
      echo "$url | strategy=${strategy:-hash} | pattern=${pattern:-}"
      ((count++))
    fi
  done
  if [[ $count -eq 0 ]]; then
    echo "No targets configured"
  fi
}

updates_remove() {
  local url=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url) url="$2"; shift 2 ;;
      *) log_error "Unknown option: $1"; print_updates_usage; exit 1 ;;
    esac
  done
  [[ -n "$url" ]] || { log_error "URL is required"; exit 1; }
  local dir
  dir="$(target_dir "$url")"
  if [[ -d "$dir" ]]; then
    rm -rf "$dir"
    log_success "Removed target: $url"
  else
    log_warn "Target not found: $url"
  fi
  db_delete_target "$url" || true
}

check_one() {
  local url="$1"
  load_meta "$url" || { log_warn "No metadata for $url"; return 0; }
  local html
  html="$(fetch_content "$url" || true)"
  if [[ -z "$html" ]]; then
    log_error "Failed to fetch $url"; return 1
  fi

  case "${strategy:-hash}" in
    hash)
      local h
      h="$(echo -n "$html" | compute_hash)"
      local prev
      prev="$(load_state_value "$url" hash || true)"
      if [[ "$h" != "$prev" ]]; then
        save_state "$url" hash "$h"
        log_success "Change detected - hash at $url"
        echo "$url | change=hash | at=$(date -u +%FT%TZ)"

        db_insert_event "$url" "hash" "$h" || true
        notify_discord_change "$url" "hash" "content hash changed"
      else
        log_info "No change - hash at $url"
      fi
      ;;
    size)
      local size prev
      size="$(echo -n "$html" | wc -c | awk '{print $1}')"
      prev="$(load_state_value "$url" size || true)"
      if [[ "$size" != "$prev" ]]; then
        save_state "$url" size "$size"
        log_success "Change detected - size=$size at $url"
        echo "$url | change=size | size=$size"

        db_insert_event "$url" "size" "$size" || true
        notify_discord_change "$url" "size" "content size=$size"
      else
        log_info "No change - size at $url"
      fi
      ;;
    headers)
      local headers etag lm prev
      headers="$(fetch_headers "$url" || true)"
      etag="$(echo "$headers" | grep -i '^ETag:' | sed -E 's/ETag:\s*"?([^\r"]+)"?.*/\1/i' | tr -d '\r' | head -1)"
      lm="$(echo "$headers" | grep -i '^Last-Modified:' | sed -E 's/Last-Modified:\s*(.*)/\1/i' | tr -d '\r' | head -1)"
      prev="$(load_state_value "$url" header || true)"
      local now_val="$etag|$lm"
      if [[ "$now_val" != "$prev" ]]; then
        save_state "$url" header "$now_val"
        log_success "Change detected - headers at $url"
        echo "$url | change=headers | etag=$etag | lm=$lm"

        db_insert_event "$url" "headers" "$now_val" || true
        notify_discord_change "$url" "headers" "etag=$etag lm=$lm"
      else
        log_info "No change - headers at $url"
      fi
      ;;
    regex)
      local match prev
      match="$(extract_latest_date_regex "$html" "${pattern:-}")"
      prev="$(load_state_value "$url" match || true)"
      if [[ -n "$match" && "$match" != "$prev" ]]; then
        save_state "$url" match "$match"
        log_success "Change detected - regex=$match at $url"
        echo "$url | change=regex | match=$match"

        db_insert_event "$url" "regex" "$match" || true
        notify_discord_change "$url" "regex" "match=$match"
      else
        log_info "No change - regex at $url"
      fi
      ;;
    *)
      log_error "Unknown strategy: ${strategy}"
      return 1
      ;;
  esac
}

updates_check() {
  local url=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url) url="$2"; shift 2 ;;
      *) log_error "Unknown option: $1"; print_updates_usage; exit 1 ;;
    esac
  done

  if [[ -n "$url" ]]; then
    check_one "$url"
    return $?
  fi

  shopt -s nullglob
  for dir in "$UPDATES_DIR"/*; do
    [[ -d "$dir" && -f "$dir/meta.txt" ]] || continue
    load_meta "$(grep '^url=' "$dir/meta.txt" | cut -d'=' -f2-)" || continue
    [[ -n "${url:-}" ]] || continue
    check_one "$url" || true
  done
}

is_running() {
  local pid="$1"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

monitor_start() {
  local url="" interval=86400 daemon=false monitor_all=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url) url="$2"; shift 2 ;;
      --interval) interval="$2"; shift 2 ;;
      --daemon) daemon=true; shift ;;
      --all) monitor_all=true; shift ;;
      *) log_error "Unknown option: $1"; print_updates_usage; exit 1 ;;
    esac
  done

  # If --all, start monitors for all targets from DB
  if [[ "$monitor_all" == true ]]; then
    local count=0
    if db_enabled; then
      local rows
      rows=$(db_get_all_targets || true)
      if [[ -z "$rows" ]]; then
        log_warn "No targets found in database"
        return 0
      fi
      echo "Starting monitors for all database targets..."
      echo "DEBUG: Total rows from DB: $(echo "$rows" | wc -l)"
      while IFS='|' read -r t_url t_strategy t_pattern; do
        echo "DEBUG: Loop iteration $count - URL: '$t_url'"
        [[ -z "$t_url" ]] && { echo "DEBUG: Empty URL, skipping"; continue; }
        echo "DEBUG: Saving meta for $t_url"
        save_meta "$t_url" "$t_strategy" "$t_pattern"
        # If no state file yet, take initial snapshot to verify pattern
        if [[ ! -f "$(target_dir "$t_url")/state.txt" ]]; then
          echo "DEBUG: Taking initial snapshot for $t_url"
          initial_snapshot "$t_url" || true
        else
          echo "DEBUG: State file exists for $t_url"
        fi

        # Start monitor for this target
        local t_dir t_pid_file
        t_dir="$(target_dir "$t_url")"
        echo "DEBUG: Target dir: $t_dir"
        mkdir -p "$t_dir"
        t_pid_file="$t_dir/monitor.pid"
        t_log_file="$t_dir/monitor.log"
        echo "DEBUG: PID file: $t_pid_file"

        # Check if already running
        if [[ -f "$t_pid_file" ]]; then
          local oldpid
          oldpid="$(cat "$t_pid_file" 2>/dev/null || true)"
          if is_running "$oldpid"; then
            log_warn "[${count}] Monitor already running for $t_url (PID: $oldpid)"
            ((count++))
            continue
          fi
        fi

        # Start daemon for this URL using nohup (same as single-target mode)
        # Use escaped variables for proper expansion in subshell
        echo "DEBUG: About to start nohup for $t_url with interval=$interval"
        nohup bash -c "
          echo \$BASHPID > \"$t_pid_file\"
          while true; do
            \"$ROOT_DIR/modules/updates.sh\" check -u \"$t_url\" || true
            sleep $interval
            [[ -f \"$t_pid_file\" ]] || break
          done
        " >> "$t_log_file" 2>&1 & disown

        sleep 0.2
        echo "DEBUG: Checking if PID file was created: $t_pid_file"
        if [[ -f "$t_pid_file" ]]; then
          local check_pid=$(cat "$t_pid_file" 2>/dev/null)
          if is_running "$check_pid"; then
            echo "DEBUG: Process $check_pid is running for $t_url"
          else
            echo "DEBUG: WARNING - Process $check_pid is NOT running for $t_url (immediately crashed?)"
            [[ -f "$t_log_file" ]] && echo "DEBUG: Log file contents:" && head -20 "$t_log_file"
          fi
        else
          echo "DEBUG: ERROR - PID file not created for $t_url"
        fi

        log_success "[${count}] Started monitor - daemon for $t_url - interval=${interval}s"
        ((count++))
      done <<< "$rows"
    fi
    echo ""
    log_success "✓ Started monitors for $count target(s) - interval=${interval}s ($(($interval / 3600)) hours)"
    return 0
  fi

  # Single target mode
  [[ -n "$url" ]] || { log_error "URL is required - or use --all"; exit 1; }
  local dir pid_file log_file
  dir="$(target_dir "$url")"
  mkdir -p "$dir"
  pid_file="$dir/monitor.pid"
  log_file="$dir/monitor.log"

  if [[ -f "$pid_file" ]]; then
    local oldpid
    oldpid="$(cat "$pid_file" 2>/dev/null || true)"
    if is_running "$oldpid"; then
      log_warn "Monitor already running for $url with PID $oldpid"
      echo "$oldpid"
      return 0
    fi
  fi

  if [[ "$daemon" == true ]]; then
    # Inline the monitor loop code directly in nohup (same as --all mode)
    nohup bash -c "
      echo \$BASHPID > \"$pid_file\"
      while true; do
        \"$ROOT_DIR/modules/updates.sh\" check -u \"$url\" || true
        sleep $interval
        [[ -f \"$pid_file\" ]] || break
      done
    " >> "$log_file" 2>&1 & disown
    log_success "Started monitor - daemon for $url - interval=${interval}s"
  else
    # Non-daemon mode - run monitor loop in foreground
    echo $$ > "$pid_file"
    log_success "Started monitor for $url - interval=${interval}s"
    while true; do
      "$ROOT_DIR/modules/updates.sh" check -u "$url" || true
      sleep "$interval"
      # If pid file removed, stop
      [[ -f "$pid_file" ]] || break
    done
  fi
}

monitor_stop() {
  local url="" stop_all=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -u|--url) url="$2"; shift 2 ;;
      --all) stop_all=true; shift ;;
      *) log_error "Unknown option: $1"; print_updates_usage; exit 1 ;;
    esac
  done

  # If --all, stop all monitors for DB targets
  if [[ "$stop_all" == true ]]; then
    local count=0 stopped=0
    if db_enabled; then
      local rows
      rows=$(db_get_all_targets || true)
      while IFS='|' read -r t_url t_strategy t_pattern; do
        [[ -z "$t_url" ]] && continue
        local t_dir t_pid_file t_pid
        t_dir="$(target_dir "$t_url")"
        t_pid_file="$t_dir/monitor.pid"
        if [[ -f "$t_pid_file" ]]; then
          t_pid="$(cat "$t_pid_file" 2>/dev/null || true)"
          rm -f "$t_pid_file"
          if is_running "$t_pid"; then
            kill "$t_pid" >/dev/null 2>&1 || true
            ((stopped++))
          fi
        fi
        ((count++))
      done <<< "$rows"
    fi
    log_success "Stopped $stopped monitors out of $count targets"
    return 0
  fi

  # Single target mode
  [[ -n "$url" ]] || { log_error "URL is required - or use --all"; exit 1; }
  local dir pid_file
  dir="$(target_dir "$url")"
  pid_file="$dir/monitor.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    rm -f "$pid_file"
    if is_running "$pid"; then
      kill "$pid" >/dev/null 2>&1 || true
      log_success "Stopped monitor for $url - PID $pid"
      return 0
    else
      log_warn "No running process for $url - stale PID file removed"
      return 1
    fi
  else
    log_warn "Monitor not running for $url"
    return 1
  fi
}

monitor_list() {
  local printed=0
  # Prefer DB-backed list including status
  if db_enabled; then
    local rows
    rows=$(db_get_all_targets || true)
    if [[ -n "$rows" ]]; then
      while IFS='|' read -r t_url t_strategy t_pattern; do
        [[ -z "$t_url" ]] && continue
        local t_dir t_pid_file t_pid status="stopped"
        t_dir="$(target_dir "$t_url")"
        t_pid_file="$t_dir/monitor.pid"
        if [[ -f "$t_pid_file" ]]; then
          t_pid="$(cat "$t_pid_file" 2>/dev/null || true)"
          if is_running "$t_pid"; then status="running PID=$t_pid"; else status="stale"; fi
        fi
        echo "$t_url | strategy=${t_strategy:-hash} | monitor=$status"
        printed=1
      done <<< "$rows"
    fi
  fi

  # Also show any running monitors not in DB (filesystem only)
  shopt -s nullglob
  for dir in "$UPDATES_DIR"/*; do
    [[ -d "$dir" && -f "$dir/meta.txt" ]] || continue
    load_meta "$(grep '^url=' "$dir/meta.txt" | cut -d'=' -f2-)" || continue
    local pid_file="$dir/monitor.pid" pid status="stopped"
    if [[ -f "$pid_file" ]]; then
      pid="$(cat "$pid_file" 2>/dev/null || true)"
      if is_running "$pid"; then status="running PID=$pid"; else status="stale"; fi
    fi
    # Skip if already printed in DB pass
    [[ "$printed" -eq 1 ]] && continue
    echo "$url | strategy=${strategy:-hash} | monitor=$status"
    printed=1
  done
  [[ "$printed" -eq 0 ]] && echo "No monitors configured"
}

updates_monitor() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    start) monitor_start "$@" ;;
    stop)  monitor_stop  "$@" ;;
    list)  monitor_list       ;;
    *)     print_updates_usage; exit 1 ;;
  esac
}

updates_main() {
  local action="${1:-}"; shift || true
  case "$action" in
    add)    updates_add "$@" ;;
    list)   updates_list ;;
    remove) updates_remove "$@" ;;
    check)  updates_check "$@" ;;
    monitor) updates_monitor "$@" ;;
    *)      print_updates_usage; exit 1 ;;
  esac
}

updates_main "$@"
