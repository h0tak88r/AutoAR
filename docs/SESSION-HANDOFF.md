# Session Handoff — 2026-08-24

Purpose: everything done in this session, where it lives, and what is still
pending, so another agent can pick up without re-discovering the context.

## Environment / deploy flow (verified working)

- Repo: `github.com/h0tak88r/AutoAR`. Remotes: `origin` (public `AutoAR`),
  `private` (`AutoAR-private`).
- Branch flow: work happens on local branch `private`; push with
  `git push private HEAD:testing` and `git push private HEAD:master`
  (master is what Dokploy builds; testing mirrors it).
- Dokploy: on the VPS `sallam@169.58.14.255` (SSH key auth works), Dokploy UI
  on `localhost:3000`. App: project **AutoAR** → application **autoar-api**,
  applicationId `NaTHyGNBhsrL_TdKqrNMI`, builds `Dockerfile` from
  `git@github.com:h0tak88r/AutoAR-private.git` branch **master**.
- Deploy via API (run on the VPS over SSH):
  ```bash
  curl -X POST -H "x-api-key: <dokploy-key>" -H "Content-Type: application/json" \
    -d '{"applicationId":"NaTHyGNBhsrL_TdKqrNMI"}' \
    http://localhost:3000/api/application.deploy
  # poll: GET /api/application.one?applicationId=... -> .applicationStatus running|done|error
  ```
  A full Dockerfile build takes ~10–15 min. `done` + container
  `Up … (healthy)` = success.
- The Dokploy API key the user provided is in the chat history (2026-08-07
  session); do not commit it anywhere.

## Feature 1 — Multiple Shodan API keys (DONE, in tree, committed by user)

- `internal/utils/env.go`: `ParseKeyList(raw)` — splits comma/semicolon/
  newline/whitespace-separated key lists, strips quotes, dedupes.
- Settings: `SHODAN_API_KEYS` (list) + legacy `SHODAN_API_KEY` merged, DB-backed
  via `persistedEnvKeys` (`internal/api/settings_persist.go`), surfaced in
  `/api/config` as `shodan_keys_set`/`shodan_keys_count`, UI textarea in
  Settings → Platforms & Keys (`internal/api/ui/pages/settings.js`).
- Subfinder config generation (`internal/scanner/subdomains/subdomains.go`)
  emits `shodan: ["k1","k2"]`. Note: the user refactored key access through an
  `internal/.../apikeys` package (`apikeys.All("SHODAN_API_KEYS")`) and added a
  generic `subfinder_key_counts` config field — follow that pattern now.

## Feature 2 — Client-side bug candidates in JS scan (DONE, DEPLOYED)

Commit `58fdf8b5` on private `testing`+`master`; deployed on Dokploy 2026-08-24
(container healthy).

- `regexes/client-side-patterns.yaml` (new): 25 RE2 regexes, names prefixed by
  bug class: `DOM XSS Source/Sink`, `Dynamic Code Execution`, `postMessage`,
  `Open Redirect Sink`, `Prototype Pollution`, `Sensitive Storage`,
  `CORS Hint`, `Insecure WebSocket`. Shipped in Docker via `COPY regexes/`.
- `internal/utils/pattern_matcher.go`: new exported `LoadPatternFile(dir, name)`;
  `LoadSecretPatterns` refactored to use it (behavior unchanged).
- `internal/scanner/jsscan/jsscan.go`: `scanJSFiles` downloads each JS file ONCE
  and applies both pattern sets; `emitClientSideFindings` writes
  `js-clientside-vulnerabilities.json` (module `js-clientside`, template
  `JS Client-Side Candidate (<class>)`). Severity map in `clientSideSeverity`:
  sources=info, sinks/postMessage/prot-pollution/dyn-exec=medium, rest=low.
- Results wiring: `internal/api/scan_results_api.go` (`inferModuleFromFileName`
  + raw→JSON supersede map), `internal/api/api.go` skip-list,
  `internal/api/ui/pages/scan-common.js` module fallback — all treat
  `js-clientside*` as module `js-analysis`.
- Tests: `internal/utils/pattern_matcher_test.go::TestClientSidePatternsFileLoads`
  (every regex compiles + fires on samples) and `env_test.go::TestParseKeyList`.

## Feature 3 — Nuclei template watcher via PDCP API (DONE)

Shipped in the same commit as the rescan fix below. Files:
- `internal/api/nuclei_template_watch.go` (new), `nuclei_template_watch_test.go`
  (new), `internal/api/ui_api.go` (extracted `runGlobalNucleiScan`),
  `internal/app/app.go` (daemon start), `internal/api/settings_persist.go`
  (`PDCP_API_KEY` persisted), `env.example` (docs).

How it works:
- Daemon started at boot in `app.go` (gated on `DB_HOST`), first tick 30s after
  start, then every 30 min (`NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES`, floor 5).
- Source: PDCP search API `GET https://api.projectdiscovery.io/v2/template/search`
  with header `X-API-Key`, params `scope=public&sort_desc=created_at&fields=...`.
  Key: `PDCP_API_KEY`, fallback `CHAOS_API_KEY` (same PDCP key; if Chaos is
  configured in Settings the watcher already works).
- Watermark in settings DB: `nuclei_templates_last_created_at` +
  `nuclei_templates_seen_ids` (csv, cap 300). First-ever run baselines silently
  + one "watch active" Discord message.
- On new templates: Discord alert via `MONITOR_WEBHOOK_URL` (name, SEVERITY,
  CVE ids, GitHub link from the `uri` field), then auto-runs the raw YAML from
  the API response (written to a temp dir; nuclei accepts a dir) against all
  live hosts via `runGlobalNucleiScan` — same engine as "Run Nuclei Template".
  Runs appear on the Scans page as `nuclei-watch-<timestamp>`.
- Caps: max 10 templates staged/run per cycle (alert lists all);
  `NUCLEI_TEMPLATE_WATCH=off` disables, `NUCLEI_TEMPLATE_AUTORUN=off` = notify only.
- Verified: `go build`, `go vet`, full `go test ./...` (38 pkgs) green; PDCP API
  responses confirmed live with the user's key.
- Note: the user's PDCP API key was pasted in chat. It needs to be set as
  `PDCP_API_KEY` in the Dokploy env (or rely on the saved CHAOS_API_KEY — same
  key) for the watcher to activate.

## Feature 4 — Nuclei rescan support (DONE)

Rescan for `nuclei` scans previously failed with "in-process scan type nuclei
does not support rescan yet" because the stored command had no template.

- `internal/api/scan_runner.go`: new `RunScanInProcessWithCommand` (explicit
  stored command); `RunScanInProcess` delegates with the default.
- `internal/api/ui_api.go::apiRunGlobalNuclei`: raw-YAML templates are written
  to a durable per-scan file `new-results/global-subdomains/templates/<scanID>.yaml`
  (NOT a deleted temp file), and the scan record's command is stored as
  `inprocess:nuclei target=global-subdomains template=<path-or-id>`.
- `internal/api/scan_handlers.go::runInProcessRescan`: signature now takes the
  stored command; new `case "nuclei"` parses ` template=` and replays via
  `runGlobalNucleiScan`. Absolute template paths must still exist on disk;
  relative values pass through (nuclei template IDs resolve at runtime).
- Old nuclei scans (no template in command) get a specific error telling the
  user to re-run from the Scans page. Watcher-triggered scans store no template
  (temp dir is deleted after the run) — rescanning them gives the same message.

## Conventions worth following (observed in this codebase)

- Settings that must survive Dokploy redeploys: env var + entry in
  `persistedEnvKeys` (`settings_persist.go`); boot does `SeedDBFromEnv()` then
  `HydrateEnvFromDB()`; save via `saveEnvSetting`.
- Time-lapse watermarks: settings table (see `program_watch.go` pattern).
- Scan artifacts: `utils.WriteJSONToScanDir(scanID, "<name>-vulnerabilities.json", …)`
  + `WriteNoFindingsJSON`; raw `.txt` intermediates are superseded via the
  `rawToJSON` map in `scan_results_api.go` and the skip-list in `api.go`.
- `go vet ./...` and `go test ./...` must stay green; repo is NOT gofmt-clean
  globally — don't blanket `gofmt -w` files you didn't touch.

## Not done

- The deep code review from the first request never ran: the review subagent
  died on a billing-quota 403. Only build/vet/tests were verified. If wanted,
  redo a focused review of `internal/api` (auth, SQL string building) and
  scanner command construction.
