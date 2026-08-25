# Session Handoff — 2026-08-24

> **Update 2026-08-25 (review + fixes session):** a full code/DB/CI review ran
> (the one deferred below), followed by fixes. See `git log` for
> `fix(...)` commits of that date. Summary of what changed:
>
> - **Code:** nuclei `runNucleiCommand` now builds its engine on
>   `utils.CurrentScanContext()` (new hook, registered in `api/scans.go init()`)
>   → `/scan/nuclei` + domain/subdomain workflows are cancellable; atomic match
>   counters in `ui_api.go` / `pipeline_api.go`; `writeErr` via `sync.Once` in
>   both nuclei callbacks; `SanitizeHostname` rejects invalid UTF-8 *before*
>   `strings.ToLower` mangles it (was a silent batch-killer on PG);
>   `InsertJSFile` (both dialects) normalizes via `SanitizeHostname`;
>   jsscan initial fetches gated by `utils.ValidatePublicHTTPURL` (SSRF);
>   `r2storage` globals now guarded by RWMutex + snapshot (safe live Reload);
>   nuclei URL-mode results dir sanitized (`SanitizeTargetSegment`); ops-tools
>   report `document.write` escapes interpolations; `autoar db backup
>   [--upload-r2]` CLI command added (README previously documented it — the
>   implementation existed but nothing invoked it); CI/release workflows use
>   `go-version-file: go.mod`. New tests: `internal/db/hostname_test.go`.
>   `go build` / `go vet` / `go test ./...` (38 pkgs) green.
> - **VPS (169.58.14.255):** nightly Postgres backup cron 03:15
>   (`/home/sallam/backups/autoar-db/backup.sh`, 14-day retention, pg_dump
>   inside the postgres container); swarm service `autoar-api-ifqfw7` updated —
>   published port 8000 REMOVED and `autoar-results` volume mounted at
>   `/app/new-results` (results + rescan templates now survive redeploys);
>   iptables drop of external :8000 + root @reboot cron re-applying it
>   (defense in depth). Verified: domain https 200, raw IP :8000 closed,
>   container healthy, watcher restarted.
> - **Still on the user:** deploy the new build via Dokploy (the fixes need a
>   rebuild); mirror the port-removal + volume in the **Dokploy UI** (Dokploy's
>   stored config still has the port and no volume — a Dokploy redeploy would
>   revert the direct `docker service update`); rotate the expired Intigriti
>   token (Settings → Platforms & Keys; logs show 401).

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

## Feature 5 — Pre-deploy security review + fixes (DONE)

A 4-agent review (API layer, DB/scanner layers, dashboard JS XSS, the session's
own commits) produced ~30 findings. Fixed before this deploy:

- **HIGH — URL monitor SSRF** (`internal/scanner/monitor/daemon.go`,
  `internal/utils/ssrf.go` new): monitor fetched arbitrary URLs and the regex
  strategy shipped body content to Discord — a working cloud-metadata
  credential-exfil channel. Now: scheme allowlist + private/loopback/link-local
  IP rejection (incl. per-redirect revalidation via `utils.NewPublicHTTPClient`),
  5 MB body cap, 20-way concurrency bound.
- **jsscan redirect-SSRF** (`jsscan.go`): JS downloads refuse cross-host
  redirects (a target's /x.js 302ing to 169.254.169.254 would be secret-scanned
  and shipped to artifacts/webhooks).
- **keyhack API key leak** (`api.go`): `storedCommand()` redacts the keyhack
  validate API key from the persisted/displayed scan command (was readable via
  GET /api/scans/:id).
- **scan-ID collisions** (`ui_api.go`): global nuclei runs now use
  `scan-<ts>-<uuid8>` — two runs in one second previously collided on the
  CreateScan insert AND the persisted template path.
- **Watcher fixes** (`nuclei_template_watch.go`): watermark persisted BEFORE the
  scan dispatches (restart mid-scan no longer re-announces); staged temp dir
  cleaned when the runner aborts without calling fn; empty-created_at cycle
  logs instead of silently looping.
- **Per-scan nuclei output** (`ui_api.go`): `nuclei-<scanID>.json` instead of
  the shared `nuclei-global.json` that overlapping runs truncated.
- **Artifact indexing** (`api.go`): `new-results/<target>/templates/*.yaml`
  (rescan inputs) are never indexed/copied as scan findings.
- **Log-stream traversal guard** (`scan_results_api.go`): `/api/scans/:id/logs/stream`
  rejects IDs with `..`/separators (a literal `..` read one level above the
  results root via the log-file fallback).

Deferred (known, documented, not blocking): URL-monitor `regex` strategy still
stores matched body content in the DB detail (fetch is now guarded, content
handling is by design); Postgres `BatchInsertSubdomains` aborts the whole batch
on one bad row (tx semantics, silent data loss — worth fixing later);
`BatchInsertSubdomains` hostname validation gaps; nuclei URL-mode results-dir
traversal (`internal/scanner/nuclei/nuclei.go:81` missing SanitizeTargetSegment);
SQLite backup is a raw file copy under WAL (use VACUUM INTO); subfinder config
persists keys at a predictable temp path; `jsscan.extractRootDomain` is naive
(use utils.ParseSubdomainAndRoot if its callers change); dashboard
`ops-tools.js generateScanReport` document.write XSS (scan target not escaped);
per-process (not per-IP) API rate limiter; `loginAttempts` map never prunes;
`scans.go` ExecCmd read-after-unlock race; lexical `created_at` comparison in
the watcher (fractional-second edge).

## Status at end of session

Commits `1562872` (template watch + nuclei rescan) and `a1daf67` (security
review fixes) are pushed to private `testing` + `master` and DEPLOYED on
Dokploy (verified healthy 2026-08-24 ~22:10 VPS time). The watcher confirmed
live in container logs: `watcher started (interval 30m0s, autorun=true)` +
baseline seeded from PDCP. The PDCP key resolves from the DB-hydrated
CHAOS_API_KEY (no extra env needed).

Follow-up fixes (same day, after the first watcher run hit production):

- **Un-cancellable nuclei scans**: `RunGlobalTemplate` built its engine on
  `context.Background()`, so UI cancel marked the DB row but the engine kept
  sweeping all hosts and firing webhooks. Fixed by threading the scan lifetime
  context: `ScanInfo.Ctx` (`scans.go`) set by `RunScanInProcessWithCommand`,
  read via `scanContext(scanID)` and passed into
  `nuclei.RunGlobalTemplate(ctx, …)` (signature changed — ctx is the first
  param; callers: `ui_api.go::runGlobalNucleiScan`,
  `pipeline_api.go::runRootPipeline`). Verified empirically: engine stops ~0s
  after cancel (`err=context canceled`).
  NOTE: the domain-scan nuclei path (`runNucleiCommand` in nuclei.go) still
  uses `context.Background()` — same fix applies if cancel is wanted there.
- **Duplicate alerts/runs per template**: the PDCP search index returns BOTH
  the public and draft document of a template (same `id`, same `uri`,
  different raw revision). The watcher now dedupes each batch by template ID.
- **Empty Target in Discord hits**: `event.Matched` can be empty for some
  event shapes; both nuclei callbacks now fall back Matched → URL → Host.
- **info-severity templates are alert-only**: the watcher still announces them
  on Discord but never auto-runs them (`nucleiWatchRunnable` — panels and
  tech-detects aren't worth a full live-host sweep). Empty/unknown severity
  fails open (runs).
- The leaked staging dir from a cancelled scan (`/tmp/nuclei-watch-templates-*`)
  is wiped by the fn cleanup when the engine actually stops — with ctx now
  wired, cancel → engine stops → cleanup runs.

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
