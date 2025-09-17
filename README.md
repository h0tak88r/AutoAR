# autoAr

An automated reconnaissance and vulnerability scanning tool that combines multiple tools for comprehensive web application security assessment, with integrated SQLite storage for findings.

<img width="1271" height="1162" alt="image" src="https://github.com/user-attachments/assets/0a08b273-07c2-42b0-ada4-ab15099af700" />


## What’s new (Web UI)
- Modern web portal at `autoar-web/`
  - Async job queue with live status
  - Cancel running jobs
  - HTML report per scan (`/reports/<scan_id>/report.html`)
  - Browse raw logs and copied artefacts
  - Delete scan result (removes all files)
- Smart tool-root detection (no apkx coupling)
- Safer repo (secrets ignored, gitleaks CI)
- Docker/Compose and GitHub Actions release

## Quick start (Web UI, native)
```bash
cd /home/sallam/AutoAR/autoar-web
# flags
# -addr    listen address (default :8888)
# -root    web-data root (default /srv) – use autoar-web folder for native
# -config  path to autoar.yaml
./autoar-web -addr :8888 \
  -root /home/sallam/AutoAR/autoar-web \
  -config /home/sallam/AutoAR/autoar.yaml
# Open http://localhost:8888 (forward port if remote)
```

## CLI Scan (original)
All subcommands remain available through `autoAr.sh`.

```bash
./autoAr.sh liteScan -d example.com
./autoAr.sh fastLook -d example.com
./autoAr.sh domain   -d example.com
```

## Docker (UI-only image)
The image serves the web UI. It doesn’t include recon tools inside the container by default. Use it to browse results or drive scans that run on the host (artefacts will appear in mounted web-data).

Build:
```bash
docker build -t autoar-web -f autoar-web/Dockerfile .
```
Run (recommended mounts):
```bash
docker run --rm -p 8888:8888 \
  -v "$(pwd)/autoar-web/web-data:/srv/web-data" \
  -v "$(pwd)/autoar.yaml:/srv/config/autoar.yaml:ro" \
  autoar-web
# Open http://localhost:8888
```
Run (full repo mounted – lets the container see autoAr.sh path, still UI-only):
```bash
docker run --rm -p 8888:8888 \
  -v "$(pwd):/srv" \
  autoar-web -root /srv/autoar-web -config /srv/autoar.yaml -addr :8888
```
Environment/flags:
- `PORT` or `-addr`
- `AUTOAR_CONFIG` or `-config` (default `/srv/config/autoar.yaml` in Docker)
- `AUTOAR_ROOT` or auto-detect (uses config dir, upward search for `autoAr.sh`, `$HOME/AutoAR`, etc.)

## Docker Compose
Compose is provided to avoid buildx and simplify local runs.
```bash
cd /home/sallam/AutoAR
docker compose up --build -d
# Stop: docker compose down
```
What it does:
- Builds from `autoar-web/Dockerfile`
- Runs on port `8888`
- Mounts `./autoar-web/web-data -> /srv/web-data`
- Mounts `./autoar.yaml -> /srv/config/autoar.yaml:ro`

## CI/CD: Releases and Secret Scans
- `.github/workflows/release.yml` builds binaries for Linux/macOS/Windows and pushes a Docker image to GHCR on tag push `v*.*.*`.
- `.gitleaks.toml` blocks secret leaks in CI.

Release flow:
```bash
git tag v1.0.0
git push origin v1.0.0
```

## Security & Secrets
- Real secrets live in `autoar.yaml` (ignored by git).
- A sanitized `autoar.sample.yaml` shows the schema.
- CI uses gitleaks to prevent accidental secret commits.

## Notes
- Install the recon toolchain on the host if you run scans natively: subfinder, dnsx, httpx, nuclei, ffuf, kxss, etc.
- A “full scan” Docker image can be added to bundle all tools; open an issue if you want this path. 
