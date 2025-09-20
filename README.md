# autoAr

An automated reconnaissance and vulnerability scanning tool that combines multiple tools for comprehensive web application security assessment, with integrated SQLite storage for findings.

## What's new (v2.0.0) - Web Portal & Dockerization
- **🌐 Modern Web Portal** at `autoar-web/`
  - Async job queue with live status updates
  - Cancel running jobs with one click
  - HTML report generation per scan (`/reports/<scan_id>/report.html`)
  - Browse raw logs and copied artefacts
  - Delete scan results (removes all files)
  - Real-time progress monitoring
- **🐳 Full Dockerization Support**
  - Complete Docker image with all recon tools
  - Docker Compose for easy deployment
  - Smart config path detection
  - Volume mounting for persistent data
- **🔧 Enhanced Features**
  - Smart tool-root detection (no external dependencies)
  - Safer repository (secrets ignored, gitleaks CI)
  - GitHub Actions for automated releases
  - Multi-platform binary builds
  - Comprehensive error handling

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

## Docker (Complete Solution)
The Docker image includes the web UI AND all recon tools, making it a complete solution for reconnaissance.

### Quick Start with Docker Compose
```bash
cd /home/sallam/AutoAR
docker compose up --build -d
# Open http://localhost:8888
```

### Manual Docker Build
```bash
docker build -t autoar-web -f autoar-web/Dockerfile .
```

### Docker Run (Complete)
```bash
docker run --rm -p 8888:8888 \
  -v "$(pwd)/autoar-web/web-data:/srv/web-data" \
  -v "$(pwd)/autoar.yaml:/srv/config/autoar.yaml:ro" \
  -v "$(pwd)/results:/srv/results" \
  -v "$(pwd)/Wordlists:/srv/Wordlists" \
  -v "$(pwd)/regexes:/srv/regexes" \
  -v "$(pwd)/nuclei_templates:/srv/nuclei_templates" \
  autoar-web
```

### Environment Variables
- `PORT` or `-addr` (default: 8888)
- `AUTOAR_CONFIG` or `-config` (default: `/srv/config/autoar.yaml`)
- `APKX_ROOT` (default: `/srv`)

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