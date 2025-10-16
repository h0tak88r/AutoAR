# AutoAR (Modular) – Discord + CLI

AutoAR is a modular security automation toolkit with a Discord bot frontend and a bash-based CLI backend. The system streams findings to Discord via a webhook and supports Dokploy deployments via Docker.

## Quick Start (Docker Compose)

1) Set environment (required):

- DISCORD_BOT_TOKEN: Bot token
- DISCORD_WEBHOOK: Channel webhook for logs/files

Optionally set API keys (SecurityTrails, etc.) in `.env`.

2) Build and run:

```bash
# full toolchain baked in by default
docker compose build
docker compose up -d
```

3) Bot will start and register slash commands. Use commands like:

- /subdomains domain:example.com
- /domain_run domain:example.com

## CLI Usage (inside container)

```bash
# Exec into the container
docker exec -it autoar-bot bash

# Examples
/app/main.sh subdomains get -d example.com
/app/main.sh cnames get -d example.com
/app/main.sh livehosts get -d example.com
/app/main.sh urls collect -d example.com
/app/main.sh reflection scan -d example.com
/app/main.sh nuclei run -d example.com
/app/main.sh ports scan -d example.com
/app/main.sh gf scan -d example.com
/app/main.sh sqlmap run -d example.com
/app/main.sh dalfox run -d example.com
/app/main.sh dns takeover -d example.com
/app/main.sh lite run -d example.com
/app/main.sh domain run -d example.com

# DB helpers (SQLite)
/app/main.sh db domains list
/app/main.sh db subdomains list -d example.com
/app/main.sh db subdomains export -d example.com -o /app/new-results/example.com/subs/db-subdomains.txt
```

## Configuration

- Config file: `/app/autoar.yaml` (generated at startup by `generate_config.sh` using env)
- Key env vars: `DISCORD_ONLY`, `DISCORD_WEBHOOK`, `AUTOAR_RESULTS_DIR`, `AUTOAR_CONFIG_FILE`
- Results path: `/app/new-results` (volume `results-data`)

## Build Variants

- RUN_SETUP_AT_BUILD=true: Bake full toolchain (default in compose)
- RUN_FASTLOOK_SETUP=true: Minimal install for fastLook verification

## Healthcheck

Container reports healthy if `discord` python module loads. The bot logs startup to stdout.

## Develop Branch Workflow

```bash
git checkout -b develop
# add/commit changes
git add -A && git commit -m "feat: modular db module and discord slash cmds"
# set upstream once
git push -u origin develop
```

Dokploy should be configured to track the `develop` branch or a specific tag. Ensure `docker-compose.yml` is at repo root (as provided).

## Notes

- Some modules skip gracefully if a tool is missing; run `setup.sh` or bake tools at build.
- In DISCORD_ONLY=true, files sent to Discord may be deleted locally after upload.
- `modules/db.sh` requires `sqlite3` binary available in the runtime (install if needed).