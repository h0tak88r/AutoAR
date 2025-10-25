# AutoAR Docker Setup

## Quick Start

To run AutoAR with all dependencies pre-installed (recommended):

```bash
# Build and start AutoAR in Docker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop AutoAR
docker-compose down
```

## Why Docker?

AutoAR requires several dependencies that are pre-installed in the Docker container:
- PostgreSQL client (psql)
- Python dependencies (psycopg2, discord.py, etc.)
- Go-based security tools (subfinder, httpx, confused2, etc.)
- All other scanning tools

## Database Commands

When running in Docker, these commands will work properly:
- `/db_domains` - List all domains
- `/db_subdomains` - List subdomains for a domain
- `/db_stats` - Database statistics
- `/db_cleanup` - Clean up old data

## Environment Variables

Create a `.env` file with your configuration:

```bash
# Discord Bot
DISCORD_BOT_TOKEN=your_bot_token_here
DISCORD_WEBHOOK=your_webhook_url_here

# Database (PostgreSQL)
DB_TYPE=postgresql
DB_HOST=your_db_host
DB_PORT=5432
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name

# API Keys (optional)
GITHUB_TOKEN=your_github_token
SECURITYTRAILS_API_KEY=your_key
# ... other API keys
```

## Troubleshooting

If you get "psql is not installed" errors, you're running outside Docker. Use Docker instead:

```bash
docker-compose up -d
```

This ensures all dependencies are available and properly configured.
