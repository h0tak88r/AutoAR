# Python Scripts

This directory contains all Python scripts used by AutoAR for enhanced functionality and reliability.

## Scripts

### `db_handler.py`
Database handler for PostgreSQL operations. Provides a Python-based interface for all database operations including:
- Domain management (insert, get, delete)
- Subdomain batch operations
- JS file management
- Database connection handling

### `github_wordlist.py`
GitHub Target Based Wordlist generator. Creates comprehensive wordlists from GitHub organization ignore files:
- Fetches repositories from GitHub organizations
- Downloads ignore files (.gitignore, .eslintignore, etc.)
- Extracts patterns and generates word variations
- Sends results to Discord

### `db_wrapper.sh`
Shell wrapper script for Python database operations. Located in `lib/db_wrapper.sh`, it provides backward compatibility for shell scripts calling the Python database handler.

## Dependencies

All required Python packages are listed in `requirements.txt`:
- `psycopg2-binary>=2.9.0` - PostgreSQL database driver
- `requests>=2.31.0` - HTTP requests for GitHub API
- `discord.py>=2.4.0` - Discord bot functionality
- `fastapi==0.104.1` - Web API framework
- `uvicorn[standard]==0.24.0` - ASGI server
- `pydantic==2.5.0` - Data validation
- `pyyaml==6.0.1` - YAML configuration parsing
- `python-multipart==0.0.6` - Multipart form handling

## Usage

### Database Operations
```bash
# From shell scripts
python3 python/db_handler.py get-domains
python3 python/db_handler.py batch-insert-subdomains domain file.txt
python3 python/db_handler.py insert-js-file domain js_url
```

### GitHub Wordlist Generation
```bash
# From main.sh
./main.sh github-wordlist organization_name

# Direct Python execution
python3 python/github_wordlist.py organization_name
```

## Architecture

The Python scripts are designed to:
1. **Replace unreliable bash operations** with robust Python implementations
2. **Provide better error handling** and logging
3. **Improve performance** through efficient data processing
4. **Maintain compatibility** with existing shell script interfaces
5. **Enable Docker deployment** with proper dependency management

## Development

When adding new Python scripts:
1. Place them in this `python/` directory
2. Add required dependencies to `requirements.txt`
3. Update `main.sh` to call the new script
4. Update `Dockerfile` if executable permissions are needed
5. Document the script in this README
