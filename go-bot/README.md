# AutoAR Discord Bot - Go Migration

This directory contains the Go implementation of the AutoAR Discord bot using [discordgo](https://github.com/bwmarrin/discordgo).

## Benefits

- **Performance**: Compiled binary, faster execution
- **Memory**: Lower memory footprint than Python
- **Concurrency**: Native goroutines for better parallel processing
- **Consistency**: Single language stack (Go for both bot and next88 scanner)
- **Docker**: Smaller image size (no Python runtime needed)

## Migration Status

🚧 **In Progress** - Proof of concept phase

## Current Implementation

- Python: `discord_bot.py` (3400 lines, 54 commands)
- Go: `go-bot/` (migration in progress)

## Structure

```
go-bot/
├── main.go           # Bot entry point
├── bot.go            # Bot initialization and setup
├── commands/         # Discord slash commands
│   ├── scan.go       # Scan commands (subdomains, livehosts, etc.)
│   ├── react2shell.go # React2Shell specific commands
│   └── ...
├── handlers/         # Event handlers
├── utils/            # Utility functions
│   ├── config.go     # Configuration management
│   ├── db.go         # Database integration
│   └── webhook.go    # Discord webhook helpers
└── README.md         # This file
```

## Dependencies

- `github.com/bwmarrin/discordgo` - Discord API bindings
- `github.com/lib/pq` - PostgreSQL driver (if using DB)
- Standard Go libraries for subprocess, file handling, etc.

## Migration Plan

1. ✅ Setup project structure
2. ⏳ Port core bot initialization
3. ⏳ Port configuration management
4. ⏳ Port React2Shell commands (priority - most used)
5. ⏳ Port other scan commands
6. ⏳ Port database integration
7. ⏳ Port webhook/file sending
8. ⏳ Testing and validation
9. ⏳ Docker integration
10. ⏳ Full migration

## Running

```bash
cd go-bot
go mod init autoar-bot
go get github.com/bwmarrin/discordgo
go run main.go
```

## Docker Integration

The Go bot will replace the Python bot in the Dockerfile, reducing image size and improving performance.
