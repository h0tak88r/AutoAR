# Main.sh to Go Migration Plan

## Architecture Overview

```
AutoAR/
├── main.go                    # New Go CLI entry point (replaces main.sh)
├── go.mod                     # Main module
├── gomodules/                 # Go modules directory
│   ├── gobot/                 # Discord bot + API server (moved from go-bot/)
│   │   ├── bot.go
│   │   ├── api.go
│   │   ├── commands*.go
│   │   └── react2shell.go
│   ├── github-wordlist/       # GitHub wordlist generator (moved from go-tools/)
│   │   └── wordlist.go        # Exported functions, not main()
│   └── wp-confusion/          # WordPress confusion scanner (moved from go-tools/)
│       └── confusion.go       # Exported functions, not main()
├── modules/                   # Bash modules (unchanged)
│   └── *.sh
└── lib/                       # Bash libraries (unchanged)
    └── *.sh
```

## Benefits

1. **Single Entry Point**: One Go binary instead of bash script
2. **Unified Go Modules**: All Go code in one place, shared as modules
3. **Better Performance**: Go CLI is faster than bash for argument parsing/dispatching
4. **Type Safety**: Go's type system for command handling
5. **Still Uses Bash**: Bash modules remain for tool orchestration (best of both worlds)

## Implementation Steps

### Phase 1: Module Structure
1. ✅ Create `gomodules/` directory
2. Move `go-bot/` → `gomodules/gobot/` (as module, not binary)
3. Move `go-tools/github-wordlist/` → `gomodules/github-wordlist/` (refactor to library)
4. Move `go-tools/wp-confusion/` → `gomodules/wp-confusion/` (refactor to library)

### Phase 2: Main CLI
1. Create `main.go` at root with command dispatcher
2. Import modules: `github.com/h0tak88r/AutoAR/gomodules/gobot`
3. Import modules: `github.com/h0tak88r/AutoAR/gomodules/github-wordlist`
4. Import modules: `github.com/h0tak88r/AutoAR/gomodules/wp-confusion`
5. Implement command routing (replaces main.sh case statement)

### Phase 3: Module Refactoring
1. **gobot**: Keep as-is, but export functions for CLI use
2. **github-wordlist**: Convert `main()` to exported function `GenerateWordlist(org, token string)`
3. **wp-confusion**: Convert `main()` to exported function `ScanWPConfusion(args)`

### Phase 4: Integration
1. CLI calls bash modules via `exec.Command` (like current go-bot does)
2. CLI calls Go modules directly (no subprocess for Go tools)
3. Update Dockerfile to build single `autoar` binary

## Command Routing

```go
// main.go
func main() {
    if len(os.Args) < 2 {
        printUsage()
        os.Exit(1)
    }
    
    cmd := os.Args[1]
    args := os.Args[2:]
    
    switch cmd {
    case "subdomains", "livehosts", "cnames", ...:
        // Call bash module
        runBashModule(cmd, args)
    case "github-wordlist":
        // Call Go module directly
        githubwordlist.GenerateWordlist(args...)
    case "wp-depconf":
        // Call Go module directly
        wpconfusion.Scan(args...)
    case "bot":
        // Start Discord bot
        gobot.StartBot()
    case "api":
        // Start API server
        gobot.StartAPI()
    }
}
```

## Module Exports

### gomodules/github-wordlist/wordlist.go
```go
package githubwordlist

// GenerateWordlist generates wordlist from GitHub org
func GenerateWordlist(org, token string) error {
    // ... existing logic
}
```

### gomodules/wp-confusion/confusion.go
```go
package wpconfusion

// ScanWPConfusion scans for WordPress plugin confusion
func ScanWPConfusion(args []string) error {
    // ... existing logic
}
```

## Backward Compatibility

- Keep `main.sh` as wrapper that calls Go binary (for transition period)
- Or make `main.sh` symlink to Go binary
- All existing commands work the same way
