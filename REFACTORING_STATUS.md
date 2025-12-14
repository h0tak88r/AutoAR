# Main.sh to Go Refactoring - Status

## Overview
Converting `main.sh` to Go and unifying all Go code into a modular structure under `gomodules/`.

## Current Status: 🚧 Planning Phase

## Structure Plan

```
AutoAR/
├── main.go                    # New Go CLI (replaces main.sh)
├── go.mod                     # Root module
├── gomodules/                 # All Go modules
│   ├── gobot/                 # Discord bot + API (from go-bot/)
│   ├── github-wordlist/       # GitHub wordlist (from go-tools/, refactored to library)
│   └── wp-confusion/          # WP confusion (from go-tools/, refactored to library)
├── modules/                   # Bash modules (unchanged)
└── lib/                       # Bash libraries (unchanged)
```

## Implementation Steps

### ✅ Phase 1: Setup (DONE)
- [x] Create `gomodules/` directory structure
- [x] Copy `go-bot/` → `gomodules/gobot/`
- [x] Create root `go.mod`
- [x] Create migration plan document

### ⏳ Phase 2: Module Refactoring (IN PROGRESS)
- [ ] Refactor `github-wordlist` to library (export functions)
- [ ] Refactor `wp-confusion` to library (export functions)
- [ ] Update `gobot` module structure

### ⏳ Phase 3: Main CLI
- [ ] Create `main.go` with command dispatcher
- [ ] Implement bash module execution
- [ ] Implement Go module calls
- [ ] Add argument parsing

### ⏳ Phase 4: Integration
- [ ] Update Dockerfile
- [ ] Test all commands
- [ ] Update documentation

## Next Steps

1. Refactor `github-wordlist` to export `GenerateWordlist()` function
2. Refactor `wp-confusion` to export `ScanWPConfusion()` function
3. Create main CLI dispatcher
4. Test integration

## Notes

- Bash modules remain unchanged (they work well for tool orchestration)
- Go modules become libraries (not standalone binaries)
- Main CLI calls bash modules via `exec.Command` (like current go-bot does)
- Main CLI calls Go modules directly (no subprocess overhead)
