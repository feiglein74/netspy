# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Claude Code Preferences

### Testing & Running
- **ALWAYS use `go run main.go` for testing**, NOT the compiled exe
- **Example**: `timeout 90 go run main.go watch 10.0.0.0/24 --interval 30s`

### Git Workflow
- **Auto-commit regularly** to track progress and prevent data loss
- Before `/compact` or when approaching session limits, ALWAYS commit
- Use descriptive commit messages following the project's commit style
- Check `git status` and `git diff` before committing

### Permissions
- All commonly used commands are pre-approved in `.claude/settings.local.json`
- Includes: go build, go run, go test, git commands, ipconfig, arp, etc.

## Project Overview

NetSpy is a modern network discovery tool written in Go that helps monitor network infrastructure. It provides real-time subnet scanning with multiple discovery methods (ICMP, ARP, hybrid) and beautiful CLI output.

## Development Commands

### Building
```bash
go build -o netspy
```

### Running
```bash
# Run the built binary
./netspy scan <network>

# Or run directly with go
go run main.go scan <network>
```

### Testing
```bash
go test ./...
```

### Dependencies
```bash
# Download dependencies
go mod download

# Update dependencies
go mod tidy
```

## Architecture

### Project Structure
- `main.go` - Entry point that calls cmd.Execute()
- `cmd/` - Cobra commands (root, scan, watch)
- `pkg/` - Core functionality packages
  - `scanner/` - Host scanning logic and Host type definition
  - `discovery/` - Network discovery methods (ARP, ping)
  - `output/` - Result formatting (table, JSON, CSV)

### Key Components

**Scanner Package (`pkg/scanner/scanner.go`)**
- Core `Host` struct represents discovered network hosts with IP, Hostname, MAC, Vendor, RTT, Ports, and Online status
- `Scanner` orchestrates concurrent host scanning with configurable workers and timeouts
- Supports three modes: fast (speed over accuracy), thorough (accuracy over speed), balanced (default)

**Discovery Package**
- `discovery/ping.go` - TCP-based ping using common ports (22, 80, 443) for reliable detection
  - `conservativePing()` - Tries reliable ports (22, 80, 443) to minimize false positives
  - `fastPing()` - Quick detection using only HTTP/HTTPS
  - `thoroughPing()` - Tries many common ports with validation
- `discovery/arp.go` - ARP table reading and parsing
  - Platform-specific ARP table parsing (Windows, Linux, macOS)
  - `RefreshARPTable()` populates ARP entries by triggering network traffic

**Scan Modes (`cmd/scan.go`)**
1. **Default**: Conservative TCP scan using reliable ports
2. **--fast**: Quick scan (may miss devices)
3. **--thorough**: Comprehensive scan (may have false positives)
4. **--arp**: ARP-based scan (most accurate for local networks)
5. **--hybrid**: ARP discovery + ping/port details (recommended for best accuracy + details)

Scan modes are mutually exclusive and validated in PreRun.

**Hybrid Scanning Workflow**
1. Populate ARP table by pinging all IPs in subnet (`populateARPTable()`)
2. Read system ARP table to find active hosts (`readCurrentARPTable()`)
3. Enhance each ARP-discovered host with RTT and port data (`enhanceHostsWithDetails()`)
4. Output combined results with MAC addresses and network details

### Configuration
- Uses Viper for configuration management
- Default config file: `$HOME/.netspy.yaml`
- Global flags: `--config`, `--verbose`, `--quiet`
- Scan flags: `-c` (concurrent), `-t` (timeout), `-f` (format), `-p` (ports)

### Concurrency
- Scanner uses semaphore pattern to limit concurrent scans
- Default workers: 40 (conservative), 100 (fast), 20 (thorough)
- Hybrid mode uses separate concurrency limits: 50 for ARP population, 20 for enhancement
- Progress tracking with atomic counters

### Platform Considerations
- ARP scanning is platform-specific (Windows uses `arp -a` with different output format than Linux/macOS)
- Windows ARP format: IP, MAC (aa-bb-cc-dd-ee-ff), type
- Linux/macOS ARP format: hostname (IP) at MAC [ether] on interface

## Watch Mode (`cmd/watch.go`)

**Current Implementation**: Static table with in-place updates using ANSI escape codes

### Key Features
- **Static Table**: ONE table that updates in place (no scrolling)
- **ANSI Cursor Control**: Uses `\033[A` (move up) and `\033[2K` (clear line)
- **Live Updates**: Uptime/downtime counters, DNS lookups, status changes all update in the table
- **Single Status Line**: Below table shows scan stats and countdown timer
- **Table Refresh**: Full redraw every 5 seconds to catch DNS updates

### Important Functions
- `redrawTable()` - Redraws entire table in place
- `moveCursorUp(n)` - Moves cursor up n lines
- `clearLine()` - Clears current line
- `showCountdownWithTableUpdates()` - Updates status line + periodic table refresh
- `performScanQuiet()` - Scans without output (results processed by runWatch)
- `performBackgroundDNSLookups()` - Async DNS resolution during countdown

### Design Principle
**NO new lines after initial table draw** - Everything updates in place for a clean, dashboard-like experience
