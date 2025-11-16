# Cross-Platform Kompatibilitäts-Notizen

## UI-Implementierungen

NetSpy bietet zwei UI-Modi für den `watch` Command:

### 1. **Bubbletea UI** (Standard, empfohlen) ✅
**Framework**: github.com/charmbracelet/bubbletea v1.3.10
**Aktivierung**: `netspy watch <network> --ui bubbletea` (default)

**Features**:
- ✅ Scrollbares Device-Liste (↑/↓, PgUp/PgDn, Home/End)
- ✅ Live-Suche (/ zum Aktivieren)
- ✅ Responsive Layout mit Auto-Resize
- ✅ Countdown-Timer mit Live-Updates
- ✅ Mouse-Support (optional)
- ✅ Alt-Screen-Buffer (sauberes Exit)

**Cross-Platform Status**:
| Plattform | Terminal | Status | Getestet |
|-----------|----------|--------|----------|
| Windows | Windows Terminal | ✅ **FUNKTIONIERT** | ✅ 16.11.2025 |
| Windows | PowerShell | ✅ Sollte funktionieren | ❓ Zu testen |
| Windows | cmd.exe | ✅ Sollte funktionieren | ❓ Zu testen |
| Windows | Git Bash | ⚠️ Unklar (bekannte Issues) | ❓ Zu testen |
| macOS | Terminal.app / iTerm2 | ✅ Sollte funktionieren | ❓ Zu testen |
| Linux | gnome-terminal / xterm | ✅ Sollte funktionieren | ❓ Zu testen |

**Bekannte Bubbletea Windows-Fixes** (bereits in v1.3.10):
- ✅ Flickering Issue #1019 - GEFIXT
- ✅ Windows Console API Support verbessert
- ✅ Key Disambiguation für Windows

### 2. **Legacy ANSI UI** (Fallback)
**Aktivierung**: `netspy watch <network> --ui legacy`

**Hinweis**: Die Legacy-Implementierung hat bekannte Probleme mit Git Bash (siehe unten).

## Terminal-Handling per Plattform (Legacy UI)

### macOS (watch_unix.go)
**Status**: ✅ Sollte funktionieren
- SIGWINCH für Resize-Detection (native Unix)
- stty für Raw-Mode (native Unix)
- ANSI Escape Codes (nativ unterstützt)
- **Risiko**: KEINE - alles standard Unix

### Linux (watch_unix.go)
**Status**: ✅ Sollte funktionieren
- Identisch zu macOS (shared watch_unix.go)
- ANSI Escape Codes (nativ unterstützt)
- **Risiko**: KEINE - standard Unix

### Windows (watch_windows.go)
**Status**: ⚠️ KOMPLEX - mehrere Terminal-Typen

#### Native Windows Terminals (cmd.exe, PowerShell, Windows Terminal)
- ✅ VT Processing via syscalls funktioniert
- ✅ ANSI Escape Codes nach VT-Aktivierung
- ✅ Resize-Polling (500ms) funktioniert
- **Risiko**: NIEDRIG

#### Git Bash / MSYS2 / MinGW
- ❌ Windows Console API funktioniert NICHT (handle invalid)
- ❓ ANSI Escape Codes SOLLTEN funktionieren (POSIX-Emulation)
- ⚠️ AKTUELLES PROBLEM: [2J[H wird als Text ausgegeben
- **Risiko**: HOCH - Claude Code nutzt Git Bash

## Aktuelles Problem

### Symptom
```bash
# In Git Bash:
[2J[H╔════════════╗
     ^--- ANSI Code wird sichtbar statt interpretiert
```

### Root Cause
1. Git Bash ist POSIX-Emulation über Windows
2. Windows Console API (kernel32.dll) greift nicht
3. ANSI-Interpretation funktioniert anders als natives Terminal

### Mögliche Lösungen

#### Option A: Terminal-Typ-Detection
```go
// Prüfe ob wir in Git Bash laufen
if os.Getenv("MSYSTEM") != "" {
    // Git Bash detected - anderer Ansatz
}
```

#### Option B: Universelle ANSI-Library
```go
import "golang.org/x/term"
// Cross-platform ANSI ohne syscalls
```

#### Option C: Hybrid-Ansatz
```go
// 1. Versuche Windows VT Processing
// 2. Falls fehlschlägt: gehe davon aus dass ANSI nativ funktioniert
// 3. Falls beides nicht klappt: Fallback zu non-ANSI Mode
```

## Testing-Matrix

| Plattform | Terminal | ANSI | Resize | Getestet |
|-----------|----------|------|--------|----------|
| macOS | Terminal.app | ✅ Native | ✅ SIGWINCH | ❓ Nein |
| macOS | iTerm2 | ✅ Native | ✅ SIGWINCH | ❓ Nein |
| Linux | gnome-terminal | ✅ Native | ✅ SIGWINCH | ❓ Nein |
| Linux | xterm | ✅ Native | ✅ SIGWINCH | ❓ Nein |
| Windows | cmd.exe | ⚠️ VT needed | ⚠️ Polling | ❓ Nein |
| Windows | PowerShell | ⚠️ VT needed | ⚠️ Polling | ❓ Nein |
| Windows | Windows Terminal | ✅ Modern | ⚠️ Polling | ❓ Nein |
| Windows | Git Bash | ❌ BROKEN | ⚠️ Polling | ✅ Ja - FEHLER |

## Empfohlene Action Items

1. **Sofort**: Testen in nativem Windows Terminal
2. **Kurzfristig**: Git Bash Detection + Workaround
3. **Mittelfristig**: macOS/Linux Testing
4. **Langfristig**: CI/CD Pipeline mit allen Plattformen
