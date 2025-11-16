# Cross-Platform Kompatibilitäts-Notizen

## Terminal-Handling per Plattform

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
