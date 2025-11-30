# tview Migration Plan für NetSpy Watch-Modus

**Datum**: 2025-11-30
**Status**: Phase 1 - Planung
**Ziel**: Migration des Watch-Modus von ANSI-Escape-Codes zu tview TUI-Framework

---

## 1. Übersicht

### 1.1 Aktueller Stand

Der Watch-Modus hat aktuell **zwei Implementierungen**:

| UI | Dateien | Aktivierung | Status |
|----|---------|-------------|--------|
| Legacy (ANSI) | `pkg/watch/display.go`, `pkg/watch/watcher.go` | Standard | Produktiv |
| Bubbletea | `cmd/watch_bubbletea.go` | `--ui=bubbletea` | Experimentell |

**Legacy-Probleme:**
- Manuelle ANSI-Escape-Codes (`\033[A`, `\033[2K`, etc.)
- Plattform-spezifische Terminal-Quirks
- Kein echtes Scrolling (nur Paging)
- Flicker bei schnellen Updates
- Komplexe Cursor-Positionierung

### 1.2 Ziel-Architektur mit tview

```
┌─────────────────────────────────────────────────────────────┐
│  tview.Application                                          │
│  ├── tview.Flex (Haupt-Layout)                              │
│  │   ├── tview.TextView (Header: NetSpy - Network Monitor)  │
│  │   ├── tview.TextView (Info: Network, Mode, Stats)        │
│  │   ├── tview.Table (Host-Liste mit Scrolling)             │
│  │   └── tview.TextView (Footer: Status, Hotkeys)           │
│  └── tview.Modal (Help Overlay bei '?')                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Vorteile von tview

| Feature | Legacy (ANSI) | tview |
|---------|---------------|-------|
| Terminal-Kompatibilität | Manuell testen | tcell handled alles |
| Scrolling | Paging (n/p Tasten) | Natives Table-Scrolling |
| Maus-Support | Nicht vorhanden | Eingebaut |
| Resize-Handling | SIGWINCH + manuell | Automatisch |
| Farben | Manuell (fatih/color) | theme-fähig |
| Focus-Management | Nicht vorhanden | Eingebaut |
| Unicode/Wide-Chars | Manuell (runewidth) | Automatisch |

---

## 3. Abhängigkeiten

### 3.1 Neue Dependencies

```bash
go get github.com/rivo/tview
go get github.com/gdamore/tcell/v2
```

### 3.2 Zu entfernende Dependencies (nach Migration)

- `github.com/fatih/color` - Nur noch für Nicht-TUI-Output (scan command)
- `github.com/mattn/go-runewidth` - Von tcell übernommen

---

## 4. Migrations-Phasen

### Phase 1: Planung ✅
- [x] Aktuelle Architektur analysieren
- [x] tview-Konzept erstellen
- [x] Migrationsplan dokumentieren

### Phase 2: Prototyp
- [ ] `pkg/watch/tview.go` erstellen
- [ ] Basis-Layout (Flex + Table)
- [ ] Daten-Binding von DeviceState
- [ ] Keyboard-Navigation
- [ ] `--ui=tview` Flag hinzufügen

### Phase 3: Feature-Parität
- [ ] Alle Spalten implementieren (IP, Hostname, MAC, Vendor, etc.)
- [ ] Sortierung (i, h, m, v, d, r, t, u, f Tasten)
- [ ] Farbschema (Online=Grün, Offline=Rot, Neu=Grün, Flaps=Gelb)
- [ ] Help-Overlay ('?' Taste)
- [ ] Screen-Copy ('c' Taste)

### Phase 4: Testing & Polish
- [ ] Windows-Test
- [ ] macOS-Test
- [ ] Linux-Test
- [ ] Performance-Vergleich mit Legacy
- [ ] Edge-Cases (sehr kleine/große Terminals)

### Phase 5: Finale Umstellung
- [ ] tview als Standard setzen
- [ ] Legacy-Code als Fallback behalten oder entfernen
- [ ] Dokumentation aktualisieren

---

## 5. Datei-Struktur (Ziel)

```
pkg/watch/
├── state.go          # DeviceState, SortState (unverändert)
├── scanner.go        # PerformScanQuiet, etc. (unverändert)
├── dns.go            # DNS-Lookups (unverändert)
├── utils.go          # Helper-Funktionen (unverändert)
├── display.go        # Legacy ANSI-Display (deprecated)
├── watcher.go        # Legacy Watch-Loop (deprecated)
└── tview.go          # NEU: tview-basierte UI

cmd/
├── watch.go          # Haupt-Command (UI-Auswahl)
├── watch_tview.go    # NEU: tview Entry-Point
├── watch_bubbletea.go # Bubbletea (optional behalten)
└── watch_*.go        # Platform-spezifisch (Terminal-Setup)
```

---

## 6. API-Design

### 6.1 Haupt-Struct

```go
// WatchApp ist die tview-basierte Watch-Anwendung
type WatchApp struct {
    app          *tview.Application
    flex         *tview.Flex
    headerView   *tview.TextView
    infoView     *tview.TextView
    table        *tview.Table
    footerView   *tview.TextView
    helpModal    *tview.Modal

    // State
    deviceStates map[string]*DeviceState
    sortState    *SortState
    network      string
    interval     time.Duration
    mode         string
    scanCount    int

    // Channels
    updateChan   chan UpdateMsg
    stopChan     chan struct{}
}
```

### 6.2 Update-Messages

```go
type UpdateMsg struct {
    Type      UpdateType
    Hosts     []scanner.Host      // für ScanComplete
    DNSResult map[string]string   // für DNSComplete
}

type UpdateType int
const (
    ScanComplete UpdateType = iota
    DNSComplete
    Tick
)
```

### 6.3 Haupt-Funktionen

```go
// NewWatchApp erstellt eine neue tview Watch-Anwendung
func NewWatchApp(network, mode string, interval time.Duration) *WatchApp

// Run startet die Anwendung (blockiert)
func (w *WatchApp) Run() error

// Stop beendet die Anwendung graceful
func (w *WatchApp) Stop()

// updateTable aktualisiert die Host-Tabelle
func (w *WatchApp) updateTable()

// startScanLoop startet den Scan-Zyklus
func (w *WatchApp) startScanLoop(ctx context.Context)
```

---

## 7. Mapping: Legacy → tview

| Legacy-Funktion | tview-Äquivalent |
|-----------------|------------------|
| `DrawBtopLayout()` | `WatchApp.updateTable()` |
| `RedrawTable()` | `table.Clear()` + `table.SetCell()` |
| `PrintTableRow()` | `table.SetCell(row, col, cell)` |
| `ShowHelpOverlay()` | `app.SetRoot(helpModal, true)` |
| `MoveCursorUp()` | Nicht nötig (tview managed) |
| `ClearLine()` | Nicht nötig (tview managed) |
| ANSI-Farben | `tcell.ColorGreen`, etc. |

---

## 8. Keyboard-Mapping

| Taste | Aktion | tview-Implementation |
|-------|--------|----------------------|
| `q`, `Ctrl+C` | Beenden | `app.Stop()` |
| `?` | Help | `app.SetRoot(helpModal, true)` |
| `c` | Copy | `clipboard.WriteAll(...)` |
| `↑`/`k` | Scroll hoch | `table.Select(row-1, col)` |
| `↓`/`j` | Scroll runter | `table.Select(row+1, col)` |
| `PgUp` | Seite hoch | Custom handler |
| `PgDn` | Seite runter | Custom handler |
| `i` | Sort by IP | `sortState.Toggle(SortByIP)` |
| `h` | Sort by Host | `sortState.Toggle(SortByHostname)` |
| etc. | ... | ... |

---

## 9. Farb-Schema

```go
var (
    colorOnline       = tcell.ColorGreen
    colorOffline      = tcell.ColorRed
    colorNew          = tcell.ColorLime
    colorFlapping     = tcell.ColorYellow
    colorLocalMAC     = tcell.ColorYellow
    colorHeader       = tcell.ColorCyan
    colorBorder       = tcell.ColorCyan
    colorZebraLight   = tcell.ColorWhite
    colorZebraDark    = tcell.Color240  // Grau
)
```

---

## 10. Risiken & Mitigationen

| Risiko | Wahrscheinlichkeit | Mitigation |
|--------|-------------------|------------|
| Performance-Regression | Mittel | Benchmark vor/nach |
| Feature-Lücken | Niedrig | Checkliste für Parität |
| Windows-Terminal-Issues | Mittel | Früh testen |
| Breaking Change für User | Niedrig | `--ui=legacy` Fallback |

---

## 11. Zeitplan (geschätzt)

| Phase | Aufwand | Beschreibung |
|-------|---------|--------------|
| Phase 1 | ✅ | Planung abgeschlossen |
| Phase 2 | 2-3h | Basis-Prototyp |
| Phase 3 | 3-4h | Feature-Parität |
| Phase 4 | 1-2h | Testing |
| Phase 5 | 30min | Finale Umstellung |

**Gesamt**: ~7-10 Stunden

---

## 12. Nächste Schritte

1. **Prototyp starten**: `pkg/watch/tview.go` mit Basis-Layout
2. **Flag hinzufügen**: `--ui=tview` in `cmd/watch.go`
3. **Iterativ entwickeln**: Feature für Feature hinzufügen
4. **Parallel testen**: Legacy und tview vergleichen

---

---

## 13. Nutzung (aktuell)

### tview-Modus starten

```bash
# Mit tview UI
netspy watch 10.0.0.0/24 --ui=tview

# Mit kürzerem Interval
netspy watch 192.168.1.0/24 --ui=tview --interval 30s

# Mit spezifischem Modus
netspy watch 10.0.0.0/24 --ui=tview --mode arp
```

### Verfügbare UI-Modi

| Modus | Flag | Beschreibung |
|-------|------|--------------|
| Legacy | `--ui=legacy` (default) | ANSI-basiert, Paging |
| tview | `--ui=tview` | TUI mit echtem Scrolling |
| Bubbletea | `--ui=bubbletea` | Elm-Style TUI |

### Getestete Features (tview)

- [x] Maus-Scrolling
- [x] Keyboard-Navigation (↑/↓)
- [x] Sortierung (i/h/m/v/d/r/u/f)
- [x] Help-Overlay (?)
- [x] Beenden (q/ESC)
- [x] Live-Scan mit Countdown
- [x] Farben (Online/Offline/Neu/Flaps)
- [x] Responsive Layout

---

## Changelog

| Datum | Version | Änderung |
|-------|---------|----------|
| 2025-11-30 | 0.1 | Initialer Plan erstellt |
| 2025-11-30 | 0.2 | Prototyp implementiert und getestet |
