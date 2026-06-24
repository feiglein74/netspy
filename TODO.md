# NetSpy TODO

> **Hinweis:** Dies ist die öffentliche TODO-Liste für GitHub.
> Interne/private TODOs gehören in `TODO.private.md` (wird nicht committed).

## High Priority

### 🎨 UI/UX Improvements
- [x] **Responsive Tabellen für Watch-Mode implementiert** ✅
  - Bubbletea UI unterstützt jetzt responsive Layouts
  - Dynamische Spaltenbreiten für alle drei Breakpoints
  - Wide-Layout enthält DeviceType und RTT Spalten
  - Thread-Safe Message-Pattern eliminiert DNS-Hostname-Flickering

### 🔴 Kritische Bugs

- [x] **Sentinel-File Mechanismus** ✅
  - `.netspy.running` Datei zeigt laufenden Prozess an
  - Beim Start: Warnung wenn letzter Lauf unsauber beendet wurde
  - Unterscheidet: Crash (mit Log) vs. Kill (ohne Log)

- [x] **Goroutine-Panics abfangen** (KRITISCH) ✅
  - Alle anwendungsrelevanten `go func()` abgesichert
  - **Worker-Goroutinen** (Scan-Pools): `defer crash.RecoverAndLog(...)` → Panic loggen + weitermachen
  - **Dauerschleifen** (`scanLoop`, `countdownLoop`): `crash.SafeGo()` → loggen + beenden
  - Abgedeckt: `pkg/watch/*`, `pkg/scanner`, `pkg/discovery`, `cmd/scan.go`
  - Bewusst ausgenommen: Signal-Handler in `main.go` / `crash/handler.go` (trivial, kein Panic-Risiko)

- [x] **MAC-Adresse wird um 1 Zeichen abgeschnitten** ✅
  - Fix: `TruncateMAC()` gibt MAC jetzt IMMER vollständig zurück
  - MAC-Adressen werden nie gekürzt (17 Zeichen, Kürzung sinnlos)

### 🔴 Cross-Platform Critical Issues (v0.2.0)
- [ ] **Spinner-Fix auf Windows testen** (nach macOS-Fix)
  - ANSI-Escape-Codes statt Carriage Return
  - Verifizieren dass Windows 10+ funktioniert

### 🧪 Testing & Quality
- [ ] **Code Quality Tools einrichten**
  - [ ] golangci-lint Konfiguration
  - [ ] go vet in Build-Prozess integrieren
  - [ ] go fmt Pre-Commit Hook
  - [ ] Code Coverage Reporting (Ziel: >80%)
- [ ] **Fix failing tests** (2 von 50 Tests schlagen fehl - deutlich verbessert! ✅)
  - [x] `GenerateIPsFromCIDR` - Behoben ✅
  - [x] `DetectDeviceType` - Behoben ✅
  - [x] `GetMACVendor` - Behoben ✅
  - [x] `ScanARPTable` - Behoben ✅
  - [x] `Scanner.Scan` - Behoben ✅
  - [ ] `IsLikelyGateway` - Gateway-Heuristik für /8 Netzwerke (.0.0.254)
  - [ ] `IsLikelyGateway` - Edge Case (IP außerhalb Netzwerk)
- [ ] **Tests für pkg/output/ hinzufügen** (aktuell keine Tests)
- [ ] **CI/CD Pipeline**
  - [ ] GitHub Actions Workflow für Tests
  - [ ] Automatische Releases
  - [ ] Multi-Platform Builds (Linux, macOS, Windows)
- [ ] Linux vollständig testen (ARP, Gateway, Watch-Mode)

### ⚙️ Configuration
- [ ] Add configuration file support (.netspy.yaml)

## Projektregeln-Compliance

> **Audit vom 2026-01-09**: Prüfung gegen `PROJECT_RULES.md`

### 📄 Dokumentation & Versionierung
- [x] **LICENSE-Datei erstellen** ✅ (MIT License)
- [x] **DESIGN-PRINCIPLES.md erstellen** ✅
  - Leitprinzipien dokumentiert (Vollständigkeit vor Kürze, Opt-in, Transparenz)
  - Verweis von CLAUDE.md hinzugefügt

### 🔧 .gitignore Konfiguration
- [x] **Claude Code Dateien ausschließen** ✅
  - `.claude/` hinzugefügt
  - `CLAUDE.md` hinzugefügt

### 📝 Git-Commit-Stil
- [ ] **Commit-Stil entscheiden**: Aktuell Mischstil (englische Präfixe `feat:`, `fix:` + deutsche Beschreibung)
  - Option A: Vollständig Deutsch ("Füge Feature hinzu")
  - Option B: Conventional Commits auf Englisch beibehalten
  - In PROJECT_RULES.md dokumentieren

### 🎯 Design-Prinzipien im Code (Kritisch!)

**Regel: "Vollständigkeit vor Kürze" & "Opt-in statt Opt-out"**

Alle folgenden automatischen Kürzungen verstoßen gegen die Projektregeln:

| Priorität | Datei | Zeile | Problem |
|-----------|-------|-------|---------|
| KRITISCH | `pkg/discovery/arp.go` | 287-289 | ARP-Refresh auf 50 IPs limitiert, **keine Transparenz** |
| KRITISCH | `pkg/discovery/http.go` | 159-160 | Banner automatisch auf 50 Zeichen gekürzt |
| KRITISCH | `pkg/discovery/http.go` | 184-185 | Page-Title automatisch auf 40 Zeichen gekürzt |
| HOCH | `pkg/output/table_responsive.go` | 45-46 | Hostname automatisch auf 13-25 Zeichen gekürzt |
| HOCH | `pkg/output/table_responsive.go` | 59-64 | MAC-Adresse "intelligent" gekürzt ohne Opt-in |
| MITTEL | `pkg/output/table_responsive.go` | 122-183 | DeviceType automatisch auf 16-23 Zeichen gekürzt |
| MITTEL | `pkg/output/table_responsive.go` | 191-204 | HTTP-Banner + Ports automatisch gekürzt |
| MITTEL | `pkg/discovery/vendor_learn.go` | 177-202 | Vendor-Name automatisch auf 25 Zeichen gekürzt |
| MITTEL | `pkg/watch/details.go` | 478-479 | Banner in Modal auf 30 Zeichen gekürzt |

**Lösungsansatz:**
- [x] Globales Flag `--full-output` implementiert ✅
  - `pkg/output/truncate.go` mit `Truncate()` und `TruncateMAC()` Funktionen
  - Alle Tabellen-Ausgaben nutzen jetzt die zentrale Truncation-Logik
- [x] Transparente Warnung bei Kürzung ✅ (zeigt "[+N]" für versteckte Zeichen)
- [ ] Konfigurationsoption für Truncation-Limits (optional, niedrige Priorität)
- [ ] ARP-Refresh-Limit transparent machen oder konfigurierbar

## Features
- [ ] Add export functionality for watch mode results
- [ ] Implement alert system for offline devices
- [ ] Add web UI for watch mode
- [ ] Add HTTP banner grabbing for web services
- [ ] Correct Redraw of the Table if it Grows, the Region Flaps is wrong

## Improvements
- [ ] Add IPv6 support
- [ ] Cross-platform testing (Linux, macOS)
- [ ] ICMP ping support for RTT measurement (requires admin rights)
- [ ] Improve mDNS/LLMNR reliability (some devices don't respond)

## Done ✅

### v0.1.2 (2025-11-16)
- [x] **Heuristische Gateway-Erkennung für entfernte Netzwerke**
  - Erkennt `.1` und `.254` als typische Gateways in Remote-Netzwerken
  - Funktioniert für /8, /16, /24 Netzwerke
  - `IsLikelyGateway()` kombiniert lokale + heuristische Erkennung
  - Gateway-Cache für Performance
  - `IsGateway` Feld in Host-Struktur
  - Tests für heuristische Erkennung
  - Gateway-Marker [G] funktioniert in allen Modi

### v0.1.1 (2025-11-15)
- [x] **Plattformspezifische Gateway-Erkennung** - Windows, macOS, Linux Support
  - `gateway_windows.go`: `route print` für Windows
  - `gateway_darwin.go`: `route -n get default` für macOS
  - `gateway_linux.go`: `ip route` / `route -n` für Linux
  - Gateway-Marker [G] direkt an IP angehängt (z.B. "192.168.179.1 [G]")
- [x] **Responsive Tabellen für Scan-Mode** - 3 Layouts (narrow/medium/wide)
  - Terminal < 100 cols: Kompakte Ansicht (IP, Hostname kurz, RTT, MAC kurz)
  - Terminal 100-139 cols: Standard-Ansicht (+ Device Type)
  - Terminal >= 140 cols: Vollständige Ansicht (alle Spalten)
- [x] **Unicode-Ellipsis (…)** statt drei Punkte (...) bei Kürzungen
- [x] **Spaltenausrichtung korrigiert** - Header stimmt mit Datenspalten überein
- [x] **Watch-Mode Tabellen-Rendering Fix** - clearLine() für saubere Updates
- [x] **Automatischer Fallback für fremde Subnets**
  - ARP-Modus erkennt lokale vs. remote Subnets
  - Hybrid-Modus fällt auf TCP-Scan zurück bei Remote-Netzen
  - Informative Meldungen über verwendete Strategie

### v0.1.0 (2025-11-15)
- [x] **README.md, CHANGELOG.md erstellt** - Vollständige Projekt-Dokumentation
- [x] **Versionierung implementiert** - SemVer mit --version Flag/Command
- [x] **Git-Tag v0.1.0** - Initial Release markiert
- [x] **Spinner-Fix für macOS** - ANSI-Escape-Codes für Cross-Platform Kompatibilität
- [x] **Cross-Platform Analyse** - Vollständige Code-Review mit 4 Berichten in `docs/`
- [x] **Ginkgo/Gomega BDD Testing Framework** eingerichtet (11 Test-Dateien, 42 Specs)
- [x] **Plattformspezifische Tests** (Windows, macOS, Linux) mit Build-Tags
- [x] **Deutsche Code-Kommentare** in allen Dateien
- [x] **Network Auto-Detection** für watch command
- [x] **Unified Scan Mode Flags** (--mode statt separate Flags)
- [x] Static table watch mode with live updates
- [x] Hybrid ARP+ping scanning
- [x] Background DNS lookups with NetBIOS fallback
- [x] NetBIOS name queries for Windows hosts (RFC 1002)
- [x] ANSI cursor control for in-place table updates
- [x] Graceful shutdown with Ctrl+C
- [x] Real-time uptime/downtime tracking
- [x] Column alignment fix for online/offline status
- [x] Expand MAC vendor database (976+ OUI entries)
- [x] Fix hostname flickering with resolution caching
- [x] RTT (response time) measurement in watch mode
- [x] Flapping detection for unstable devices
- [x] Locally-administered MAC address visual indicator
- [x] --quiet flag for clean piped output
- [x] Remove redundant output summary
- [x] Multi-port RTT fallback for devices without standard services
- [x] **Device type detection** (Smartphone/Privacy, Computer, IoT, Network Equipment, etc.)
- [x] **mDNS/Bonjour support** for Apple/IoT devices
- [x] **LLMNR support** for Windows hostname resolution
- [x] **OS detection** based on open ports (Windows, Linux, Server detection)
