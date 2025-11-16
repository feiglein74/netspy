# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Added
- **Bubbletea UI für watch-Modus** - Moderne Terminal-UI mit Charmbracelet Bubbletea Framework
  - Scrollbares Device-Liste (↑/↓, PgUp/PgDn, Home/End) für große Netzwerke (>20 Devices)
  - Live-Suche mit `/` zum Filtern nach IP, Hostname, MAC oder Vendor
  - Responsive Layout mit automatischem Resize
  - Live Countdown-Timer mit sekündlichen Updates
  - Mouse-Support (optional)
  - Alt-Screen-Buffer für sauberes Exit ohne Terminal-Scrollen
- `--ui` Flag für `watch` Command: `bubbletea` (default) oder `legacy`
- Cross-Platform Keyboard-Handling durch Bubbletea (Windows, macOS, Linux)

### Changed
- Bubbletea ist jetzt der Standard-UI-Modus für `watch`
- Legacy ANSI-UI verfügbar via `--ui legacy`

### Fixed
- Windows Terminal Compatibility verbessert durch Bubbletea Framework
- Flickering Issues auf Windows durch Bubbletea v1.3.10 Fixes
- Scrolling funktioniert jetzt auch bei großen Netzwerken (254+ Devices)

- Ginkgo/Gomega BDD Testing Framework (42 Specs in 11 Test-Dateien)
- Plattformspezifische Tests (Windows, macOS, Linux) mit Build-Tags
- Netzwerk-Auto-Detection für Watch-Command
- Unified Scan Mode Flags (--mode statt separate Flags)

### Changed (cont.)
- Deutsche Code-Kommentare in allen Dateien
- CLAUDE.md auf Deutsch übersetzt
- Ausführungspräferenz auf kompilierte Binary geändert

### Fixed (cont.)
- Spinner-Ausgabe auf macOS korrigiert (ANSI-Escape-Codes statt Carriage Return)

### Dependencies
- Added `github.com/charmbracelet/bubbletea` v1.3.10
- Added `github.com/charmbracelet/lipgloss` v1.1.0

## [0.1.0] - Initial Release

### Features

#### Kern-Funktionalität
- **Hybrid Network Discovery** - Kombination aus ARP + TCP-Ping für höchste Genauigkeit
- **Statischer Watch-Modus** - Live-Updates ohne Scrollen mittels ANSI-Cursor-Steuerung
- **Mehrere Scan-Modi** - Conservative, Fast, Thorough, ARP, Hybrid
- **Plattformübergreifend** - Windows, macOS, Linux Support mit plattformspezifischem ARP-Parsing

#### Discovery & Detection
- **Intelligente Gerätetyp-Erkennung** - Heuristische Analyse für Router, Smartphones, IoT, etc.
- **Multi-Protokoll Hostname-Auflösung**:
  - DNS (Standard)
  - mDNS/Bonjour (Apple/IoT-Geräte)
  - NetBIOS (Windows-Hosts, RFC 1002)
  - LLMNR (Windows Link-Local)
- **MAC-Vendor-Datenbank** - 976+ OUI-Einträge für Hersteller-Identifikation
- **Gateway-Erkennung** - Automatische Markierung des Default-Gateways (G-Indikator)
- **HTTP Banner Grabbing** - Web-Server-Identifikation

#### Monitoring & Tracking
- **Uptime/Downtime-Tracking** - Kontinuierliche Verfügbarkeit über Zeit
- **Flapping-Detection** - Zähler für instabile Netzwerkverbindungen
- **RTT-Messung** - Response-Time mit Multi-Port-Fallback (80, 443, 22, 445, 135)
- **Reachability-Checks** - Periodische Erreichbarkeitsprüfung während Countdown
- **Background DNS-Lookups** - Asynchrone Hostname-Auflösung

#### UI/UX
- **Statische Tabellen-Ansicht** - In-Place-Updates ohne Scrollen
- **Farbcodierung** - Visuelle Indikatoren für:
  - Online/Offline-Status (🟢/🔴)
  - Lokal administrierte MAC-Adressen (gelb)
  - Flapping-Warnungen (gelb)
- **ANSI-Cursor-Steuerung** - Flicker-freie Table-Redraws
- **Graceful Shutdown** - Sauberer Exit mit Ctrl+C

#### Output & Formate
- **Mehrere Ausgabe-Formate** - Table (Standard), JSON, CSV
- **Quiet-Flag** - Reduzierte Ausgabe für Scripting/Piping
- **Zeitstempel** - First Seen, Last Seen, Status-Änderungen

### Technische Details

#### Architektur
- **Cobra CLI-Framework** - Strukturierte Command-Hierarchie
- **Viper Configuration** - Flexible Config-Datei-Support
- **Concurrent Scanning** - Worker-Pool mit Semaphore-Pattern
- **Plattformspezifisches ARP-Parsing** - Separate Implementierungen für Windows/macOS/Linux

#### Performance
- **Konfigurierbare Concurrency** - Standard: 40 (conservative), 100 (fast), 20 (thorough)
- **Hybrid-Modus Optimierung** - Separate Limits für ARP-Population (50) und Enhancement (20)
- **Atomare Counter** - Thread-safe Fortschritts-Tracking
- **Timeout-Management** - Konfigurierbare Timeouts pro Host

#### Code-Qualität
- **BDD Testing** - Ginkgo + Gomega Test-Framework
- **Plattformspezifische Tests** - Build-Tags für OS-spezifische Features
- **Deutsche Dokumentation** - Kommentare und Docs auf Deutsch
- **Strukturierte Architektur** - Separation of Concerns (cmd/pkg)

### Bekannte Probleme

- 16 von 42 Tests schlagen aktuell fehl (siehe TODO.md):
  - `GenerateIPsFromCIDR` - IP-Range-Logik
  - `DetectDeviceType` - Leere String-Rückgaben
  - `GetMACVendor` - MAC-Format-Handling
  - `ScanARPTable` - Nil statt leeres Array
  - `Scanner.Scan` - Localhost-Detection
- Tabellen-Redraw bei wachsender Tabelle (Flaps-Spalte)
- Einige IoT-Geräte antworten nicht auf mDNS/LLMNR
- Kein IPv6-Support
- Kein ICMP-Ping (erfordert Admin-Rechte)

### Abhängigkeiten

- Go 1.21+
- github.com/spf13/cobra
- github.com/spf13/viper
- github.com/fatih/color
- github.com/onsi/ginkgo/v2
- github.com/onsi/gomega

---

## Versionierung

Dieses Projekt verwendet [Semantic Versioning](https://semver.org/lang/de/):
- **MAJOR** - Inkompatible API-Änderungen
- **MINOR** - Neue Funktionen (rückwärtskompatibel)
- **PATCH** - Bugfixes (rückwärtskompatibel)

[Unreleased]: https://github.com/yourusername/netspy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/netspy/releases/tag/v0.1.0
