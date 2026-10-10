# NetSpy

[![License](https://img.shields.io/github/license/feiglein74/netspy)](LICENSE) ![Go](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-555) [![Release](https://img.shields.io/github/v/release/feiglein74/netspy)](https://github.com/feiglein74/netspy/releases/latest)

**Network scanner and live LAN monitor for the terminal.** NetSpy finds every device in a subnet (ARP, ICMP or TCP scan), resolves hostnames via DNS, mDNS/Bonjour, NetBIOS and LLMNR, looks up the MAC vendor and guesses the device type — then keeps watching: a live TUI dashboard tracks uptime, outages and flapping devices. Single binary for Windows, Linux and macOS, no install, no admin rights needed.

![NetSpy watch mode: live device table with vendor, device type, RTT, uptime and flap counter](docs/demo.gif)

<sub>Demo data from the documentation range 192.0.2.0/24 — recorded with [`docs/demo.tape`](docs/demo.tape).</sub>

## Quickstart

Download the ZIP for your platform from the [latest release](https://github.com/feiglein74/netspy/releases/latest) (Windows, Linux, macOS — amd64 and arm64), unpack it, then:

```bash
# Live monitoring dashboard (auto-detects your networks if no CIDR is given)
netspy watch 192.168.1.0/24

# One-shot scan of a subnet, ARP + port details
netspy scan 192.168.1.0/24 --mode hybrid

# Remote / routed network: use ICMP instead of ARP
netspy watch 10.10.1.0/24 --mode icmp --interval 30s
```

On Linux/macOS, e.g.:

```bash
curl -LO https://github.com/feiglein74/netspy/releases/latest/download/netspy-linux-amd64.zip
unzip netspy-linux-amd64.zip && chmod +x netspy-linux-amd64
./netspy-linux-amd64 watch 192.168.1.0/24
```

Build from source (Go 1.24+): `git clone https://github.com/feiglein74/netspy && cd netspy && go build -o netspy`

## What it does

- **Discovery:** ARP, ICMP (system `ping`, no raw sockets), TCP ping, or hybrid (ARP + ports/RTT)
- **Names:** reverse DNS, mDNS/Bonjour, NetBIOS, LLMNR — resolved in the background
- **MAC vendor lookup:** offline longest-prefix match against the IEEE MA-L/MA-M/MA-S registries (cached in `~/.netspy/registry`; only the full public lists are downloaded — for prefixes still unknown, just the OUI is looked up at macvendors.com, never a full MAC)
- **Device type detection:** router, server, printer, computer, smartphone, IoT, … plus gateway marker and randomized/private MAC detection
- **Watch mode (TUI):** live table with uptime, downtime, flap counter, RTT; sort by any column, filter (`/`, e.g. `vendor=apple`), host details with on-demand port scan, change network and scan mode at runtime
- **Scan mode:** table, JSON or CSV output for scripting

Keys in watch mode: `/` filter · `c` clear filter · `i h m v d r u f` sort · `Enter` host details · `Tab` edit network/mode · `?` help · `q` quit

> Detailed documentation below is in German.

---

## Überblick (Deutsch)

Modernes Netzwerk-Discovery-Tool in Go zur Überwachung von Netzwerkinfrastruktur mit Echtzeit-Scanning und schöner CLI-Ausgabe.

## Features

- **Echtzeit-Netzwerk-Überwachung** - Kontinuierliches Monitoring mit Live-Updates
- **Terminal-UI (tview)** - Live-Tabelle mit Sortierung, Filter, Host-Details und Port-Scan
- **Mehrere Discovery-Methoden** - ARP, ICMP, TCP, Hybrid-Scanning
- **Intelligente Geräte-Erkennung** - Automatische Identifikation von Gerätetypen (Router, Smartphone, IoT, etc.)
- **Hostname-Auflösung** - DNS, mDNS/Bonjour, NetBIOS, LLMNR Support
- **MAC-Vendor-Erkennung** - Offline-Lookup über die IEEE-Register (MA-L/MA-M/MA-S, Longest-Prefix-Match), Cache in `~/.netspy/registry`
- **Gateway-Erkennung** - Automatische Markierung des Default-Gateways
- **Uptime/Downtime-Tracking** - Verfolgung von Geräteverfügbarkeit über Zeit
- **Flapping-Detection** - Erkennung instabiler Netzwerkverbindungen
- **RTT-Messung** - Response-Time-Tracking für Performance-Monitoring
- **Plattformübergreifend** - Windows, macOS, Linux Support

## Installation

### Release herunterladen (empfohlen)

Fertige Binaries für Windows, Linux und macOS (jeweils amd64 und arm64) gibt es unter
[Releases](https://github.com/feiglein74/netspy/releases/latest). ZIP entpacken und starten – keine Installation nötig.

### Voraussetzungen

- Für den Build aus den Quellen: Go 1.24 oder höher
- Terminal-Fenster: Mindestens 80 Spalten x 15 Zeilen für Watch-Modus (VT100 Standard)

### Build

```bash
go build -o netspy
```

### Dependencies

```bash
go mod download
```

## Usage

### Scan-Modus

Einmaliger Netzwerk-Scan:

```bash
# Einfacher Scan mit Standard-Einstellungen
netspy scan 192.168.1.0/24

# Schneller Scan (kann Geräte übersehen)
netspy scan 192.168.1.0/24 --mode fast

# Gründlicher Scan (kann False Positives haben)
netspy scan 192.168.1.0/24 --mode thorough

# ARP-basierter Scan (am genauesten für lokale Netzwerke)
netspy scan 192.168.1.0/24 --mode arp

# Hybrid-Modus (empfohlen - ARP + Ping/Port-Details)
netspy scan 192.168.1.0/24 --mode hybrid

# ICMP-Modus (für entfernte/geroutete Netze, nutzt System-ping)
netspy scan 10.10.1.0/24 --mode icmp

# Spezifische Ports scannen
netspy scan 192.168.1.0/24 -p 80,443,8080

# Output-Format ändern
netspy scan 192.168.1.0/24 -f json
netspy scan 192.168.1.0/24 -f csv
```

### Watch-Modus

Kontinuierliche Netzwerk-Überwachung mit Live-Updates:

```bash
# Standard Watch mit 60s Intervall
netspy watch 192.168.1.0/24

# Kürzeres Intervall (30 Sekunden)
netspy watch 192.168.1.0/24 --interval 30s

# Mit spezifischem Scan-Modus
netspy watch 192.168.1.0/24 --mode hybrid --interval 30s

# Entferntes Netz per ICMP überwachen
netspy watch 10.10.1.0/24 --mode icmp

# Demo-Modus mit fiktiven Geräten (für Screenshots, kein echter Scan)
netspy watch 192.0.2.0/24 --mode demo --interval 5s

# Auto-Detection des Netzwerks (interaktive Auswahl)
netspy watch
```

**Watch-Modus Features:**
- Terminal-UI auf Basis von [tview](https://github.com/rivo/tview)
- Scrollbare Geräteliste (↑/↓, PgUp/PgDn), Sortierung per Taste (`i h m v d r u f`)
- Filter mit `/` inkl. Spalten-Syntax und Klammern (z.B. `vendor=apple`), History und Vorschlägen
- Host-Details mit Port-Scan per `Enter`
- Netzbereich und Scan-Modus zur Laufzeit wechselbar (`Tab` → Network/Mode)
- Echter Scan-Fortschritt in der Statuszeile
- Hilfe mit `?`
- Live-Updates für Uptime/Downtime-Zähler
- Automatische DNS-Lookups im Hintergrund
- Reachability-Checks während Countdown
- Flap-Counter für instabile Verbindungen
- Gateway-Markierung (G-Indikator)
- Farbcodierung für lokal administrierte MAC-Adressen

### Flags

**Globale Flags:**
- `--config <file>` - Konfigurations-Datei (Standard: `$HOME/.netspy.yaml`)
- `--verbose` - Ausführliche Ausgabe
- `--quiet` - Reduzierte Ausgabe (für Scripting)

**Scan-Flags:**
- `-c, --concurrent <n>` - Anzahl gleichzeitiger Scans
- `-t, --timeout <duration>` - Timeout pro Host
- `-f, --format <format>` - Ausgabeformat (table, json, csv)
- `-p, --ports <ports>` - Zu scannende Ports (Komma-separiert)
- `--mode <mode>` - Scan-Modus (conservative, fast, thorough, arp, hybrid, icmp)

**Watch-Flags:**
- `--interval <duration>` - Scan-Intervall (Standard: 60s)
- `--mode <mode>` - Scan-Modus (hybrid, arp, icmp, fast, thorough, conservative; Standard: hybrid)
- `--max-threads <n>` - Maximale parallele Threads (0 = automatisch nach Netzgröße)
- `-p, --ports <ports>` - Zu scannende Ports

## Scan-Modi

| Modus | Beschreibung | Geschwindigkeit | Genauigkeit | Use Case |
|-------|--------------|-----------------|-------------|----------|
| `conservative` | Standard TCP-Scan mit zuverlässigen Ports (22, 80, 443) | Mittel | Hoch | Allgemeiner Einsatz |
| `fast` | Schneller Scan nur HTTP/HTTPS | Sehr schnell | Niedrig | Schnelle Übersicht |
| `thorough` | Umfassender Scan vieler Ports | Langsam | Mittel | Detaillierte Analyse |
| `arp` | ARP-Tabellen-basiert (nur MAC/IP) | Schnell | Sehr hoch | Lokale Netzwerke |
| `hybrid` | ARP + TCP-Details (empfohlen) | Mittel | Sehr hoch | Beste Balance |
| `icmp` | ICMP-Ping über System-`ping` (keine Admin-Rechte) | Mittel | Hoch | Entfernte/geroutete Netze |

## Architektur

```
netspy/
├── main.go              # Einstiegspunkt
├── cmd/                 # CLI-Befehle (Cobra)
│   ├── root.go         # Root-Command
│   ├── scan.go         # Scan-Command
│   └── watch.go        # Watch-Command
├── pkg/
│   ├── scanner/        # Host-Scanning-Logik
│   ├── discovery/      # Discovery-Methoden (ARP, Ping, DNS, Vendor)
│   ├── watch/          # Watch-Modus (tview-TUI)
│   ├── filter/         # Filter-Syntax
│   ├── crash/          # Panic-Handling und Crash-Logs
│   └── output/         # Ausgabe-Formatierung (Scan-Modus)
└── README.md
```

### Kernkomponenten

**Scanner** (`pkg/scanner/`)
- Host-Struct mit IP, Hostname, MAC, Vendor, RTT, Ports, Status
- Concurrent-Scanning mit Worker-Pool-Pattern
- Konfigurierbare Timeouts und Concurrency-Limits

**Discovery** (`pkg/discovery/`)
- TCP-basiertes Ping (Ports 22, 80, 443, etc.)
- ARP-Tabellen-Parsing (plattformspezifisch)
- DNS/mDNS/NetBIOS/LLMNR Hostname-Auflösung
- MAC-Vendor-Lookup (IEEE-Register, gelernte Vendors)
- Gerätetyp-Erkennung (heuristische Analyse)
- Gateway-Detection

**Output** (`pkg/output/`)
- Tabellarische Ausgabe mit Farben
- JSON/CSV Export

**Watch** (`pkg/watch/`)
- tview-basierte Terminal-UI
- Device-State-Tracking (Uptime, Downtime, Flaps)
- Hintergrund-DNS und Reachability-Checks

## Entwicklung

### Tests ausführen

```bash
# Standard Go Tests
go test ./...

# Mit Ginkgo BDD Framework (empfohlen)
ginkgo -r

# Mit Coverage
ginkgo -r --cover

# Watch-Mode (Auto-Run bei Änderungen)
ginkgo watch -r

# Verbose Output
ginkgo -r -v
```

**Test-Framework:** Ginkgo (BDD) + Gomega (Matcher)
**Plattformspezifische Tests:** Build-Tags für Windows, macOS, Linux

### Code-Style

- **Sprache:** Deutsche Kommentare, englische Variablennamen
- **Commits:** Deutsch, Imperativ (z.B. "Füge Feature X hinzu")
- **Testing:** Vor jedem Commit Tests ausführen
- **Dokumentation:** Markdown-Format

## Plattform-Support

| Feature | Windows | macOS | Linux | Notizen |
|---------|---------|-------|-------|---------|
| ARP-Scanning | ✅ | ✅ | ✅* | *Linux nicht vollständig getestet |
| TCP-Ping | ✅ | ✅ | ✅ | Pure Go |
| DNS-Auflösung | ✅ | ✅ | ✅ | Standard Library |
| mDNS/Bonjour | ✅ | ✅ | ✅ | Pure Go |
| NetBIOS | ✅ | ⚠️ | ⚠️ | Windows-optimiert |
| LLMNR | ✅ | ✅ | ✅ | |
| Gateway-Detection | ✅ | ❌ | ❌ | **Siehe Bekannte Einschränkungen** |
| Watch-Modus | ✅ | ✅ | ✅ | tview |

**Detaillierte Plattform-Informationen:** Siehe [docs/PLATFORM_COMPATIBILITY.md](docs/PLATFORM_COMPATIBILITY.md)

## Konfiguration

Standard-Konfigurations-Datei: `$HOME/.netspy.yaml`

```yaml
# Beispiel-Konfiguration
verbose: false
quiet: false
scan:
  concurrent: 40
  timeout: 2s
  mode: hybrid
watch:
  interval: 60s
  mode: hybrid
```

## Bekannte Einschränkungen

### Cross-Platform
- **Gateway-Erkennung funktioniert nur auf Windows** (KRITISCH)
  - macOS und Linux: Gateway-Marker `[G]` fehlt im Watch-Modus
  - Lösung in Arbeit für v0.2.0
  - Details: [docs/PLATFORM_COMPATIBILITY.md](docs/PLATFORM_COMPATIBILITY.md)
- Linux-Support vollständig implementiert aber noch nicht in Produktion getestet

### Allgemein
- Einige IoT-Geräte antworten nicht auf mDNS/LLMNR
- ICMP-Modus nutzt das System-`ping` (keine Raw-Sockets, keine Admin-Rechte)
- IPv6-Support noch nicht implementiert

## Roadmap

Siehe [TODO.md](TODO.md) für geplante Features und Verbesserungen.

## Lizenz

MIT – siehe [LICENSE](LICENSE)

## Autor

NetSpy - Network Discovery Tool
