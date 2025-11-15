# NetSpy

Modernes Netzwerk-Discovery-Tool in Go zur Überwachung von Netzwerkinfrastruktur mit Echtzeit-Scanning und schöner CLI-Ausgabe.

## Features

- **Echtzeit-Netzwerk-Überwachung** - Kontinuierliches Monitoring mit Live-Updates
- **Mehrere Discovery-Methoden** - ICMP, ARP, Hybrid-Scanning
- **Intelligente Geräte-Erkennung** - Automatische Identifikation von Gerätetypen (Router, Smartphone, IoT, etc.)
- **Hostname-Auflösung** - DNS, mDNS/Bonjour, NetBIOS, LLMNR Support
- **MAC-Vendor-Datenbank** - 976+ OUI-Einträge für Hersteller-Identifikation
- **Gateway-Erkennung** - Automatische Markierung des Default-Gateways
- **Statische Tabellen-Ansicht** - In-Place-Updates ohne Scrollen (Watch-Modus)
- **Uptime/Downtime-Tracking** - Verfolgung von Geräteverfügbarkeit über Zeit
- **Flapping-Detection** - Erkennung instabiler Netzwerkverbindungen
- **RTT-Messung** - Response-Time-Tracking für Performance-Monitoring
- **Plattformübergreifend** - Windows, macOS, Linux Support

## Installation

### Voraussetzungen

- Go 1.21 oder höher

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

# Auto-Detection des Netzwerks (interaktive Auswahl)
netspy watch
```

**Watch-Modus Features:**
- Statische Tabelle mit ANSI-Cursor-Steuerung (kein Scrollen)
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
- `--mode <mode>` - Scan-Modus (conservative, fast, thorough, arp, hybrid)

**Watch-Flags:**
- `--interval <duration>` - Scan-Intervall (Standard: 60s)
- `--mode <mode>` - Scan-Modus (Standard: hybrid)

## Scan-Modi

| Modus | Beschreibung | Geschwindigkeit | Genauigkeit | Use Case |
|-------|--------------|-----------------|-------------|----------|
| `conservative` | Standard TCP-Scan mit zuverlässigen Ports (22, 80, 443) | Mittel | Hoch | Allgemeiner Einsatz |
| `fast` | Schneller Scan nur HTTP/HTTPS | Sehr schnell | Niedrig | Schnelle Übersicht |
| `thorough` | Umfassender Scan vieler Ports | Langsam | Mittel | Detaillierte Analyse |
| `arp` | ARP-Tabellen-basiert (nur MAC/IP) | Schnell | Sehr hoch | Lokale Netzwerke |
| `hybrid` | ARP + TCP-Details (empfohlen) | Mittel | Sehr hoch | Beste Balance |

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
│   ├── discovery/      # Discovery-Methoden (ARP, Ping, DNS)
│   └── output/         # Ausgabe-Formatierung
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
- MAC-Vendor-Lookup (OUI-Datenbank)
- Gerätetyp-Erkennung (heuristische Analyse)
- Gateway-Detection

**Output** (`pkg/output/`)
- Tabellarische Ausgabe mit Farben
- JSON/CSV Export
- ANSI-gesteuerte Live-Updates (Watch-Modus)

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
**Test-Coverage:** 42 Specs in 11 Test-Dateien
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
| Watch-Modus | ✅ | ✅ | ✅ | ANSI Codes |

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
- ICMP-Ping erfordert Admin-Rechte (aktuell nur TCP)
- IPv6-Support noch nicht implementiert
- 16 von 42 Tests schlagen aktuell fehl (siehe [TODO.md](TODO.md))

## Roadmap

Siehe [TODO.md](TODO.md) für geplante Features und Verbesserungen.

## Lizenz

Proprietär - Alle Rechte vorbehalten

## Autor

NetSpy - Network Discovery Tool
