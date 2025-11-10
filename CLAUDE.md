# CLAUDE.md

Diese Datei bietet Anleitungen für Claude Code (claude.ai/code) bei der Arbeit mit Code in diesem Repository.

## Claude Code Präferenzen

### Testen & Ausführen
- **IMMER `go run main.go` zum Testen verwenden**, NICHT die kompilierte exe
- **Beispiel**: `timeout 90 go run main.go watch 10.0.0.0/24 --interval 30s`

### Git Workflow
- **Regelmäßig auto-committen**, um Fortschritt zu tracken und Datenverlust zu vermeiden
- Vor `/compact` oder beim Erreichen von Session-Limits IMMER committen
- Aussagekräftige Commit-Messages im Projektstil verwenden
- `git status` und `git diff` vor dem Committen prüfen

### Berechtigungen
- Alle häufig verwendeten Befehle sind in `.claude/settings.local.json` vorab genehmigt
- Beinhaltet: go build, go run, go test, git commands, ipconfig, arp, etc.

## Projekt-Übersicht

NetSpy ist ein modernes Netzwerk-Discovery-Tool in Go, das bei der Überwachung von Netzwerkinfrastruktur hilft. Es bietet Echtzeit-Subnet-Scanning mit mehreren Discovery-Methoden (ICMP, ARP, hybrid) und schöner CLI-Ausgabe.

## Entwicklungs-Befehle

### Bauen
```bash
go build -o netspy
```

### Ausführen
```bash
# Kompilierte Binary ausführen
./netspy scan <network>

# Oder direkt mit go ausführen
go run main.go scan <network>
```

### Testen
```bash
go test ./...
```

### Abhängigkeiten
```bash
# Abhängigkeiten herunterladen
go mod download

# Abhängigkeiten aktualisieren
go mod tidy
```

## Architektur

### Projektstruktur
- `main.go` - Einstiegspunkt, ruft cmd.Execute() auf
- `cmd/` - Cobra-Befehle (root, scan, watch)
- `pkg/` - Kern-Funktionalitätspakete
  - `scanner/` - Host-Scanning-Logik und Host-Typ-Definition
  - `discovery/` - Netzwerk-Discovery-Methoden (ARP, ping)
  - `output/` - Ergebnis-Formatierung (table, JSON, CSV)

### Kernkomponenten

**Scanner Package (`pkg/scanner/scanner.go`)**
- Kern-`Host`-Struct repräsentiert entdeckte Netzwerk-Hosts mit IP, Hostname, MAC, Vendor, RTT, Ports und Online-Status
- `Scanner` orchestriert gleichzeitiges Host-Scanning mit konfigurierbaren Workers und Timeouts
- Unterstützt drei Modi: fast (Geschwindigkeit über Genauigkeit), thorough (Genauigkeit über Geschwindigkeit), balanced (Standard)

**Discovery Package**
- `discovery/ping.go` - TCP-basiertes Ping mit gängigen Ports (22, 80, 443) für zuverlässige Erkennung
  - `conservativePing()` - Versucht zuverlässige Ports (22, 80, 443) um False Positives zu minimieren
  - `fastPing()` - Schnelle Erkennung nur mit HTTP/HTTPS
  - `thoroughPing()` - Probiert viele gängige Ports mit Validierung
- `discovery/arp.go` - ARP-Tabellen lesen und parsen
  - Plattformspezifisches ARP-Tabellen-Parsing (Windows, Linux, macOS)
  - `RefreshARPTable()` füllt ARP-Einträge durch Auslösen von Netzwerk-Traffic

**Scan-Modi (`cmd/scan.go`)**
1. **Default**: Konservativer TCP-Scan mit zuverlässigen Ports
2. **--mode fast**: Schneller Scan (kann Geräte übersehen)
3. **--mode thorough**: Umfassender Scan (kann False Positives haben)
4. **--mode arp**: ARP-basierter Scan (am genauesten für lokale Netzwerke)
5. **--mode hybrid**: ARP-Discovery + Ping/Port-Details (empfohlen für beste Genauigkeit + Details)

Scan-Modi schließen sich gegenseitig aus und werden validiert.

**Hybrid-Scanning-Workflow**
1. ARP-Tabelle füllen durch Pingen aller IPs im Subnet (`populateARPTable()`)
2. System-ARP-Tabelle lesen um aktive Hosts zu finden (`readCurrentARPTable()`)
3. Jeden ARP-entdeckten Host mit RTT- und Port-Daten anreichern (`enhanceHostsWithDetails()`)
4. Kombinierte Ergebnisse mit MAC-Adressen und Netzwerk-Details ausgeben

### Konfiguration
- Verwendet Viper für Konfigurations-Management
- Standard-Config-Datei: `$HOME/.netspy.yaml`
- Globale Flags: `--config`, `--verbose`, `--quiet`
- Scan-Flags: `-c` (concurrent), `-t` (timeout), `-f` (format), `-p` (ports)

### Nebenläufigkeit
- Scanner verwendet Semaphore-Pattern um gleichzeitige Scans zu limitieren
- Standard-Workers: 40 (conservative), 100 (fast), 20 (thorough)
- Hybrid-Modus verwendet separate Nebenläufigkeits-Limits: 50 für ARP-Population, 20 für Enhancement
- Fortschritts-Tracking mit atomaren Zählern

### Plattform-Überlegungen
- ARP-Scanning ist plattformspezifisch (Windows verwendet `arp -a` mit anderem Ausgabeformat als Linux/macOS)
- Windows-ARP-Format: IP, MAC (aa-bb-cc-dd-ee-ff), type
- Linux/macOS-ARP-Format: hostname (IP) at MAC [ether] on interface

## Watch-Modus (`cmd/watch.go`)

**Aktuelle Implementierung**: Statische Tabelle mit In-Place-Updates mittels ANSI-Escape-Codes

### Hauptfeatures
- **Statische Tabelle**: EINE Tabelle die in-place aktualisiert wird (kein Scrollen)
- **ANSI-Cursor-Steuerung**: Verwendet `\033[A` (nach oben) und `\033[2K` (Zeile löschen)
- **Live-Updates**: Uptime/Downtime-Zähler, DNS-Lookups, Status-Änderungen - alles aktualisiert sich in der Tabelle
- **Einzelne Status-Zeile**: Unter der Tabelle zeigt Scan-Stats und Countdown-Timer
- **Tabellen-Refresh**: Vollständiges Redraw alle 5 Sekunden um DNS-Updates zu erfassen

### Wichtige Funktionen
- `redrawTable()` - Zeichnet gesamte Tabelle in-place neu
- `moveCursorUp(n)` - Bewegt Cursor n Zeilen nach oben
- `clearLine()` - Löscht aktuelle Zeile
- `showCountdownWithTableUpdates()` - Aktualisiert Status-Zeile + periodisches Tabellen-Refresh
- `performScanQuiet()` - Scannt ohne Output (Ergebnisse werden von runWatch verarbeitet)
- `performBackgroundDNSLookups()` - Asynchrone DNS-Auflösung während Countdown

### Design-Prinzip
**KEINE neuen Zeilen nach initialem Tabellen-Draw** - Alles aktualisiert sich in-place für ein sauberes, Dashboard-artiges Erlebnis
