# Changelog

Alle nennenswerten Änderungen an diesem Projekt werden in dieser Datei dokumentiert.

Das Format basiert auf [Keep a Changelog](https://keepachangelog.com/de/1.0.0/),
und dieses Projekt folgt [Semantic Versioning](https://semver.org/lang/de/).

## [Unreleased]

### Fixed
- **Einzelne IP auf der Kommandozeile wurde abgelehnt** - `netspy scan 192.0.2.5` brach mit "invalid CIDR" ab, ebenso `watch`. Jetzt scannt `scan` mit einer einzelnen IP genau diesen Host, `watch` beobachtet ihr /24 (wie das Netzfeld in der TUI)
- **Watch mit kleinem `--max-threads` blieb hängen** - Bei `--max-threads 1` bis `4` wurde mindestens eine Thread-Art auf 0 abgerundet. Bei 1 lief der Scan gar nicht, bis 4 wurden Hostnamen nie aufgelöst. Jetzt bekommt jede Art mindestens einen Thread
- **Gekürzte Spalten im Scan-Modus nannten in `[+N]` eine zu kleine Zahl** versteckter Zeichen, und Umlaute konnten mitten im Zeichen abgeschnitten werden. Es wird jetzt in Zeichen statt in Bytes gezählt
- **CSV-Ausgabe verschob Spalten**, wenn ein Feld ein Komma enthielt (z.B. Hersteller "Apple, Inc."). Felder werden jetzt nach RFC 4180 in Anführungszeichen gesetzt
- **Falsche Crash-Meldung nach einem Kill** - Nach einem einzigen Absturz meldete netspy bei jedem späteren von außen beendeten Lauf "Crash-Report gefunden", weil das Crash-Log nie gelöscht wird. Jetzt zählt das Log nur, wenn es nach dem Start des letzten Laufs geschrieben wurde
- `scan` sortierte Ergebnisse textuell nach IP (`.10` vor `.2`), jetzt numerisch - gilt für Tabelle, JSON und CSV

### Changed
- Code nach golangci-lint bereinigt (staticcheck, ineffassign), keine Verhaltensänderung
- DEVELOPMENT.md: golangci-lint als Linter, Prüfung für alle Plattformen per `GOOS`

## [0.2.1] - 2026-10-16

### Fixed
- **Netze größer als /24 wurden nur teilweise gescannt** - Die Zählung der Host-Adressen sprang nach `.255` auf `.0.1` zurück. Bei einem /23 wurden die Adressen des ersten /24-Blocks doppelt gescannt, die des zweiten nie; bei einem /16 nur 256 von 65.534 Adressen
- Completion-Befehl meldet Schreibfehler, Banner-Grabbing kann nicht mehr ohne Timeout hängen, Fehler beim Kopieren in die Zwischenablage werden vollständig gemeldet

### Changed
- Crash-Log, Sentinel-Datei und `vendor_learned.txt` werden nur für den eigenen Nutzer lesbar angelegt (0600), der Registry-Ordner mit 0750 (Linux/macOS)
- Linting mit golangci-lint v2, die Konfiguration war für v2 ungültig und wurde neu aufgesetzt

## [0.2.0] - 2026-10-16

### Added
- **Hersteller-Auflösung über die lokale IEEE-Registry** - Longest-Prefix-Match über MA-S (36 Bit), MA-M (28 Bit) und MA-L (24 Bit)
  - Unterteilte MAC-Blöcke werden jetzt korrekt aufgelöst (vorher "IEEE Registration Authority", z.B. bei 58:47:CA)
  - Registry-Dateien werden in `~/.netspy/registry` zwischengespeichert, Aktualisierung läuft im Hintergrund
  - Datenschutz: Es werden nur die vollständigen öffentlichen Listen geladen, nie einzelne MAC-Adressen abgefragt
- **Demo-Modus für Watch** - `netspy watch 192.0.2.0/24 --mode demo` zeigt fiktive Geräte aus dem Dokumentationsnetz (RFC 5737), ohne Pakete ins reale Netz zu senden
  - Simuliert neue Geräte, ein flappendes Gerät und eine Privacy-MAC
  - `docs/demo.tape` (vhs) und `docs/demo.gif` für README/Screenshots
- **SBOM im Release** - Jedes Release enthält pro Plattform eine Software Bill of Materials im CycloneDX-Format (`netspy-<os>-<arch>.cdx.json`), als eigenes Asset und im ZIP
- **Lizenztexte im Release** - Jedes ZIP enthält `LICENSE` und `THIRD_PARTY_LICENSES.txt` mit allen Lizenz- und NOTICE-Texten der enthaltenen Module
- **Fremdpakete dokumentiert** - `THIRD_PARTY.md` listet alle Module der Binary mit Version, Lizenz und Zweck sowie Test-Pakete, Datenquellen und Werkzeuge

### Fixed
- Vendor-API-Lookups (macvendors.com) auf eine Anfrage pro Sekunde begrenzt - parallele Anfragen wurden vorher teilweise mit HTTP 429 abgewiesen und still verworfen
- `netspy --version` zeigte fest "0.1.1" statt der tatsächlichen Version
- `netspy version` zeigte bei Release-Builds ein doppeltes "v" (z.B. "vv0.1.2")
- Falsche Warnung "Letzter Lauf wurde nicht sauber beendet" nach `netspy --version` oder einem fehlerhaften Befehl - die Sentinel-Datei wurde in diesen Fällen nicht entfernt
- Crash-Meldung verwies auf ein falsches Repository für Fehlerberichte

### Changed
- **Go 1.26 oder höher** für den Build aus den Quellen erforderlich (vorher 1.24), bedingt durch aktualisierte `golang.org/x`-Pakete. Release-Binaries sind nicht betroffen
- README um englischen Kopf (Quickstart, Features) und Badges ergänzt, veraltete Angaben korrigiert
- Binary und leere `scan_result.csv` nicht mehr im Repo, Binaries kommen ausschließlich über Releases
- Release-Workflow liest die Go-Version aus `go.mod`

### Dependencies
- `github.com/gdamore/tcell/v2` 2.13.0 → 2.13.10
- `github.com/spf13/cobra` 1.9.1 → 1.10.2
- `github.com/spf13/viper` 1.20.1 → 1.21.0
- `github.com/fatih/color` 1.18.0 → 1.19.0
- `golang.org/x/term` 0.37.0 → 0.47.0
- `github.com/onsi/ginkgo/v2` 2.27.2 → 2.33.1 (nur Tests)
- `github.com/onsi/gomega` 1.38.2 → 1.44.0 (nur Tests)
- Indirekte Abhängigkeiten entsprechend aktualisiert

## [0.1.2] - 2026-07-15

### Added
- **Netzbereich und Scan-Modus zur Laufzeit wechselbar** - Editierbares Network-Feld und Modus-Dropdown im Watch-Header (per `Tab` erreichbar)
  - Akzeptiert CIDR und einzelne IP (wird zu /24)
  - Beim Netzwechsel bleiben nur Geräte im neuen Bereich erhalten
  - Laufender Scan wird beim Wechsel sofort abgebrochen
- **Echter Scan-Fortschritt in der Statuszeile** - z.B. `pinge 12340 / 65534 (19%)`

### Fixed
- **Goroutine-Panics abgefangen (Crash-Hardening)** - Worker-Goroutinen und Background-Helfer (DNS, Port-Scan, Vendor-Lookup) loggen Panics und laufen weiter, statt die Watch-Session zu beenden

## [0.1.1] - 2026-02-07

### Added
- Release-ZIPs enthalten zusätzlich `vendor_learned.txt` (gelernte MAC-Hersteller)

## [0.1.0] - 2026-02-07

Erstes öffentliches Release.

### Features

#### Kern-Funktionalität
- **Watch-Modus als TUI (tview)** - Live-Dashboard mit Uptime, Downtime, Flap-Zähler und RTT
- **Mehrere Scan-Modi** - Conservative, Fast, Thorough, ARP, Hybrid, ICMP
- **ICMP-Modus für remote Netzwerke** - Nutzt das System-`ping`, keine Raw-Sockets, keine Admin-Rechte
- **Plattformübergreifend** - Windows, macOS, Linux mit plattformspezifischem ARP-Parsing und Gateway-Erkennung

#### Discovery & Detection
- **Intelligente Gerätetyp-Erkennung** - Heuristische Analyse für Router, Smartphones, IoT, etc.
- **Multi-Protokoll Hostname-Auflösung**:
  - DNS (Standard, inkl. DNS-Cache-Vorbefüllung)
  - mDNS/Bonjour (Apple/IoT-Geräte)
  - NetBIOS (Windows-Hosts, RFC 1002)
  - LLMNR (Windows Link-Local)
  - HTTP-Titel (z.B. Philips Hue)
- **SSDP/UPnP Discovery** - Bessere Erkennung von Medien- und IoT-Geräten
- **MAC-Vendor-Erkennung** - Eingebaute OUI-Datenbank plus selbstlernendes System (`vendor_learned.txt`, Lookup über macvendors.com)
- **Gateway-Erkennung** - Automatische Markierung des Default-Gateways
- **Erkennung lokal administrierter (Privacy-)MACs**

#### Watch-Modus (TUI)
- Sortierung nach jeder Spalte (`i h m v d r u f`) mit stabiler Sekundärsortierung nach IP
- Filter (`/`) mit Spalten-Syntax und Klammern, z.B. `vendor=apple`
- Host-Details (`Enter`) mit Port-Scan auf Abruf und DNS-Konsistenz-Check
- Hilfe-Overlay (`?`), Markierung neuer Hosts, Zebra-Streifen
- Plattformspezifische Farbanpassungen für macOS/Windows/Linux

#### Output & Formate
- **Mehrere Ausgabe-Formate** - Table (Standard), JSON, CSV
- **Quiet-Flag** - Reduzierte Ausgabe für Scripting/Piping
- **Shell-Completion** - bash, zsh, fish, PowerShell

#### Robustheit
- **Crash-Handler** - Panics werden in eine Log-Datei geschrieben
- **Sentinel-Datei** - Erkennt beim Start, ob der letzte Lauf unsauber beendet wurde (Crash vs. Kill)

#### Weitere Details (aus der früheren TODO-Liste übernommen)
- **Heuristische Gateway-Erkennung** für entfernte Netzwerke (`.1` / `.254` in /8, /16, /24), kombiniert mit lokaler Erkennung in `IsLikelyGateway()`, mit Cache
- **Plattformspezifische Gateway-Erkennung** - Windows `route print`, macOS `route -n get default`, Linux `ip route` / `route -n`
- **Automatischer Fallback für fremde Subnetze** - ARP/Hybrid erkennen remote Netze und weichen auf TCP aus, mit Hinweis auf die verwendete Strategie
- **Responsive Tabellen im Scan-Modus** - 3 Layouts (< 100, 100-139, ≥ 140 Spalten)
- **`--full-output`** und zentrale Kürzung (`pkg/output/truncate.go`) mit sichtbarem Hinweis `[+N]` auf versteckte Zeichen; Unicode-Ellipsis `…` statt `...`
- **Netzwerk-Auto-Erkennung** für `watch` ohne CIDR-Angabe
- **Einheitliches `--mode`-Flag** statt separater Flags je Scan-Modus
- **RTT-Messung** mit Multi-Port-Fallback für Geräte ohne Standarddienste
- **OS-Erkennung** anhand offener Ports (Windows, Linux, Server)
- **NetBIOS-Fallback** bei Background-DNS-Lookups
- **MAC-Vendor-Datenbank** mit 976+ OUI-Einträgen

#### Fixed
- MAC-Adressen werden nie mehr gekürzt (`TruncateMAC()` gibt immer alle 17 Zeichen zurück)
- Spinner-Ausgabe auf macOS (ANSI-Escape-Codes statt Carriage Return)
- Hostname-Flackern durch Caching der Auflösung behoben
- Spaltenausrichtung von Header und Datenzeilen

### Technische Details
- **Cobra CLI-Framework** und **Viper** für Konfiguration (`$HOME/.netspy.yaml`)
- **Concurrent Scanning** - Worker-Pool mit Semaphore-Pattern, konfigurierbare Concurrency
- **BDD Testing** - Ginkgo + Gomega, plattformspezifische Tests über Build-Tags
- **GitHub Actions Release-Workflow** - ZIPs für Windows, Linux, macOS (amd64, arm64)

### Bekannte Einschränkungen
- Kein IPv6-Support
- Einige IoT-Geräte antworten nicht auf mDNS/LLMNR

---

## Versionierung

Dieses Projekt verwendet [Semantic Versioning](https://semver.org/lang/de/):
- **MAJOR** - Inkompatible API-Änderungen
- **MINOR** - Neue Funktionen (rückwärtskompatibel)
- **PATCH** - Bugfixes (rückwärtskompatibel)

[Unreleased]: https://github.com/feiglein74/netspy/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/feiglein74/netspy/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/feiglein74/netspy/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/feiglein74/netspy/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/feiglein74/netspy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/feiglein74/netspy/releases/tag/v0.1.0
