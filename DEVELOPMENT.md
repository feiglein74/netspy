# Development

Technisches Projektwissen für Entwickler: Setup, Befehle, Architektur, Stolperfallen.
Zweck und Nutzung stehen in der [README](README.md), das *Warum* in den
[Design-Prinzipien](DESIGN-PRINCIPLES.md), offene Aufgaben in der [TODO](TODO.md).

> ⚠️ **Der Watch-Modus ist der Hauptzweck des Projekts.** `scan` und die übrigen Befehle sind
> vor allem Test- und Entwicklungshilfen. Watch nutzt tview (`pkg/watch/`) und damit komplett
> andere Code-Pfade als die CLI-Ausgabe der Scan-Modi (`pkg/output/`).
> **Bei Bug-Fixes daher immer beide Pfade prüfen** (`grep -r` über das ganze Projekt) und alle
> Stellen fixen, nicht nur die zuerst gefundene.

## Setup

- **Go 1.26 oder höher** (Mindestversion durch die `golang.org/x`-Pakete vorgegeben, siehe `go.mod`)
- Optional: [Ginkgo-CLI](https://onsi.github.io/ginkgo/) für ausführlichere Testausgabe:
  `go install github.com/onsi/ginkgo/v2/ginkgo@latest`
- [golangci-lint](https://golangci-lint.run/) v2 (enthält staticcheck, errcheck, gosec, misspell …):
  `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0`
  (muss mit der installierten Go-Version gebaut sein, siehe Stolperfallen)
- Für die SBOM: [cyclonedx-gomod](https://github.com/CycloneDX/cyclonedx-gomod) (nur für Releases, läuft im Workflow)

```bash
go mod download
go build -o netspy          # Windows: go build -o netspy.exe
./netspy watch 192.168.1.0/24
go run main.go scan 192.168.1.0/24 --mode hybrid
```

Gefahrlos testen ohne echtes Netz: `netspy watch 192.0.2.0/24 --mode demo` (fiktive Hosts).

## Tests & Linting

**Vor jedem Commit**: Tests und Linting, alle Findings fixen.

```bash
go test ./...               # alle Tests (Exit-Code ≠ 0 bei Fehlern)
go vet ./...                # Code-Qualität
golangci-lint run ./...     # Linting nach .golangci.yml (Exit-Code ≠ 0 bei Findings)
```

Plattformspezifischer Code (`*_windows.go`, `*_linux.go`, `*_darwin.go`) wird nur für das
eigene OS geprüft. Vor Änderungen daran auch die anderen prüfen:

```bash
GOOS=linux golangci-lint run ./...
GOOS=darwin golangci-lint run ./...
```

`.golangci.yml`: Ausschlüsse stehen mit Begründung in der Datei. `_ = f()` gilt als bewusstes
Ignorieren eines Fehlers; einzelne Ausnahmen per `//nolint:<linter> // <Grund>`.

Ausführlicher mit Ginkgo:

```bash
ginkgo -r                   # alle Suites
ginkgo -r -v                # verbose
ginkgo -r --cover           # mit Coverage
ginkgo pkg/discovery        # einzelnes Package
ginkgo watch -r             # bei Änderungen automatisch
```

### Test-Framework

**Ginkgo** (BDD) mit **Gomega** (Matcher). Plattformspezifische Tests über Build-Tags
(`//go:build windows`, `//go:build darwin`, `//go:build linux`).

| Datei | Inhalt |
|---|---|
| `pkg/scanner/scanner_test.go` | Scanner |
| `pkg/discovery/vendor_test.go` | MAC-Vendor-Erkennung |
| `pkg/discovery/vendor_registry_test.go` | IEEE-Registry (Longest-Prefix-Match MA-S/MA-M/MA-L) |
| `pkg/discovery/devicetype_test.go` | Gerätetyp-Erkennung |
| `pkg/discovery/gateway_test.go` | Gateway-Erkennung (lokal + heuristisch) |
| `pkg/discovery/ping_test.go` | Ping und IP-Generierung |
| `pkg/discovery/arp_test.go` | ARP plattformübergreifend |
| `pkg/discovery/arp_{windows,darwin,linux}_test.go` | ARP plattformspezifisch |
| `pkg/filter/filter_test.go` | Filter-Syntax des Watch-Modus |

Ohne Tests: `pkg/watch`, `pkg/output`, `pkg/crash`, `cmd` (siehe TODO.md).

## Architektur

### Projektstruktur

- `main.go` - Einstiegspunkt: Crash-Handler, Sentinel, Signal-Handler, `cmd.Execute()`
- `cmd/` - Cobra-Befehle (`root`, `scan`, `watch`, `version`, `completion`)
- `pkg/watch/` - Watch-Modus (tview-TUI, Scan-Schleife, DNS, Host-Details, Demo-Modus)
- `pkg/scanner/` - Host-Scanning und `Host`-Struct (IP, Hostname, MAC, Vendor, RTT, Ports, Status)
- `pkg/discovery/` - Discovery (ARP, TCP-Ping, ICMP), Namensauflösung (DNS, mDNS, NetBIOS, LLMNR,
  HTTP, SSDP), Vendor (IEEE-Registry, gelernte Vendors, macvendors.com), Gerätetyp, Gateway
- `pkg/filter/` - Filter-Syntax (Spalten, Klammern) für den Watch-Modus
- `pkg/crash/` - Crash-Handler, `RecoverAndLog`/`SafeGo` für Goroutinen, Sentinel-Datei
- `pkg/output/` - Formatierung der Scan-Modi (Table, JSON, CSV), zentrale Kürzung in `truncate.go`

### Scan-Modi

1. **conservative** (Default von `scan`): TCP-Ping auf zuverlässige Ports (22, 80, 443)
2. **fast**: nur HTTP/HTTPS, kann Geräte übersehen
3. **thorough**: viele Ports, kann False Positives liefern
4. **arp**: ARP-Tabelle, am genauesten im lokalen Netz
5. **hybrid**: ARP-Discovery + RTT/Port-Details (empfohlen)
6. **icmp**: System-`ping` ohne Raw-Sockets, für geroutete/remote Netze ohne ARP
7. **demo** (nur Watch): fiktive Hosts aus 192.0.2.0/24, kein Netzverkehr

Die Modi schließen sich gegenseitig aus und werden validiert. Hybrid/ARP fallen bei fremden
Subnetzen automatisch auf TCP zurück.

**Hybrid-Ablauf**: ARP-Tabelle durch Pingen aller IPs füllen → System-ARP-Tabelle lesen →
gefundene Hosts mit RTT und Ports anreichern → zusammenführen.

### Watch-Modus (`cmd/watch.go` → `pkg/watch/`)

TUI mit [tview](https://github.com/rivo/tview). Die frühere ANSI-Escape-Variante und die
Bubbletea-UI gibt es nicht mehr (siehe `TVIEW_MIGRATION.md`).

| Datei | Inhalt |
|---|---|
| `tview.go` | `TviewApp`: `setupUI()`, `setupKeyBindings()`, `updateTable()`, `updateHeader()`, `scanLoop()`, `performScan()`, `updateDeviceStates()`, `countdownLoop()`, `applyNetworkChange()`, `applyModeChange()`, Filter |
| `scanner.go` | `PerformScanQuiet()` verteilt auf Hybrid/ARP/ICMP/Normal; `PerformQuickReachabilityCheck()` |
| `dns.go` | `PopulateFromDNSCache()`, `PerformInitialDNSLookups()`, `PerformBackgroundDNSLookups()` |
| `details.go` | `HostDetailsModal` (Port-Scan, Banner, DNS-Konsistenz-Check) |
| `state.go` | `DeviceState`, `SortState`, `SortIPs()`, `CalculateThreads()` |
| `demo.go` | `PerformDemoScan()` für `--mode demo` |

### Nebenläufigkeit

- Semaphore-Pattern begrenzt gleichzeitige Scans; Fortschritt über atomare Zähler
- Standard-Workers: 40 (conservative), 100 (fast), 20 (thorough); Hybrid: 50 für ARP-Population, 20 für Anreicherung
- Watch: Thread-Anzahl abhängig von der Netzgröße (`CalculateThreads()`)
- **Jede Goroutine absichern**: Worker mit `defer crash.RecoverAndLog(...)`, Dauerschleifen mit `crash.SafeGo()`
- **UI-Updates aus Goroutinen nur über `app.QueueUpdateDraw()`**
- Vendor-API (macvendors.com): höchstens 1 Anfrage pro Sekunde (Semaphor + Zeitstempel in `vendor_learn.go`)

### Konfiguration

- Viper, Standard-Datei `$HOME/.netspy.yaml`
- Globale Flags: `--config`, `--verbose`, `--quiet`, `--full-output`
- Scan-Flags: `-c` (concurrent), `-t` (timeout), `-f` (format), `-p` (ports)

### Plattformen

Code muss auf **Windows, macOS und Linux** funktionieren. Plattformspezifischer Code über
Build-Tags (`//go:build unix`, `//go:build windows` bzw. Dateisuffixe `_windows.go`, `_darwin.go`, `_linux.go`).

- ARP: Windows `arp -a` (IP, MAC `aa-bb-cc-dd-ee-ff`, Typ); Linux/macOS `hostname (IP) at MAC [ether] on interface`
- Gateway: Windows `route print`, macOS `route -n get default`, Linux `ip route` / `route -n`
- Details: [CROSS_PLATFORM_NOTES.md](CROSS_PLATFORM_NOTES.md), [docs/](docs/)

## Abhängigkeiten

```bash
go get <modul>@latest
go mod tidy
```

**Bei jeder Änderung an Abhängigkeiten [THIRD_PARTY.md](THIRD_PARTY.md) nachziehen**
(Versionen, Lizenzen, neue oder entfallene Module). Welche Module tatsächlich in der Binary
stecken: `go version -m <binary>`. Die Liste unterscheidet sich je Plattform
(z.B. `mousetrap` nur unter Windows).

## Release

1. `CHANGELOG.md` pflegen, `Version` in `cmd/version.go` auf die neue Version setzen
2. Tests und Linting, committen, pushen
3. Tag `vX.Y.Z` pushen → `.github/workflows/release.yml` baut 6 Plattformen
   (windows/linux/darwin × amd64/arm64)
4. Pro Plattform entsteht ein ZIP (Binary, `vendor_learned.txt`, `LICENSE`,
   `THIRD_PARTY_LICENSES.txt`, SBOM) plus die CycloneDX-SBOM als eigenes Asset
5. Release-Notes aus dem CHANGELOG-Abschnitt setzen: `gh release edit vX.Y.Z --notes-file <datei>`

Die Version wird per ldflags aus dem Tag gesetzt (`-X netspy/cmd.Version=vX.Y.Z`),
`getVersion()` entfernt das führende `v`.

## Stolperfallen

### Go baut über laufende Binaries
Go schreibt die Binary erst nach erfolgreichem Build und ersetzt sie dann. Laufende Prozesse
behalten die alte Version. **Nicht** vorher `taskkill`/`pkill` ausführen, einfach bauen.

### Windows: Defender/ASR blockt frisch gebaute .exe in `%TEMP%`
Attack Surface Reduction kann frisch kompilierte `.exe` in `%TEMP%` mit "Zugriff verweigert"
blockieren. Das betrifft `go build` (der Linker schreibt nach TEMP) und `go test` (Test-Binaries).

- Build direkt in ein von ASR ausgenommenes Verzeichnis: `go build -o <ausgenommen>/netspy.exe`
- Tests: `GOTMPDIR` auf ein ausgenommenes Verzeichnis setzen. `-o` reicht **nicht**, die
  Zwischenstufen landen sonst weiter in TEMP.
- Auch heruntergeladene Release-Binaries lassen sich in TEMP nicht starten oder kopieren,
  dort ebenfalls direkt ins ausgenommene Verzeichnis entpacken.
- Go-Tools (`go install`) können auch in `~/go/bin` blockiert werden, teils erst Minuten nach
  der Installation ("Permission denied"). Abhilfe: `GOBIN=<ausgenommen>/bin go install …`
  und das Tool mit vollem Pfad aufrufen.

### `os.Exit` überspringt den Sentinel-Cleanup
`main.go` legt beim Start `.netspy.running` an (im aktuellen Verzeichnis) und entfernt die
Datei per `defer`. `os.Exit` überspringt `defer`, dann bleibt die Datei liegen und der nächste
Start meldet fälschlich "Letzter Lauf wurde nicht sauber beendet". Daher in `cmd/` `return`
statt `os.Exit(0)`; wo `os.Exit(1)` nötig ist, vorher `crash.StopSentinel()` aufrufen.

### Watch braucht ein echtes Terminal
Die tview-TUI läuft nicht ohne TTY (z.B. in Pipes oder nicht-interaktiven Shells). Zum
Testen ohne Terminal den `scan`-Befehl nutzen, für Screenshots `--mode demo`.

### Prozesse zeitlich begrenzt laufen lassen
`timeout` fehlt auf macOS standardmäßig. Plattformübergreifend:

```bash
./netspy watch 10.0.0.0/24 --interval 30s &
NETSPY_PID=$!
sleep 8
kill $NETSPY_PID
wait $NETSPY_PID 2>/dev/null || true
```

### Git Bash
Eingeschränkte ANSI-Unterstützung, für den Watch-Modus nicht empfohlen. Windows Terminal,
PowerShell und cmd.exe funktionieren.

### Linter passt nicht zur Go-Version
Ein Linter (golangci-lint, staticcheck), der mit einer älteren Go-Version gebaut wurde, bricht
mit `export data version N is greater than maximum supported version` ab. Abhilfe: nach einem
Go-Update neu installieren (`go install …`), damit er mit der aktuellen Go-Version gebaut wird.

### golangci-lint v2: alte Config-Schlüssel
v2 kennt `linters-settings` und `issues.exclude-rules` nicht mehr (jetzt `linters.settings`
und `linters.exclusions.rules`). Nach Änderungen an `.golangci.yml`: `golangci-lint config verify`.
misspell nicht mit `locale: US` betreiben, sonst gelten deutsche Wörter wie "Analyse" als
britisches Englisch.

## Bewusst nicht getestet

| Bereich | Begründung | Datum |
|---|---|---|

Noch offen, welche Bereiche hier landen und welche Tests bekommen, siehe TODO.md.

## Regelstand

Geprüft gegen: defaults.md v2.0.0 (2026-10-16)

Noch nicht umgesetzt (steht in TODO.md):
- Testlücken in `pkg/watch`, `pkg/output`, `pkg/crash`, `cmd` - Tests schreiben oder hier begründen
- Doku-Konsolidierung (ältere Plattform- und Migrationsnotizen)
- Commit-Stil: englische Präfixe (`feat:`, `fix:` …) mit deutscher Beschreibung, Entscheidung offen

Abweichend von den Defaults:
- `.gitattributes`: `*.go` mit `eol=lf`, sonst meldet `gofmt` unter Windows jede Datei
