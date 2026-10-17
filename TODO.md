# NetSpy TODO

Zuletzt: golangci-lint v2 als Linter eingeführt, alle Findings behoben (0 auf Windows/Linux/macOS); Release 0.2.1 mit Scanner-Fix für Netze > /24
In Arbeit: –
Als Nächstes: Testlücken schließen oder begründen

> **Hinweis:** Dies ist die öffentliche TODO-Liste für GitHub.
> Interne/private TODOs gehören in `TODO.private.md` (wird nicht committed).
> Erledigtes steht im [CHANGELOG](CHANGELOG.md).

## Aus der Defaults-Prüfung (2026-10-16)

- [ ] **Testlücken schließen oder begründen**
  - Ohne Tests: `pkg/watch`, `pkg/output`, `pkg/crash`, `cmd`
  - Je Bereich: Tests schreiben oder in DEVELOPMENT.md → "Bewusst nicht getestet" mit Begründung
  - Ohne Test sind auch die Fixes aus 0.2.0: `getVersion()` (führendes `v`), Sentinel-Cleanup bei `--version` / Befehlsfehler
- [ ] **Doku konsolidieren**
  - `TODO.README.md`, `TVIEW_MIGRATION.md`, `CROSS_PLATFORM_NOTES.md`, `docs/CROSS_PLATFORM_*` (5 Dateien), `docs/PLATFORM_COMPATIBILITY.md`
  - Teilweise veraltet: `CROSS_PLATFORM_NOTES.md` beschreibt noch die Bubbletea-UI als Standard
  - Gültiges nach DEVELOPMENT.md (Technik) bzw. CHANGELOG (Historie) verschieben, Rest entfernen

## Cross-Platform

- [ ] **Spinner-Fix auf Windows testen** (nach macOS-Fix: ANSI-Escape-Codes statt Carriage Return, Windows 10+)
- [ ] **Linux vollständig testen** (ARP, Gateway, Watch-Modus)
- [ ] **macOS testen** (ARP, Gateway, Watch-Modus)

## Testing & Qualität

- [ ] **Code Coverage Reporting** (Ziel: > 80 %)
- [ ] **gofmt Pre-Commit Hook**
- [ ] **Tests in CI** - GitHub-Actions-Workflow für `go test`, `go vet` und `golangci-lint` bei Push und PR
  (golangci-lint dort für alle drei Plattformen, siehe DEVELOPMENT.md → Tests & Linting)
  (Release-Builds für alle Plattformen gibt es bereits, siehe `.github/workflows/release.yml`)

## Konfiguration

- [ ] **Konfigurationsdatei vervollständigen** - Viper liest `~/.netspy.yaml` bereits ein, gebunden sind aber nur `verbose` und `quiet`

## Git-Commit-Stil

- [ ] **Commit-Stil entscheiden**: Aktuell Mischstil (englische Präfixe `feat:`, `fix:` + deutsche Beschreibung)
  - Defaults verlangen "Deutsch, Imperativ" – offen, ob die Präfixe bleiben
  - Option A: Vollständig Deutsch ("Füge Feature hinzu")
  - Option B: Präfixe beibehalten, Beschreibung Deutsch im Imperativ
  - Entscheidung in DESIGN-PRINCIPLES.md oder DEVELOPMENT.md festhalten

## Design-Prinzipien im Code (Kritisch!)

**Regel: "Vollständigkeit vor Kürze" & "Opt-in statt Opt-out"**

Automatische Kürzungen, die gegen die Prinzipien verstoßen (Audit vom 2026-01-09, Zeilennummern
können sich inzwischen verschoben haben):

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

- [ ] Stellen einzeln prüfen: welche sind durch `--full-output` und `[+N]`-Hinweis inzwischen abgedeckt?
  - `http.go` (Banner, Titel) und `vendor_learn.go` kürzen zusätzlich nach Bytes (`s[:47] + "..."`) und können
    Umlaute zerschneiden - auf `output.Truncate` umstellen oder dort ebenfalls in Runes zählen
- [ ] **ARP-Refresh-Limit** (50 IPs) transparent machen oder konfigurierbar
- [ ] Konfigurationsoption für Truncation-Limits (optional, niedrige Priorität)

## Features

- [ ] Export der Watch-Ergebnisse
- [ ] Alarmierung bei offline gehenden Geräten
- [ ] Web-UI für den Watch-Modus
- [ ] Redraw der Tabelle bei wachsender Tabelle, Flaps-Spalte falsch – stammt aus der ANSI-UI, prüfen ob mit tview noch relevant

## Verbesserungen

- [ ] IPv6-Support
- [ ] mDNS/LLMNR zuverlässiger machen (manche Geräte antworten nicht)
- [ ] ICMP für RTT-Messung – ICMP-Modus über System-`ping` gibt es seit 0.1.0, prüfen ob die RTT daraus in allen Modi genutzt wird
