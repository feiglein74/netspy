# NetSpy TODO

Zuletzt: Testlücken geschlossen (Tests in allen Paketen, Rest in DEVELOPMENT.md begründet), dabei 7 Fehler gefunden und behoben (Release 0.2.2)
In Arbeit: –
Als Nächstes: Doku konsolidieren

> **Hinweis:** Dies ist die öffentliche TODO-Liste für GitHub.
> Interne/private TODOs gehören in `TODO.private.md` (wird nicht committed).
> Erledigtes steht im [CHANGELOG](CHANGELOG.md).

## Aus der Defaults-Prüfung (2026-10-16)

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

- [ ] Stellen einzeln prüfen: welche sind durch `--full-output` und `[+N]`-Hinweis inzwischen abgedeckt?
  - `http.go` (Banner, Titel) und `vendor_learn.go` kürzen zusätzlich nach Bytes (`s[:47] + "..."`) und können
    Umlaute zerschneiden - auf `output.Truncate` umstellen oder dort ebenfalls in Runes zählen
- [ ] **ARP-Refresh-Limit** (50 IPs) transparent machen oder konfigurierbar
- [ ] Konfigurationsoption für Truncation-Limits (optional, niedrige Priorität)

## Roadmap: Vom Scanner zum Wächter (Wettbewerbsvergleich 2026-11-13)

Vergleich mit Fing, NetAlertX, WatchYourLAN, nmap, Advanced IP Scanner: größte Lücke ist,
dass netspy nichts über Neustarts hinweg weiß und niemanden benachrichtigt.
Grundlage ist bereits da: `watch.DeviceState` hat `FirstSeen`, `LastSeen`, `FlapCount` usw.

Ist-Stand „neue Geräte“: Geräte, die nach dem ersten Scan auftauchen, werden farbig markiert
(`pkg/watch/tview.go`, `FirstSeenScan`) – aber nur für 2 Scans, nur innerhalb des laufenden Prozesses,
ohne Log/Benachrichtigung, und `deviceStates` ist nach IP geschlüsselt (neue MAC auf alter IP fällt
vermutlich nicht als neu auf – prüfen).

### Phase 1 – Bekannte Geräte (Persistenz) · Aufwand: ~2–3 Tage
- [ ] Gerätespeicher `~/.netspy/known_hosts.json` (Schlüssel: MAC; Felder: erste/letzte Sichtung,
      letzte IP, Hostname, Vendor, eigener Name, Notiz, „vertraut“-Markierung)
  - Pro Netz trennen (CIDR), Schreiben atomar (temp + rename), Laden beim Start von watch
  - Randomisierte/private MACs (bereits erkannt) gesondert behandeln: nicht als „neu“ melden, sondern Hinweis zeigen
  - Geräte ohne MAC (ICMP-Modus, geroutete Netze): Schlüssel IP, transparent als „unsicher“ kennzeichnen
- [ ] TUI: Markierung „NEU“ für nie zuvor gesehene Geräte (über Neustarts hinweg, nicht nur pro Lauf),
      bleibt bis zur Bestätigung (z. B. „als bekannt markieren“) statt nach 2 Scans zu verschwinden
- [ ] MAC-Wechsel auf gleicher IP erkennen und als neues Gerät behandeln
- [ ] TUI: Gerät benennen / als vertraut markieren im Host-Detail (`Enter`)
- [ ] Spalten/Filter: `name=`, `new`, `known`; „zuletzt gesehen“ für aktuell offline bekannte Geräte
- [ ] Opt-out-Flag `--no-store` (Default = speichern, transparent im Header angezeigt)

### Phase 2 – Benachrichtigungen · Aufwand: ~2 Tage
- [ ] Ereignisse: neues Gerät, Gerät offline (nach Schwelle, z. B. `--offline-after 5m`), wieder online, IP-Wechsel einer MAC
- [ ] Kanäle (opt-in per Flag/Config): generischer Webhook (JSON), ntfy, Kommando ausführen (`--on-event cmd`)
- [ ] Event-Log in der TUI (eigenes Panel oder Overlay) + `~/.netspy/events.log`
- [ ] Entprellen: Flapping-Geräte nicht bei jedem Wechsel melden
- (ersetzt den früheren Punkt „Alarmierung bei offline gehenden Geräten“)

### Phase 3 – Headless-Betrieb · Aufwand: ~1–2 Tage
- [ ] `netspy watch --headless`: ohne TUI, Events als Text- oder JSON-Zeilen auf stdout (für systemd, Docker, Pi)
- [ ] Beispiel-systemd-Unit und Dockerfile in `docs/`
- [ ] Konfigurationsdatei vervollständigen (siehe Abschnitt Konfiguration) – nötig für Kanäle und Schwellen

### Phase 4 – Bessere Geräteerkennung · Aufwand: ~2–4 Tage, optional
- [ ] SSDP/UPnP-Discovery (Modellname, Hersteller von TVs, Routern, Druckern, Sonos …)
- [ ] mDNS-Service-Typen auswerten (`_airplay`, `_ipp`, `_googlecast` …) für Gerätetyp
- [ ] HTTP-Titel/Banner in die Typ-Heuristik einbeziehen

### Kleinere Ergänzungen
- [ ] Wake-on-LAN für bekannte Geräte aus dem Host-Detail
- [ ] Verbindungsaktionen für weitere Dienste im Host-Detail (Enter auf Port) – je Plattform entscheiden:
      RDP (3389), VNC (5900), SMB (445, Freigabe im Finder/Explorer); SSH mit Benutzername?
      (http, https, ssh per URL über den Standard-Handler gibt es bereits)

## Features

- [ ] Export der Watch-Ergebnisse
- [ ] Web-UI für den Watch-Modus
- [ ] Redraw der Tabelle bei wachsender Tabelle, Flaps-Spalte falsch – stammt aus der ANSI-UI, prüfen ob mit tview noch relevant

## Verbesserungen

- [ ] IPv6-Support
- [ ] mDNS/LLMNR zuverlässiger machen (manche Geräte antworten nicht)
- [ ] ICMP für RTT-Messung – ICMP-Modus über System-`ping` gibt es seit 0.1.0, prüfen ob die RTT daraus in allen Modi genutzt wird
