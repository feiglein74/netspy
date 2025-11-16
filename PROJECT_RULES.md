# Projekt-Grundregeln für NetSpy

Diese Regeln gelten für alle Arbeiten an diesem Projekt.

## Dokumentation

- ✅ **README.md** - Projektbeschreibung, Installation, Nutzung
- ✅ **TODO.md** - Aufgabenliste, Feature-Tracking
- ✅ **CHANGELOG.md** - Versionsverlauf mit Semantic Versioning (SemVer)

## Git-Konfiguration

- ✅ Git-Repository initialisiert
- ✅ `.gitignore` mit sinnvollen Excludes vorhanden

## Sprache & Kommunikation

### Chat-Kommunikation
**Du-Form** (informell)

Beispiel:
- ✅ "Ich habe die README erstellt..."
- ✅ "Du kannst jetzt..."

### Git-Commit-Messages
**Deutsch, Imperativ**

Beispiel:
- ✅ "Füge Authentifizierung hinzu"
- ✅ "Korrigiere Padding-Berechnung"
- ✅ "Implementiere Terminal-Resize-Detection"
- ❌ "Added authentication"
- ❌ "Authentifizierung hinzugefügt" (Partizip)

### Code-Kommentare
**Deutsch, sachlich/neutral** formuliert

Beispiel:
- ✅ "Berechnet den Durchschnittswert"
- ✅ "Dieser Wert wird für X verwendet"
- ✅ "Filtert Multicast-Adressen aus der ARP-Tabelle"
- ❌ "Du musst hier..."
- ❌ "Sie sollten..."

### Dokumentation (README, etc.)
**Deutsch, neutrale/Du-Form** je nach Kontext

README-Beispiel:
- ✅ "NetSpy ist ein modernes Netzwerk-Discovery-Tool"
- ✅ "Starte den Watch-Modus mit: `netspy watch ...`"

## Code-Änderungen

**WICHTIG**:
- ❌ Bestehende Codebase NICHT verändern ohne explizite Anfrage
- ✅ Nur Setup-Dateien (README, TODO, etc.) erstellen wenn nötig
- ❌ Code-Kommentare NICHT umformulieren oder ändern ohne Grund
- ✅ Neue Features nur nach Anfrage implementieren

## Background Process Management

Siehe `BACKGROUND_PROCESS_RULES.md` für vollständige Regeln.

**Kurzfassung**:
1. Vermeide Background-Prozesse
2. Temp-Dateien sofort aufräumen (`&&`)
3. Test-Skripte atomar: create && run && delete
4. Lange Prozesse dokumentieren & timeout setzen
5. Vor Session-Ende: Check & Cleanup

## Beispiele zur Klarstellung

### ✅ Richtig
```
Git-Commit: "Füge ARP-Scanner hinzu"
Code-Kommentar: "Berechnet den Durchschnittswert"
Chat: "Ich habe die README erstellt, du kannst sie jetzt lesen"
```

### ❌ Falsch
```
Git-Commit: "Added ARP scanner"
Code-Kommentar: "Du musst hier die Funktion aufrufen"
Chat: "Die README wurde erstellt, Sie können..." (zu formal)
```

## NetSpy-Spezifische Ergänzungen

### Plattformübergreifend
- Code muss auf **Windows, macOS, Linux** funktionieren
- Build-Tags nutzen für plattformspezifischen Code:
  - `//go:build unix` für macOS/Linux
  - `//go:build windows` für Windows
- Siehe `CROSS_PLATFORM_NOTES.md` für Testing-Matrix

### Testing
- Ginkgo/Gomega BDD Framework verwenden
- Tests vor JEDEM Commit ausführen: `go test ./...`
- Plattformspezifische Tests mit Build-Tags

### Terminals
- **Windows**: Windows Terminal, PowerShell, cmd.exe (funktioniert)
- **Git Bash**: ANSI-Limitierungen (dokumentiert, nicht empfohlen)
- Siehe `CLAUDE.md` für Terminal-spezifische Hinweise

## Compliance-Status

| Regel | Status | Datei |
|-------|--------|-------|
| README.md | ✅ | Vorhanden |
| TODO.md | ✅ | Vorhanden |
| CHANGELOG.md | ✅ | Vorhanden |
| .gitignore | ✅ | Vorhanden |
| Git-Commits Deutsch | ✅ | Verifiziert |
| Code-Kommentare Deutsch | ✅ | Verifiziert |
| Background Process Rules | ✅ | BACKGROUND_PROCESS_RULES.md |
| Cross-Platform Notes | ✅ | CROSS_PLATFORM_NOTES.md |

## Dokumenten-Hierarchie

```
NetSpy/
├── PROJECT_RULES.md                # Diese Datei - Übergeordnete Regeln
├── CLAUDE.md                       # Claude Code spezifische Anweisungen
├── BACKGROUND_PROCESS_RULES.md     # Universelle Prozess-Regeln
├── CROSS_PLATFORM_NOTES.md         # Plattform-Kompatibilität
├── README.md                       # Projekt-Dokumentation
├── CHANGELOG.md                    # Versions-Historie
└── TODO.md                         # Feature-Tracking
```

## Bei Unsicherheit

**Frage nach**, bevor du:
- Bestehenden Code änderst
- Neue Features implementierst
- Architektur-Entscheidungen triffst
- Größere Refactorings durchführst

**Dokumentiere** immer:
- Neue Features im CHANGELOG.md
- Bekannte Probleme in TODO.md oder CROSS_PLATFORM_NOTES.md
- API-Änderungen im README.md
