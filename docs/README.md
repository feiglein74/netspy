# NetSpy Dokumentation

Willkommen zur NetSpy-Dokumentation. Hier findest du alle technischen Dokumente und Analysen.

## 📚 Dokumentations-Übersicht

### Haupt-Dokumentation (Root)
- [../README.md](../README.md) - Projekt-Hauptdokumentation, Installation, Usage
- [../CHANGELOG.md](../CHANGELOG.md) - Versionshistorie und Release-Notes
- [../TODO.md](../TODO.md) - Geplante Features, Bugfixes, Roadmap
- [../CLAUDE.md](../CLAUDE.md) - Claude Code Präferenzen und Entwicklungs-Workflow

## 🖥️ Cross-Platform Dokumentation

### Schnellstart
**Neu hier?** Start mit: [PLATFORM_COMPATIBILITY.md](./PLATFORM_COMPATIBILITY.md)

### Vollständige Cross-Platform Analyse

#### 1. [PLATFORM_COMPATIBILITY.md](./PLATFORM_COMPATIBILITY.md) 📋
**Status-Übersicht und Action Items**
- Aktuelle Kompatibilitätsmatrix (Windows/macOS/Linux)
- Kritische Probleme und Lösungen
- Action Items nach Priorität
- Links zu allen Detail-Dokumenten

#### 2. [CROSS_PLATFORM_SUMMARY.txt](./CROSS_PLATFORM_SUMMARY.txt) 📊
**Executive Summary (5 Minuten)**
- Schnelle Übersicht für Projekt-Manager
- Bewertung: B+ (GUT mit kritischer Lücke)
- High-Level Problembeschreibungen

#### 3. [CROSS_PLATFORM_ANALYSIS.md](./CROSS_PLATFORM_ANALYSIS.md) 🔍
**Detaillierte technische Analyse**
- Feature-für-Feature Breakdown
- Plattformspezifische Implementierungen
- Build-Tag Audit
- Ausführliche Problembeschreibungen mit Code-Beispielen

#### 4. [CROSS_PLATFORM_CODE_REFERENCE.md](./CROSS_PLATFORM_CODE_REFERENCE.md) 💻
**Entwickler-Referenz während Implementierung**
- Code-Snippets für jede Plattform
- Datei-Referenzen und Zeilennummern
- Best Practices
- Implementierungs-Beispiele

#### 5. [CROSS_PLATFORM_README.md](./CROSS_PLATFORM_README.md) 🗺️
**Original Navigation zwischen Berichten**
- Erste Orientierung in der Cross-Platform-Dokumentation

## 🎯 Use Cases

### "Ich will nur wissen, was nicht funktioniert"
→ Lies [PLATFORM_COMPATIBILITY.md](./PLATFORM_COMPATIBILITY.md) - Kompatibilitätsmatrix anschauen

### "Ich muss Gateway-Erkennung für macOS implementieren"
→ Start: [PLATFORM_COMPATIBILITY.md](./PLATFORM_COMPATIBILITY.md) → Problem #1
→ Details: [CROSS_PLATFORM_ANALYSIS.md](./CROSS_PLATFORM_ANALYSIS.md#gateway-detection)
→ Code: [CROSS_PLATFORM_CODE_REFERENCE.md](./CROSS_PLATFORM_CODE_REFERENCE.md)

### "Ich brauche einen Überblick für ein Meeting"
→ Lies [CROSS_PLATFORM_SUMMARY.txt](./CROSS_PLATFORM_SUMMARY.txt) (5 Min)

### "Ich entwickle ein neues plattformspezifisches Feature"
→ [CROSS_PLATFORM_CODE_REFERENCE.md](./CROSS_PLATFORM_CODE_REFERENCE.md) - Best Practices

## 🚨 Wichtige Erkenntnisse

### Kritisches Problem (HIGH PRIORITY)
**Gateway-Erkennung funktioniert nur auf Windows**
- Betroffen: macOS, Linux
- Datei: `pkg/discovery/gateway.go`
- Auswirkung: Kein Gateway-Marker `[G]` im Watch-Modus
- Lösung: Plattformspezifische Implementierungen benötigt

**Details:** Siehe [PLATFORM_COMPATIBILITY.md](./PLATFORM_COMPATIBILITY.md)

## 📖 Weitere Themen (zukünftig)

Hier werden weitere Dokumentationen abgelegt:
- Architecture Deep-Dives
- API-Dokumentation
- Entwickler-Guides
- Performance-Analysen

## 🔄 Wartung

**Dieses Verzeichnis aktualisieren bei:**
- Neuen technischen Dokumenten
- Cross-Platform Änderungen
- Architektur-Updates
- Major/Minor Releases

---

**Erstellt:** 2025-11-15
**Version:** 0.1.0
**Maintainer:** Projekt-Team
