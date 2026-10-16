# Platform Compatibility Guide

**NetSpy Multi-Plattform-Unterstützung**
Version: 0.1.0
Letzte Aktualisierung: 2025-11-15

---

## Schnellübersicht

NetSpy ist ein Cross-Platform Netzwerk-Discovery-Tool mit Unterstützung für:
- ✅ Windows (getestet)
- ✅ macOS (getestet)
- ⏸️ Linux (geplant, noch nicht vollständig getestet)

## Aktuelle Kompatibilität

| Feature | Windows | macOS | Linux | Status |
|---------|---------|-------|-------|--------|
| ARP Scanning | ✅ Vollständig | ✅ Vollständig | ✅ Implementiert* | Getestet (Win/Mac) |
| TCP Ping | ✅ Vollständig | ✅ Vollständig | ✅ Vollständig | Pure Go |
| Gateway Detection | ✅ Vollständig | ❌ **Fehlt** | ❌ **Fehlt** | **KRITISCH** |
| Hostname (DNS) | ✅ Vollständig | ✅ Vollständig | ✅ Vollständig | Standard Library |
| Hostname (mDNS) | ✅ Vollständig | ✅ Vollständig | ✅ Vollständig | Pure Go |
| Hostname (NetBIOS) | ✅ Primär | ⚠️ Fallback | ⚠️ Fallback | Windows-optimiert |
| Watch Mode | ✅ Vollständig | ✅ Vollständig | ✅ Vollständig | ANSI Codes |
| Terminal Spinner | ✅ Vollständig | ✅ Gefixt (v0.1.0) | ✅ Vollständig | ANSI Codes |

\* Linux-ARP ist implementiert aber noch nicht in Produktion getestet

## 🔴 Kritische Probleme

### Problem #1: Gateway-Erkennung (HIGH PRIORITY)

**Betroffen:** macOS, Linux
**Datei:** `pkg/discovery/gateway.go`

**Beschreibung:**
Die Gateway-Erkennung verwendet aktuell `route print 0.0.0.0`, was nur unter Windows funktioniert. Auf macOS und Linux schlägt die Funktion stillschweigend fehl.

**Auswirkung:**
- Der Gateway-Marker `[G]` im Watch-Mode fehlt auf macOS/Linux
- Keine Fehlermeldung für Benutzer

**Lösung:**
Plattformspezifische Implementierungen erstellen:

```
pkg/discovery/
├── gateway.go           # Interface/Common Code
├── gateway_windows.go   # route print 0.0.0.0
├── gateway_darwin.go    # netstat -rn | route get default
└── gateway_linux.go     # ip route | /proc/net/route
```

**Siehe:** [CROSS_PLATFORM_ANALYSIS.md](./CROSS_PLATFORM_ANALYSIS.md#gateway-detection)

## 📋 Dokumentations-Index

Alle Cross-Platform Analysen und Referenzen:

### 1. [CROSS_PLATFORM_SUMMARY.txt](./CROSS_PLATFORM_SUMMARY.txt)
**Zweck:** Schnelle Executive Summary
**Für:** Projekt-Manager, Quick Reference
**Inhalt:** 5-Minuten-Überblick über Status und Probleme

### 2. [CROSS_PLATFORM_ANALYSIS.md](./CROSS_PLATFORM_ANALYSIS.md)
**Zweck:** Detaillierte technische Analyse
**Für:** Entwickler, die Probleme beheben
**Inhalt:**
- Feature-für-Feature Analyse
- Plattformspezifische Implementierungen
- Build-Tag Audit
- Detaillierte Problembeschreibungen

### 3. [CROSS_PLATFORM_CODE_REFERENCE.md](./CROSS_PLATFORM_CODE_REFERENCE.md)
**Zweck:** Entwickler-Referenzleitfaden
**Für:** Während der Implementierung
**Inhalt:**
- Code-Snippets für jede Plattform
- Datei-Referenzen
- Implementierungs-Beispiele
- Best Practices

### 4. [CROSS_PLATFORM_README.md](./CROSS_PLATFORM_README.md)
**Zweck:** Navigation zwischen den Berichten
**Für:** Erste Orientierung
**Inhalt:** Übersicht und Links zu allen Dokumenten

## 🎯 Action Items

### HIGH PRIORITY (vor v0.2.0)
- [ ] Gateway-Erkennung für Linux implementieren
- [ ] Gateway-Erkennung für macOS implementieren
- [ ] Build-Tags zu `gateway.go` hinzufügen
- [ ] Error-Logging für fehlgeschlagene Gateway-Erkennung

### MEDIUM PRIORITY
- [ ] Linux-Support vollständig testen
- [ ] `//go:build windows` zu `netbios.go` hinzufügen
- [ ] Plattform-Limitierungen in User-Dokumentation aufnehmen

### LOW PRIORITY
- [ ] CI/CD Testing auf allen Plattformen
- [ ] Pure Go Alternative zu System-Befehlen evaluieren

## 🧪 Testing-Status

| Plattform | Getestet | Version | Letzte Prüfung |
|-----------|----------|---------|----------------|
| Windows 10+ | ✅ | v0.1.0 | 2025-11-15 |
| macOS 14+ | ✅ | v0.1.0 | 2025-11-15 |
| Linux | ⏸️ | - | Ausstehend |

**macOS Bekannte Probleme:**
- ✅ Spinner-Ausgabe (behoben in v0.1.0)
- ❌ Gateway-Erkennung (fehlt)

**Linux Bekannte Probleme:**
- ❌ Gateway-Erkennung (fehlt)
- ⏸️ Vollständiger Test ausstehend

## 📚 Weitere Ressourcen

- [README.md](../README.md) - Projekt-Hauptdokumentation
- [CHANGELOG.md](../CHANGELOG.md) - Versionshistorie
- [TODO.md](../TODO.md) - Geplante Features und Bugfixes
- [DEVELOPMENT.md](../DEVELOPMENT.md) - Entwicklung, Tests, Stolperfallen

## 🔄 Wartung dieses Dokuments

**Aktualisieren bei:**
- Neuen Plattform-Features
- Behobenen Cross-Platform-Bugs
- Neuen Test-Ergebnissen
- Breaking Changes in Plattform-APIs

**Verantwortlich:** Projekt-Maintainer
**Review-Zyklus:** Bei jedem Minor/Major Release

---

**Erstellt von:** Claude Code Agent
**Datum:** 2025-11-15
**Basis:** Automatische Code-Analyse mit Explore Agent
