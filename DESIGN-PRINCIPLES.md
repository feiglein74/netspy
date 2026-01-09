# Design-Prinzipien für NetSpy

> **Zweck**: Diese Datei dokumentiert fundamentale Design-Entscheidungen des Projekts.
> Änderungen an diesen Prinzipien erfordern Team-Diskussion.

## Leitprinzipien

### 1. Vollständigkeit vor Kürze (Default = Alles zeigen)

**Grundregel**: Zeige standardmäßig ALLE Informationen. Kürzungen nur auf explizite Anfrage.

```go
// ❌ FALSCH - Automatisches Kürzen
func formatHostname(name string) string {
    if len(name) > 20 {
        return name[:17] + "..."
    }
    return name
}

// ✅ RICHTIG - Default = vollständig, Opt-in für Kürzung
func formatHostname(name string, maxLen int) string {
    if maxLen > 0 && len(name) > maxLen {
        return name[:maxLen-3] + "..."
    }
    return name
}
```

**Warum?**
- Informationsverlust vermeiden (kritisch für Netzwerk-Debugging)
- Principle of Least Surprise (User erwartet vollständige Daten)
- Sichere Defaults (keine versteckten Datenverluste)

---

### 2. Opt-in statt Opt-out für Einschränkungen

**Regel**: Wer Einschränkungen will (Kürzung, Filterung, Limitierung), muss sie EXPLIZIT aktivieren.

```bash
# ❌ FALSCH - Opt-out (User muss "volle Ausgabe" fordern)
netspy scan 10.0.0.0/24 --full-output

# ✅ RICHTIG - Opt-in (User muss "Kürzung" fordern)
netspy scan 10.0.0.0/24 --truncate 80
```

**Anwendung auf NetSpy:**
- Scan-Ausgaben: Vollständige Daten, keine automatische Kürzung
- Hostnames: Volle Länge, Kürzung nur bei explizitem Flag
- MAC-Adressen: Immer vollständig (17 Zeichen)
- Banner/Titel: Vollständig, mit optionaler Kürzung

---

### 3. Transparenz bei Modifikationen

**Regel**: Wenn Daten gekürzt/gefiltert/transformiert werden, MUSS das sichtbar sein.

```go
// ❌ FALSCH - Versteckte Kürzung
hostname = hostname[:20] + "..."
// User weiß nicht: Endet der Name mit "..." oder wurde gekürzt?

// ✅ RICHTIG - Transparente Kürzung
hostname = hostname[:20] + fmt.Sprintf("... [+%d]", len(original)-20)
// Klar: Es fehlen X Zeichen!
```

**Beispiele für Transparenz:**
- Strings: `"hostname.local... [+15 chars]"`
- Listen: `"22, 80, 443 [+5 ports]"`
- Limits: `"Scanning 50 of 254 hosts (use --all for full scan)"`

---

### 4. Explizit vor Implizit

**Regel**: Keine versteckten Defaults, die Daten verändern.

```go
// ❌ FALSCH - Implizites Limit
func RefreshARPTable(ips []string) {
    if len(ips) > 50 {
        ips = ips[:50]  // Verstecktes Limit!
    }
    // ...
}

// ✅ RICHTIG - Explizite Kontrolle
func RefreshARPTable(ips []string, maxHosts int) {
    if maxHosts > 0 && len(ips) > maxHosts {
        fmt.Printf("Limiting ARP refresh to %d hosts (use --all for full refresh)\n", maxHosts)
        ips = ips[:maxHosts]
    }
    // ...
}
```

**Test-Kriterium**: "Wird ein Entwickler/User überrascht sein?"
- Wenn JA → Design ändern
- Wenn NEIN → Design ist gut

---

### 5. Sichere Defaults

**Regel**: Default-Verhalten sollte keine Datenverluste oder unerwartete Einschränkungen haben.

**Sichere Defaults für NetSpy:**
- ✅ Vollständige Scan-Ausgabe
- ✅ Alle Host-Eigenschaften sichtbar
- ✅ Vollständige MAC-Adressen
- ✅ Vollständige Hostnames
- ✅ Alle entdeckten Ports anzeigen

**Unsichere Defaults (zu vermeiden):**
- ❌ Automatische Hostname-Kürzung
- ❌ Automatische Banner-Kürzung
- ❌ Versteckte IP-Limits bei ARP-Scan
- ❌ Automatisches Weglassen von Ports

---

## Projekt-spezifische Entscheidungen

### Terminal-Breite und responsive Ausgabe

**Entscheidung**: Responsive Tabellen passen sich der Terminal-Breite an.

**Begründung**:
- Schmale Terminals (< 100 cols) können nicht alle Spalten anzeigen
- ABER: Kürzung muss transparent sein (mit Ellipsis)
- ABER: `--full-output` Flag muss volle Daten zeigen können

**Implementierung:**
```go
// Terminal-responsive Kürzung ist OK, wenn:
// 1. Ellipsis zeigt dass gekürzt wurde
// 2. --full-output Flag existiert für volle Daten
// 3. JSON/CSV Export immer vollständige Daten liefert
```

### ARP-Scan Limits

**Entscheidung**: ARP-Refresh kann auf große Netzwerke limitiert werden.

**Begründung**:
- /16 Netzwerke haben 65k Hosts - alle pingen wäre Spam
- ABER: Limit muss transparent kommuniziert werden
- ABER: `--all` Flag muss volle Scans ermöglichen

### Scan-Modi

**Entscheidung**: Verschiedene Scan-Modi für unterschiedliche Anwendungsfälle.

| Modus | Verhalten | Use Case |
|-------|-----------|----------|
| default | Konservativ, zuverlässig | Alltägliche Scans |
| fast | Schnell, kann Hosts übersehen | Schnelle Übersicht |
| thorough | Gründlich, mehr False Positives | Vollständige Inventur |
| arp | Nur lokales Netzwerk | Genaue lokale Discovery |
| hybrid | ARP + Details | Beste Kombination |

---

## Merksätze

> **"Der Default ist die Wahrheit, Einschränkungen sind explizit."**

> **"Wenn du kürzt, sag es laut."**

> **"Lieber zu viel Information als zu wenig."**

---

## Bekannte Abweichungen (TODO)

Die folgenden Stellen im Code verstoßen aktuell noch gegen diese Prinzipien:

- `pkg/discovery/http.go:159-185` - Automatische Banner/Title-Kürzung
- `pkg/discovery/arp.go:287-289` - Verstecktes 50-IP-Limit
- `pkg/output/table_responsive.go` - Automatische Hostname-Kürzung
- `pkg/discovery/vendor_learn.go:177-202` - Automatische Vendor-Kürzung

Siehe `TODO.md` → "Projektregeln-Compliance" für den Behebungsplan.
