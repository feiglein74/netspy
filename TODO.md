# NetSpy TODO

## High Priority

### 🎨 UI/UX Improvements
- [ ] **Responsive Tabellen für Watch-Mode implementieren**
  - Aktuell: Nur scan-Modus hat responsive Tabellen (3 Layouts: narrow/medium/wide)
  - Watch-Mode verwendet feste Tabellen-Breite
  - Herausforderung: ANSI-Escape-Codes für Live-Updates, dynamisches Zeilen-Tracking
  - Komplexität: Cursor-Positioning muss für jedes Layout neu berechnet werden
  - Terminal-Größen: < 100 cols (narrow), 100-139 (medium), >= 140 (wide)
  - Siehe: `pkg/output/table_responsive.go` für scan-Implementierung

### 🔴 Cross-Platform Critical Issues (v0.2.0)
- [ ] **Spinner-Fix auf Windows testen** (nach macOS-Fix)
  - ANSI-Escape-Codes statt Carriage Return
  - Verifizieren dass Windows 10+ funktioniert

### 🧪 Testing & Quality
- [ ] Fix failing tests (16 von 42 Tests schlagen fehl)
  - [ ] `GenerateIPsFromCIDR` - IP-Range-Logik (erwartet alle IPs inkl. Netz/Broadcast)
  - [ ] `DetectDeviceType` - Gibt leere Strings zurück statt Gerätetypen
  - [ ] `GetMACVendor` - MAC-Format-Handling (Dashes, ohne Separator)
  - [ ] `ScanARPTable` - Gibt nil statt leeres Array zurück
  - [ ] `Scanner.Scan` - Localhost-Detection schlägt fehl
- [ ] Linux vollständig testen (ARP, Gateway, Watch-Mode)

### ⚙️ Configuration
- [ ] Add configuration file support (.netspy.yaml)

## Features
- [ ] Add export functionality for watch mode results
- [ ] Implement alert system for offline devices
- [ ] Add web UI for watch mode
- [ ] Add HTTP banner grabbing for web services
- [ ] Correct Redraw of the Table if it Grows, the Region Flaps is wrong

## Improvements
- [ ] Add IPv6 support
- [ ] Cross-platform testing (Linux, macOS)
- [ ] ICMP ping support for RTT measurement (requires admin rights)
- [ ] Improve mDNS/LLMNR reliability (some devices don't respond)

## Done ✅

### v0.1.1 (2025-11-15)
- [x] **Plattformspezifische Gateway-Erkennung** - Windows, macOS, Linux Support
  - `gateway_windows.go`: `route print` für Windows
  - `gateway_darwin.go`: `route -n get default` für macOS
  - `gateway_linux.go`: `ip route` / `route -n` für Linux
  - Gateway-Marker [G] direkt an IP angehängt (z.B. "192.168.179.1 [G]")
- [x] **Responsive Tabellen für Scan-Mode** - 3 Layouts (narrow/medium/wide)
  - Terminal < 100 cols: Kompakte Ansicht (IP, Hostname kurz, RTT, MAC kurz)
  - Terminal 100-139 cols: Standard-Ansicht (+ Device Type)
  - Terminal >= 140 cols: Vollständige Ansicht (alle Spalten)
- [x] **Unicode-Ellipsis (…)** statt drei Punkte (...) bei Kürzungen
- [x] **Spaltenausrichtung korrigiert** - Header stimmt mit Datenspalten überein
- [x] **Watch-Mode Tabellen-Rendering Fix** - clearLine() für saubere Updates
- [x] **Automatischer Fallback für fremde Subnets**
  - ARP-Modus erkennt lokale vs. remote Subnets
  - Hybrid-Modus fällt auf TCP-Scan zurück bei Remote-Netzen
  - Informative Meldungen über verwendete Strategie

### v0.1.0 (2025-11-15)
- [x] **README.md, CHANGELOG.md erstellt** - Vollständige Projekt-Dokumentation
- [x] **Versionierung implementiert** - SemVer mit --version Flag/Command
- [x] **Git-Tag v0.1.0** - Initial Release markiert
- [x] **Spinner-Fix für macOS** - ANSI-Escape-Codes für Cross-Platform Kompatibilität
- [x] **Cross-Platform Analyse** - Vollständige Code-Review mit 4 Berichten in `docs/`
- [x] **Ginkgo/Gomega BDD Testing Framework** eingerichtet (11 Test-Dateien, 42 Specs)
- [x] **Plattformspezifische Tests** (Windows, macOS, Linux) mit Build-Tags
- [x] **Deutsche Code-Kommentare** in allen Dateien
- [x] **Network Auto-Detection** für watch command
- [x] **Unified Scan Mode Flags** (--mode statt separate Flags)
- [x] Static table watch mode with live updates
- [x] Hybrid ARP+ping scanning
- [x] Background DNS lookups with NetBIOS fallback
- [x] NetBIOS name queries for Windows hosts (RFC 1002)
- [x] ANSI cursor control for in-place table updates
- [x] Graceful shutdown with Ctrl+C
- [x] Real-time uptime/downtime tracking
- [x] Column alignment fix for online/offline status
- [x] Expand MAC vendor database (976+ OUI entries)
- [x] Fix hostname flickering with resolution caching
- [x] RTT (response time) measurement in watch mode
- [x] Flapping detection for unstable devices
- [x] Locally-administered MAC address visual indicator
- [x] --quiet flag for clean piped output
- [x] Remove redundant output summary
- [x] Multi-port RTT fallback for devices without standard services
- [x] **Device type detection** (Smartphone/Privacy, Computer, IoT, Network Equipment, etc.)
- [x] **mDNS/Bonjour support** for Apple/IoT devices
- [x] **LLMNR support** for Windows hostname resolution
- [x] **OS detection** based on open ports (Windows, Linux, Server detection)
