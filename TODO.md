# NetSpy TODO

## High Priority

### 🔴 Cross-Platform Critical Issues (v0.2.0)
- [ ] **Gateway-Erkennung für macOS implementieren** (KRITISCH)
  - Aktuell: Nur Windows unterstützt (`route print 0.0.0.0`)
  - Lösung: `netstat -rn` oder `route get default` verwenden
  - Siehe: `docs/PLATFORM_COMPATIBILITY.md`
- [ ] **Gateway-Erkennung für Linux implementieren** (KRITISCH)
  - Aktuell: Nur Windows unterstützt
  - Lösung: `ip route` oder `/proc/net/route` verwenden
  - Siehe: `docs/PLATFORM_COMPATIBILITY.md`
- [ ] **Build-Tags zu gateway.go hinzufügen**
  - Dateien: `gateway_windows.go`, `gateway_darwin.go`, `gateway_linux.go`
  - Error-Logging für fehlgeschlagene Gateway-Erkennung
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
- [x] **Gateway marker** (G indicator for default gateway)
