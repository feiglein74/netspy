# NetSpy TODO

## High Priority
- [ ] Add configuration file support (.netspy.yaml)

## Features
- [ ] Add export functionality for watch mode results
- [ ] Implement alert system for offline devices
- [ ] Add web UI for watch mode
- [ ] Add mDNS/Bonjour support for Apple/IoT devices
- [ ] Add HTTP banner grabbing for web services
- [ ] OS detection based on open ports (445/135 → Windows, 22 → Linux/Unix, 3389 → RDP)

## Improvements
- [ ] Add IPv6 support
- [ ] Cross-platform testing (Linux, macOS)
- [ ] ICMP ping support for RTT measurement (requires admin rights)

## Done ✅
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
