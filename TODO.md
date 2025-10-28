# NetSpy TODO

## High Priority
- [ ] Add configuration file support (.netspy.yaml)

## Features
- [ ] Add export functionality for watch mode results
- [ ] Implement alert system for offline devices
- [ ] Add web UI for watch mode
- [ ] Add mDNS/Bonjour support for Apple/IoT devices
- [ ] Add HTTP banner grabbing for web services

## Improvements
- [ ] Add IPv6 support
- [ ] Cross-platform testing (Linux, macOS)

## Done ✅
- [x] Static table watch mode with live updates
- [x] Hybrid ARP+ping scanning
- [x] Background DNS lookups with NetBIOS fallback
- [x] NetBIOS name queries for Windows hosts (RFC 1002)
- [x] ANSI cursor control for in-place table updates
- [x] Graceful shutdown with Ctrl+C
- [x] Real-time uptime/downtime tracking
- [x] Column alignment fix for online/offline status
- [x] Expand MAC vendor database (900+ OUI entries)
- [x] Fix hostname flickering with resolution caching
