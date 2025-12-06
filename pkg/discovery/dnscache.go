package discovery

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// DNSCacheEntry represents a cached DNS entry
type DNSCacheEntry struct {
	IP       string
	Hostname string
}

// ReadDNSCache reads the system's DNS cache and returns IP->Hostname mappings
// WICHTIG: Liest nur Forward-DNS (A-Records), NICHT Reverse-DNS (PTR-Records)
// Damit kann man später im Details-Pane einen Reverse-Check machen und
// Inkonsistenzen erkennen (DNS-Spoofing, Hijacking, etc.)
func ReadDNSCache() map[string]string {
	cache := make(map[string]string)

	switch runtime.GOOS {
	case "windows":
		readWindowsDNSCache(cache)
	case "darwin":
		readDarwinDNSCache(cache)
	case "linux":
		readLinuxDNSCache(cache)
	}

	return cache
}

// readWindowsDNSCache parses output of "ipconfig /displaydns"
// Supports both English and German Windows versions
func readWindowsDNSCache(cache map[string]string) {
	cmd := exec.Command("ipconfig", "/displaydns")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	var currentRecordName string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse record name (hostname or reverse DNS name)
		// English: "Record Name . . . . . . . . . : hostname"
		// German:  "Eintragsname . . . . . : hostname"
		if strings.Contains(line, "Record Name") || strings.Contains(line, "Eintragsname") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				currentRecordName = strings.TrimSpace(parts[1])
				// Remove trailing dot
				currentRecordName = strings.TrimSuffix(currentRecordName, ".")
			}
			continue
		}

		// Parse A record (Forward DNS: hostname -> IP)
		// English: "A (Host) Record  . . . : 10.0.0.1"
		// German:  "(Host-)A-Eintrag  . . : 10.0.0.1"
		if strings.Contains(line, "A (Host) Record") || strings.Contains(line, "(Host-)A-Eintrag") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 && currentRecordName != "" {
				ipStr := strings.TrimSpace(parts[1])
				if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil {
					cache[ip.String()] = currentRecordName
					currentRecordName = "" // Reset for next record
				}
			}
			continue
		}

		// PTR-Records (Reverse DNS) werden ABSICHTLICH ignoriert!
		// Wir wollen nur Forward-Einträge, um später einen Reverse-Check
		// machen zu können und Inkonsistenzen zu erkennen.
	}
}

// readDarwinDNSCache reads DNS cache on macOS
func readDarwinDNSCache(cache map[string]string) {
	// macOS: dscacheutil -cachedump -entries Host
	cmd := exec.Command("dscacheutil", "-cachedump", "-entries", "Host")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	var currentName, currentIP string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "name:") {
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		} else if strings.HasPrefix(line, "ip_address:") {
			currentIP = strings.TrimSpace(strings.TrimPrefix(line, "ip_address:"))

			// Store mapping when we have both
			if currentName != "" && currentIP != "" {
				if ip := net.ParseIP(currentIP); ip != nil && ip.To4() != nil {
					cache[currentIP] = currentName
				}
			}
		}

		// Reset on empty line (new entry)
		if line == "" {
			currentName = ""
			currentIP = ""
		}
	}
}

// readLinuxDNSCache reads DNS cache on Linux
func readLinuxDNSCache(cache map[string]string) {
	// Linux with systemd-resolved
	cmd := exec.Command("resolvectl", "statistics")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try systemd-resolve (older command)
		cmd = exec.Command("systemd-resolve", "--statistics")
		output, err = cmd.Output()
		if err != nil {
			return
		}
	}

	// Note: systemd-resolved statistics don't show individual cache entries
	// We could also try: getent ahosts <hostname> but that requires knowing hostnames first
	// For now, Linux DNS cache reading is limited
	_ = output // Parse if format is available
}

// Note: PopulateFromDNSCache is implemented in cmd/watch.go
// since it depends on DeviceState which is defined there
