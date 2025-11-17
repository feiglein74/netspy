//go:build windows

package discovery

import (
	"net"
	"os/exec"
	"strings"
)

// QueryNetBIOSNameNative uses Windows nbtstat.exe command (Windows only)
// This is more reliable than UDP queries as it handles firewall/interface issues
func QueryNetBIOSNameNative(ip net.IP) (string, error) {
	// Use nbtstat -A <ip> to query NetBIOS name
	cmd := exec.Command("nbtstat", "-A", ip.String())
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse output for workstation name
	// Looking for lines like: "HOSTNAME    <00>  EINDEUTIG   Registriert"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and headers
		if line == "" || strings.Contains(line, "NetBIOS") || strings.Contains(line, "Name") || strings.Contains(line, "---") {
			continue
		}

		// Look for lines with <00> (workstation name) and EINDEUTIG/UNIQUE
		if strings.Contains(line, "<00>") && (strings.Contains(line, "EINDEUTIG") || strings.Contains(line, "UNIQUE")) {
			// Extract name (first field)
			fields := strings.Fields(line)
			if len(fields) > 0 {
				name := fields[0]
				// Filter out invalid names
				if name != "" && name != "__MSBROWSE__" && !strings.HasPrefix(name, "..") {
					return name, nil
				}
			}
		}
	}

	return "", nil // No error, just no name found
}
