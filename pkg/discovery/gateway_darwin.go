//go:build darwin

package discovery

import (
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// GetDefaultGateway gibt die IP-Adresse des Default-Gateways zurück
func GetDefaultGateway() net.IP {
	// macOS: route -n get default
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse output for gateway line
	// macOS format: "   gateway: 192.168.1.1"
	lines := strings.Split(string(output), "\n")
	gatewayRegex := regexp.MustCompile(`^\s*gateway:\s+(\d+\.\d+\.\d+\.\d+)`)

	for _, line := range lines {
		matches := gatewayRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			gateway := net.ParseIP(matches[1])
			if gateway != nil {
				return gateway
			}
		}
	}

	return nil
}

// IsGateway prüft ob die angegebene IP das Default-Gateway ist
func IsGateway(ip net.IP) bool {
	gateway := GetDefaultGateway()
	if gateway == nil {
		return false
	}
	return ip.Equal(gateway)
}
