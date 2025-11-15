//go:build linux

package discovery

import (
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// GetDefaultGateway gibt die IP-Adresse des Default-Gateways zurück
func GetDefaultGateway() net.IP {
	// Linux: ip route show default OR route -n
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		// Fallback zu route -n
		cmd = exec.Command("route", "-n")
		output, err = cmd.Output()
		if err != nil {
			return nil
		}
	}

	// Parse output for gateway
	// ip route format: "default via 192.168.1.1 dev eth0"
	// route -n format: "0.0.0.0         192.168.1.1     0.0.0.0         UG    0      0        0 eth0"
	lines := strings.Split(string(output), "\n")

	// Regex für "ip route" Format
	ipRouteRegex := regexp.MustCompile(`^default\s+via\s+(\d+\.\d+\.\d+\.\d+)`)
	// Regex für "route -n" Format
	routeNRegex := regexp.MustCompile(`^0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)`)

	for _, line := range lines {
		// Try ip route format first
		matches := ipRouteRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			gateway := net.ParseIP(matches[1])
			if gateway != nil {
				return gateway
			}
		}

		// Try route -n format
		matches = routeNRegex.FindStringSubmatch(line)
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
