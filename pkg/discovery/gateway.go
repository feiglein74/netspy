package discovery

import (
	"net"
	"os/exec"
	"regexp"
	"strings"
)

// GetDefaultGateway gibt die IP-Adresse des Default-Gateways zurück
func GetDefaultGateway() net.IP {
	// Windows: route print or ipconfig
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Parse output for default route
	// Windows format: "0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.100     35"
	lines := strings.Split(string(output), "\n")
	defaultRouteRegex := regexp.MustCompile(`0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)`)

	for _, line := range lines {
		matches := defaultRouteRegex.FindStringSubmatch(line)
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
