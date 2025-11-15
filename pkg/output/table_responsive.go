package output

import (
	"fmt"
	"strings"

	"netspy/pkg/scanner"

	"github.com/fatih/color"
)

// printResponsiveHybridTable gibt Hybrid-Scan-Ergebnisse responsive aus
func printResponsiveHybridTable(hosts []scanner.Host, termSize TerminalSize) error {
	if termSize.IsNarrow() {
		return printNarrowHybridTable(hosts, termSize)
	} else if termSize.IsMedium() {
		return printMediumHybridTable(hosts, termSize)
	} else {
		return printWideHybridTable(hosts, termSize)
	}
}

// printNarrowHybridTable - Kompakte Ansicht für schmale Terminals (< 100 cols)
func printNarrowHybridTable(hosts []scanner.Host, termSize TerminalSize) error {
	// Header: IP, Hostname (kurz), RTT, MAC (kurz)
	color.Cyan("%-15s %-18s %-7s %-15s\n",
		"IP", "Hostname", "RTT", "MAC")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 60)))

	for _, host := range hosts {
		// IP (ggf. mit Gateway-Marker)
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " G"
		}
		if len(ipStr) > 15 {
			ipStr = ipStr[:15]
		}

		// Hostname (gekürzt)
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		if len(hostname) > 16 {
			hostname = hostname[:13] + "…"
		}

		// RTT
		rtt := "-"
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.0fms", float64(host.RTT.Microseconds())/1000.0)
		}

		// MAC (gekürzt - nur letzten Teil)
		mac := host.MAC
		if mac == "" {
			mac = "-"
		} else if len(mac) > 15 {
			// Zeige nur letzten Teil der MAC (z.B. "…c8:26:03:8c")
			parts := strings.Split(mac, ":")
			if len(parts) >= 3 {
				mac = "…" + strings.Join(parts[len(parts)-3:], ":")
			}
		}

		fmt.Printf("%-15s %-18s %-7s %-15s\n",
			ipStr,
			hostname,
			rtt,
			mac,
		)
	}

	fmt.Println()
	return nil
}

// printMediumHybridTable - Standard-Ansicht für mittlere Terminals (100-139 cols)
func printMediumHybridTable(hosts []scanner.Host, termSize TerminalSize) error {
	// Header: IP, Hostname, RTT, MAC, Device Type
	color.Cyan("%-16s %-24s %-8s %-18s %-18s\n",
		"IP Address", "Hostname", "RTT", "MAC Address", "Device Type")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 90)))

	for _, host := range hosts {
		// IP (mit Gateway-Marker)
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " [G]"
		}

		// Hostname
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		if len(hostname) > 22 {
			hostname = hostname[:19] + "…"
		}

		// RTT
		rtt := "-"
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.0fms", float64(host.RTT.Microseconds())/1000.0)
		}

		// MAC
		mac := host.MAC
		if mac == "" {
			mac = "-"
		}

		// Device Type / Vendor
		deviceInfo := host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = host.Vendor
		}
		if deviceInfo == "" {
			deviceInfo = "-"
		}
		if len(deviceInfo) > 16 {
			deviceInfo = deviceInfo[:13] + "…"
		}

		fmt.Printf("%-16s %-24s %-8s %-18s %-18s\n",
			ipStr,
			hostname,
			rtt,
			mac,
			deviceInfo,
		)
	}

	fmt.Println()
	return nil
}

// printWideHybridTable - Volle Ansicht für breite Terminals (>= 140 cols)
func printWideHybridTable(hosts []scanner.Host, termSize TerminalSize) error {
	// Header: Alles
	color.Cyan("%-20s %-30s %-8s %-18s %-20s %-25s %-12s\n",
		"IP Address", "Hostname", "RTT", "MAC Address", "Device Type", "HTTP Banner", "Ports")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 140)))

	for _, host := range hosts {
		// IP (mit Gateway-Marker)
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " [G]"
		}

		// Hostname
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		if len(hostname) > 28 {
			hostname = hostname[:25] + "…"
		}

		// RTT
		rtt := "-"
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.0fms", float64(host.RTT.Microseconds())/1000.0)
		}

		// MAC
		mac := host.MAC
		if mac == "" {
			mac = "-"
		}

		// Device Type / Vendor
		deviceInfo := host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = host.Vendor
		}
		if deviceInfo == "" {
			deviceInfo = "-"
		}
		if len(deviceInfo) > 18 {
			deviceInfo = deviceInfo[:15] + "…"
		}

		// HTTP Banner
		httpBanner := host.HTTPBanner
		if httpBanner == "" {
			httpBanner = "-"
		}
		if len(httpBanner) > 23 {
			httpBanner = httpBanner[:20] + "…"
		}

		// Ports
		ports := "-"
		if len(host.Ports) > 0 {
			portStrs := make([]string, len(host.Ports))
			for i, p := range host.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			ports = strings.Join(portStrs, ",")
			if len(ports) > 10 {
				ports = ports[:10] + "…"
			}
		}

		fmt.Printf("%-20s %-30s %-8s %-18s %-20s %-25s %-12s\n",
			ipStr,
			hostname,
			rtt,
			mac,
			deviceInfo,
			httpBanner,
			ports,
		)
	}

	fmt.Println()
	return nil
}

// min Hilfsfunktion
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
