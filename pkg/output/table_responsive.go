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

		// Hostname (mit Truncate-Funktion für Opt-in Kürzung)
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 16)

		// RTT
		rtt := "-"
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.0fms", float64(host.RTT.Microseconds())/1000.0)
		}

		// MAC (mit TruncateMAC für Opt-in Kürzung)
		mac := host.MAC
		if mac == "" {
			mac = "-"
		} else {
			mac = TruncateMAC(mac, 15)
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

		// Hostname (mit Truncate für Opt-in Kürzung)
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 22)

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

		// Device Type / Vendor (mit Truncate für Opt-in Kürzung)
		deviceInfo := host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = host.Vendor
		}
		if deviceInfo == "" {
			deviceInfo = "-"
		}
		deviceInfo = Truncate(deviceInfo, 16)

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

		// Hostname (mit Truncate für Opt-in Kürzung)
		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 28)

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

		// Device Type / Vendor (mit Truncate für Opt-in Kürzung)
		deviceInfo := host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = host.Vendor
		}
		if deviceInfo == "" {
			deviceInfo = "-"
		}
		deviceInfo = Truncate(deviceInfo, 18)

		// HTTP Banner (mit Truncate für Opt-in Kürzung)
		httpBanner := host.HTTPBanner
		if httpBanner == "" {
			httpBanner = "-"
		}
		httpBanner = Truncate(httpBanner, 23)

		// Ports (mit Truncate für Opt-in Kürzung)
		ports := "-"
		if len(host.Ports) > 0 {
			portStrs := make([]string, len(host.Ports))
			for i, p := range host.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			ports = strings.Join(portStrs, ",")
			ports = Truncate(ports, 10)
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

// printResponsivePingTable gibt Ping-Scan-Ergebnisse responsive aus
func printResponsivePingTable(hosts []scanner.Host, termSize TerminalSize) error {
	if termSize.IsNarrow() {
		return printNarrowPingTable(hosts, termSize)
	} else {
		return printWidePingTable(hosts, termSize)
	}
}

// printNarrowPingTable - Kompakte Ping-Ansicht
func printNarrowPingTable(hosts []scanner.Host, termSize TerminalSize) error {
	color.Cyan("%-15s %-20s %-8s\n", "IP", "Hostname", "RTT")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 50)))

	for _, host := range hosts {
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " G"
		}

		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 18)

		rtt := "-"
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.0fms", float64(host.RTT.Microseconds())/1000.0)
		}

		fmt.Printf("%-15s %-20s %-8s\n", ipStr, hostname, rtt)
	}

	fmt.Println()
	return nil
}

// printWidePingTable - Volle Ping-Ansicht
func printWidePingTable(hosts []scanner.Host, termSize TerminalSize) error {
	color.Cyan("%-20s %-35s %-10s\n", "IP Address", "Hostname", "RTT")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 70)))

	for _, host := range hosts {
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " [G]"
		}

		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 33)

		rtt := "-"
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.2fms", float64(host.RTT.Microseconds())/1000.0)
		}

		fmt.Printf("%-20s %-35s %-10s\n", ipStr, hostname, rtt)
	}

	fmt.Println()
	return nil
}

// printResponsiveARPTable gibt ARP-Scan-Ergebnisse responsive aus
func printResponsiveARPTable(hosts []scanner.Host, termSize TerminalSize) error {
	if termSize.IsNarrow() {
		return printNarrowARPTable(hosts, termSize)
	} else if termSize.IsMedium() {
		return printMediumARPTable(hosts, termSize)
	} else {
		return printWideARPTable(hosts, termSize)
	}
}

// printNarrowARPTable - Kompakte ARP-Ansicht
func printNarrowARPTable(hosts []scanner.Host, termSize TerminalSize) error {
	color.Cyan("%-15s %-18s %-15s\n", "IP", "Hostname", "MAC")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 55)))

	for _, host := range hosts {
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " G"
		}
		if len(ipStr) > 15 {
			ipStr = ipStr[:15]
		}

		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 16)

		mac := host.MAC
		if mac == "" {
			mac = "-"
		} else {
			mac = TruncateMAC(mac, 15)
		}

		fmt.Printf("%-15s %-18s %-15s\n", ipStr, hostname, mac)
	}

	fmt.Println()
	return nil
}

// printMediumARPTable - Mittlere ARP-Ansicht
func printMediumARPTable(hosts []scanner.Host, termSize TerminalSize) error {
	color.Cyan("%-20s %-25s %-18s %-18s\n",
		"IP Address", "Hostname", "MAC Address", "Device Type")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 90)))

	for _, host := range hosts {
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " [G]"
		}

		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 23)

		mac := host.MAC
		if mac == "" {
			mac = "-"
		}

		deviceInfo := host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = host.Vendor
		}
		if deviceInfo == "" {
			deviceInfo = "-"
		}
		deviceInfo = Truncate(deviceInfo, 16)

		fmt.Printf("%-20s %-25s %-18s %-18s\n",
			ipStr, hostname, mac, deviceInfo)
	}

	fmt.Println()
	return nil
}

// printWideARPTable - Volle ARP-Ansicht
func printWideARPTable(hosts []scanner.Host, termSize TerminalSize) error {
	color.Cyan("%-20s %-30s %-18s %-25s\n",
		"IP Address", "Hostname", "MAC Address", "Device Type / Vendor")
	color.White("%s\n", strings.Repeat("-", min(termSize.GetDisplayWidth(), 100)))

	for _, host := range hosts {
		ipStr := host.IP.String()
		if host.IsGateway {
			ipStr = ipStr + " [G]"
		}

		hostname := host.Hostname
		if hostname == "" {
			hostname = "-"
		}
		hostname = Truncate(hostname, 28)

		mac := host.MAC
		if mac == "" {
			mac = "-"
		}

		deviceInfo := host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = host.Vendor
		}
		if deviceInfo == "" {
			deviceInfo = "-"
		}
		deviceInfo = Truncate(deviceInfo, 23)

		fmt.Printf("%-20s %-30s %-18s %-25s\n",
			ipStr, hostname, mac, deviceInfo)
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
