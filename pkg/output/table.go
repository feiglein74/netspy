package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"netspy/pkg/discovery"
	"netspy/pkg/scanner"

	"github.com/fatih/color"
)

// PrintResults outputs scan results in the specified format
func PrintResults(hosts []scanner.Host, format string) error {
	// Filter only online hosts
	var onlineHosts []scanner.Host
	for _, host := range hosts {
		if host.Online {
			onlineHosts = append(onlineHosts, host)
		}
	}

	// Sort by IP address
	sort.Slice(onlineHosts, func(i, j int) bool {
		return onlineHosts[i].IP.String() < onlineHosts[j].IP.String()
	})

	switch strings.ToLower(format) {
	case "json":
		return printJSON(onlineHosts)
	case "csv":
		return printCSV(onlineHosts)
	case "table":
		fallthrough
	default:
		return printSimpleTable(onlineHosts, len(hosts))
	}
}

func printSimpleTable(hosts []scanner.Host, totalScanned int) error {
	if len(hosts) == 0 {
		color.Red("❌ No active hosts found (scanned %d addresses)\n", totalScanned)
		return nil
	}

	// Check what data we have
	hasMAC := false
	hasRTT := false

	for _, host := range hosts {
		if host.MAC != "" {
			hasMAC = true
		}
		if host.RTT > 0 {
			hasRTT = true
		}
	}

	// Hybrid mode: show everything
	if hasMAC && hasRTT {
		color.Cyan("%-20s %-30s %-8s %-18s %-20s %-25s %-12s\n",
			"IP Address", "Hostname", "RTT", "MAC Address", "Device Type", "HTTP Banner", "Ports")
		color.White("%s\n", strings.Repeat("-", 140))

		for _, host := range hosts {
			hostname := host.Hostname
			if hostname == "" {
				hostname = "-"
			}
			// Truncate long hostnames
			if len(hostname) > 28 {
				hostname = hostname[:25] + "..."
			}

			rtt := "-"
			if host.RTT > 0 {
				rtt = fmt.Sprintf("%.0fms", float64(host.RTT.Microseconds())/1000.0)
			}

			mac := host.MAC
			if mac == "" {
				mac = "-"
			}

			// Show device type if available, otherwise show vendor
			deviceInfo := host.DeviceType
			if deviceInfo == "" || deviceInfo == "Unknown" {
				deviceInfo = host.Vendor
			}
			if deviceInfo == "" {
				deviceInfo = "-"
			}
			// Truncate if too long
			if len(deviceInfo) > 18 {
				deviceInfo = deviceInfo[:15] + "..."
			}

			ports := "-"
			if len(host.Ports) > 0 {
				portStrs := make([]string, len(host.Ports))
				for i, p := range host.Ports {
					portStrs[i] = fmt.Sprintf("%d", p)
				}
				ports = strings.Join(portStrs, ",")
				// Truncate if too long
				if len(ports) > 10 {
					ports = ports[:10] + "..."
				}
			}

			// Check if this is the gateway
			ipStr := host.IP.String()
			if discovery.IsGateway(host.IP) {
				ipStr = ipStr + " [G]"
			}

			// HTTP Banner
			httpBanner := host.HTTPBanner
			if httpBanner == "" {
				httpBanner = "-"
			}
			// Truncate if too long
			if len(httpBanner) > 23 {
				httpBanner = httpBanner[:20] + "..."
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
	} else if hasMAC {
		// ARP-only mode
		color.Cyan("%-20s %-25s %-18s %-20s\n", "IP Address", "Hostname", "MAC Address", "Device Type")
		color.White("%s\n", strings.Repeat("-", 90))

		for _, host := range hosts {
			hostname := host.Hostname
			if hostname == "" {
				hostname = "-"
			}

			mac := host.MAC
			if mac == "" {
				mac = "-"
			}

			// Show device type if available, otherwise show vendor
			deviceInfo := host.DeviceType
			if deviceInfo == "" || deviceInfo == "Unknown" {
				deviceInfo = host.Vendor
			}
			if deviceInfo == "" {
				deviceInfo = "-"
			}

			// Check if this is the gateway
			ipStr := host.IP.String()
			if discovery.IsGateway(host.IP) {
				ipStr = ipStr + " [G]"
			}

			fmt.Printf("%-20s %-25s %-18s %-20s\n",
				ipStr,
				hostname,
				mac,
				deviceInfo,
			)
		}
	} else {
		// Ping-only mode
		color.Cyan("%-15s %-30s %-10s\n", "IP Address", "Hostname", "RTT")
		color.White("%s\n", strings.Repeat("-", 60))

		for _, host := range hosts {
			hostname := host.Hostname
			if hostname == "" {
				hostname = "-"
			}

			rtt := "-"
			if host.RTT > 0 {
				rtt = fmt.Sprintf("%.2fms", float64(host.RTT.Microseconds())/1000.0)
			}

			fmt.Printf("%-15s %-30s %-10s\n",
				host.IP.String(),
				hostname,
				rtt,
			)
		}
	}

	fmt.Println()
	return nil
}

func printJSON(hosts []scanner.Host) error {
	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func printCSV(hosts []scanner.Host) error {
	fmt.Println("IP,Hostname,RTT,MAC,Vendor,DeviceType,Ports")
	for _, host := range hosts {
		hostname := host.Hostname
		if hostname == "" {
			hostname = ""
		}

		rtt := ""
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.2f", float64(host.RTT.Microseconds())/1000.0)
		}

		mac := host.MAC
		vendor := host.Vendor
		deviceType := host.DeviceType

		ports := ""
		if len(host.Ports) > 0 {
			portStrs := make([]string, len(host.Ports))
			for i, p := range host.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			ports = strings.Join(portStrs, ";")
		}

		fmt.Printf("%s,%s,%s,%s,%s,%s,%s\n",
			host.IP.String(),
			hostname,
			rtt,
			mac,
			vendor,
			deviceType,
			ports,
		)
	}
	return nil
}
