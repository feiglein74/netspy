package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

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
		color.Cyan("%-15s %-30s %-8s %-18s %-15s %-12s\n",
			"IP Address", "Hostname", "RTT", "MAC Address", "Vendor", "Ports")
		color.White("%s\n", strings.Repeat("-", 105))

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

			vendor := host.Vendor
			if vendor == "" {
				vendor = "-"
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

			fmt.Printf("%-15s %-30s %-8s %-18s %-15s %-12s\n",
				host.IP.String(),
				hostname,
				rtt,
				mac,
				vendor,
				ports,
			)
		}
	} else if hasMAC {
		// ARP-only mode
		color.Cyan("%-15s %-25s %-18s %-15s\n", "IP Address", "Hostname", "MAC Address", "Vendor")
		color.White("%s\n", strings.Repeat("-", 80))

		for _, host := range hosts {
			hostname := host.Hostname
			if hostname == "" {
				hostname = "-"
			}

			mac := host.MAC
			if mac == "" {
				mac = "-"
			}

			vendor := host.Vendor
			if vendor == "" {
				vendor = "-"
			}

			fmt.Printf("%-15s %-25s %-18s %-15s\n",
				host.IP.String(),
				hostname,
				mac,
				vendor,
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
	fmt.Println("IP,Hostname,RTT,MAC,Vendor,Ports")
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

		ports := ""
		if len(host.Ports) > 0 {
			portStrs := make([]string, len(host.Ports))
			for i, p := range host.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			ports = strings.Join(portStrs, ";")
		}

		fmt.Printf("%s,%s,%s,%s,%s,%s\n",
			host.IP.String(),
			hostname,
			rtt,
			mac,
			vendor,
			ports,
		)
	}
	return nil
}
