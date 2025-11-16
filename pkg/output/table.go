package output

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"netspy/pkg/scanner"

	"github.com/fatih/color"
)

// PrintResults gibt Scan-Ergebnisse im angegebenen Format aus
func PrintResults(hosts []scanner.Host, format string) error {
	// Nur online Hosts filtern
	var onlineHosts []scanner.Host
	for _, host := range hosts {
		if host.Online {
			onlineHosts = append(onlineHosts, host)
		}
	}

	// Nach IP-Adresse sortieren
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
		color.Red("[ERROR] No active hosts found (scanned %d addresses)\n", totalScanned)
		return nil
	}

	// Prüfen welche Daten vorhanden sind
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

	// Terminal-Größe ermitteln
	termSize := GetTerminalSize()

	// Responsive Ausgabe basierend auf verfügbaren Daten
	if hasMAC && hasRTT {
		// Hybrid-Modus: ARP + Ping/Port Daten
		return printResponsiveHybridTable(hosts, termSize)
	} else if hasMAC {
		// ARP-Modus: MAC-Adressen vorhanden
		return printResponsiveARPTable(hosts, termSize)
	} else {
		// Ping-Modus: Nur IP/Hostname/RTT
		return printResponsivePingTable(hosts, termSize)
	}
}

// Legacy code removed - alle Modi nutzen jetzt responsive Tables

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
