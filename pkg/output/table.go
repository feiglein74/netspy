package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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

	// Nach IP-Adresse sortieren (numerisch, sonst stünde .10 vor .2)
	sort.Slice(onlineHosts, func(i, j int) bool {
		return bytes.Compare(onlineHosts[i].IP.To16(), onlineHosts[j].IP.To16()) < 0
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
	// encoding/csv setzt Felder mit Komma oder Anführungszeichen in Quotes
	// (Herstellernamen wie "Apple, Inc." würden sonst die Spalten verschieben)
	w := csv.NewWriter(os.Stdout)
	if err := w.Write([]string{"IP", "Hostname", "RTT", "MAC", "Vendor", "DeviceType", "Ports"}); err != nil {
		return err
	}
	for _, host := range hosts {
		rtt := ""
		if host.RTT > 0 {
			rtt = fmt.Sprintf("%.2f", float64(host.RTT.Microseconds())/1000.0)
		}

		ports := ""
		if len(host.Ports) > 0 {
			portStrs := make([]string, len(host.Ports))
			for i, p := range host.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			ports = strings.Join(portStrs, ";")
		}

		if err := w.Write([]string{
			host.IP.String(),
			host.Hostname,
			rtt,
			host.MAC,
			host.Vendor,
			host.DeviceType,
			ports,
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
