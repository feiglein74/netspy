package cmd

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/output"
	"netspy/pkg/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	concurrent int
	timeout    time.Duration
	format     string
	ports      []int
	scanMode   string
)

// scanCmd repräsentiert den scan-Befehl
var scanCmd = &cobra.Command{
	Use:   "scan [network]",
	Short: "Scan a network for active hosts",
	Long: `Scan a network subnet to discover active hosts.

Scan modes:
  conservative: Conservative TCP scan (default)
  fast:         Quick scan (may miss some devices)
  thorough:     Comprehensive scan (may have false positives)
  arp:          ARP-based scan (most accurate for local networks)
  hybrid:       ARP discovery + ping/port details (best accuracy + details)

Examples:
  netspy scan 192.168.1.0/24                      # Conservative scan (default)
  netspy scan 192.168.1.0/24 --mode arp           # ARP scan only
  netspy scan 192.168.1.0/24 --mode hybrid        # ARP + ping details (recommended!)
  netspy scan 192.168.1.0/24 --mode hybrid --ports 22,80,443  # ARP + specific ports`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Flags
	scanCmd.Flags().IntVarP(&concurrent, "concurrent", "c", 0, "Number of concurrent scans")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 0, "Timeout per host")
	scanCmd.Flags().StringVarP(&format, "format", "f", "table", "Output format (table, json, csv)")
	scanCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{}, "Specific ports to scan")
	scanCmd.Flags().StringVar(&scanMode, "mode", "conservative", "Scan mode (conservative, fast, thorough, arp, hybrid)")
}

// isQuiet prüft ob quiet-Modus aktiviert ist
func isQuiet() bool {
	return viper.GetBool("quiet")
}

func runScan(cmd *cobra.Command, args []string) error {
	network := args[0]

	// Modus validieren
	validModes := map[string]bool{
		"conservative": true,
		"fast":         true,
		"thorough":     true,
		"arp":          true,
		"hybrid":       true,
	}
	if !validModes[scanMode] {
		return fmt.Errorf("invalid scan mode: %s (valid: conservative, fast, thorough, arp, hybrid)", scanMode)
	}

	// Hybrid-Scanning verwenden falls gewünscht
	if scanMode == "hybrid" {
		return runHybridScan(network)
	}

	// ARP-Scanning verwenden falls gewünscht
	if scanMode == "arp" {
		return runARPScan(network)
	}

	// Netzwerk-Eingabe für normale Scans validieren
	hosts, err := parseNetworkInput(network)
	if err != nil {
		return fmt.Errorf("invalid network specification: %v", err)
	}

	// Scanner-Konfiguration erstellen
	config := createScanConfig()
	s := scanner.New(config)

	// Scan-Info ausgeben (außer im quiet-Modus)
	if !isQuiet() {
		color.Cyan(" Scanning %s (%d hosts) in %s mode\n", network, len(hosts), scanMode)
		color.White("  Workers: %d, Timeout: %v\n\n", config.Concurrency, config.Timeout)
	}

	// Scan durchführen
	results, err := s.ScanHosts(hosts)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}

	// Ergebnisse ausgeben
	return output.PrintResults(results, format)
}

func runHybridScan(network string) error {
	quiet := isQuiet()

	// Parse network
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Prüfe ob das Ziel-Netzwerk lokal oder fremd ist
	isLocal, localNet := discovery.IsLocalSubnet(netCIDR)

	if !quiet {
		if isLocal {
			color.Cyan("Hybrid scan: ARP discovery + ping/port details\n")
			color.Green("Detected local subnet: %s\n", localNet.String())
			color.White("Strategy: ARP-based discovery (most accurate for local networks)\n\n")
		} else {
			color.Cyan("Hybrid scan: Remote subnet detection\n")
			color.Yellow("Target %s is in a different subnet\n", netCIDR.String())
			if localNet != nil {
				color.White("Your network: %s\n", localNet.String())
			}
			color.White("Strategy: TCP-based scanning (ARP does not work across routers)\n\n")
		}
	}

	// Step 1: Versuche ARP Discovery (nur für lokale Netzwerke sinnvoll)
	var arpHosts []scanner.Host

	if isLocal {
		if !quiet {
			color.Cyan("Step 1: ARP-based host discovery...\n")
		}

		// Populate ARP table first
		if !quiet {
			color.Cyan("Populating ARP table...\n")
		}
		if err := populateARPTable(netCIDR); err != nil {
			if !quiet {
				color.Yellow("[WARN] Warning: %v\n", err)
			}
		}

		// Read ARP table
		arpHosts = readCurrentARPTable(netCIDR)
		if !quiet {
			color.Green("[OK] ARP found %d active hosts\n\n", len(arpHosts))
		}
	}

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden wurden
	if len(arpHosts) == 0 {
		if !quiet {
			if isLocal {
				color.Yellow("[INFO] No hosts found via ARP, falling back to TCP scan\n")
			} else {
				color.Cyan("Step 1: TCP-based host discovery (remote subnet)\n")
			}
		}

		// Parse network für TCP-Scan
		hosts, err := parseNetworkInput(network)
		if err != nil {
			return fmt.Errorf("invalid network specification: %v", err)
		}

		// Scanner-Konfiguration erstellen (conservative mode für Genauigkeit)
		config := createScanConfig()
		s := scanner.New(config)

		if !quiet {
			color.White("Scanning %d hosts with TCP ping...\n", len(hosts))
		}

		// Scan durchführen
		results, err := s.ScanHosts(hosts)
		if err != nil {
			return fmt.Errorf("scan failed: %v", err)
		}

		// Ergebnisse ausgeben
		return output.PrintResults(results, format)
	}

	// Step 2: Ping + Port details for ARP-discovered hosts
	if !quiet {
		color.Cyan("Step 2: Getting ping/port details for discovered hosts...\n")
	}
	enhancedHosts := enhanceHostsWithDetails(arpHosts)

	if !quiet {
		color.Green("[OK] Enhanced %d hosts with ping/port details\n\n", len(enhancedHosts))
	}

	// Ergebnisse ausgeben
	return output.PrintResults(enhancedHosts, format)
}

func runARPScan(network string) error {
	quiet := isQuiet()

	// Parse network
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Prüfe ob das Ziel-Netzwerk lokal oder fremd ist
	isLocal, localNet := discovery.IsLocalSubnet(netCIDR)

	if !quiet {
		if isLocal {
			color.Cyan("ARP scan: Local subnet detection\n")
			color.Green("Detected local subnet: %s\n", localNet.String())
			color.White("Strategy: ARP-based discovery (most accurate for local networks)\n\n")
		} else {
			color.Cyan("ARP scan: Remote subnet detection\n")
			color.Yellow("Target %s is in a different subnet\n", netCIDR.String())
			if localNet != nil {
				color.White("Your network: %s\n", localNet.String())
			}
			color.White("Strategy: TCP-based scanning (ARP does not work across routers)\n\n")
		}
	}

	var finalHosts []scanner.Host

	// Nur ARP versuchen wenn lokales Netzwerk
	if isLocal {
		// Step 1: Check current ARP table
		if !quiet {
			color.Cyan("Step 1: Checking current ARP table...\n")
		}
		currentHosts := readCurrentARPTable(netCIDR)
		if !quiet {
			color.Green("Found %d hosts in current ARP table\n", len(currentHosts))
		}

		// Step 2: Populate ARP table by pinging all IPs
		if !quiet {
			color.Cyan("Step 2: Populating ARP table (pinging subnet)...\n")
		}
		if err := populateARPTable(netCIDR); err != nil {
			if !quiet {
				color.Yellow("[WARN] Warning: %v\n", err)
			}
		}

		// Step 3: Read ARP table again
		if !quiet {
			color.Cyan("Step 3: Reading refreshed ARP table...\n")
		}
		finalHosts = readCurrentARPTable(netCIDR)

		if !quiet {
			color.Green("[OK] Final result: %d hosts found after ARP refresh\n", len(finalHosts))
		}
	}

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden (fremdes Subnet oder ARP fehlgeschlagen)
	if len(finalHosts) == 0 {
		if !quiet {
			if isLocal {
				color.Yellow("[INFO] No hosts found via ARP, falling back to TCP scan\n")
			} else {
				color.Cyan("Step 1: TCP-based host discovery (remote subnet)\n")
			}
		}

		// Parse network für TCP-Scan
		hosts, err := parseNetworkInput(network)
		if err != nil {
			return fmt.Errorf("invalid network specification: %v", err)
		}

		// Scanner-Konfiguration erstellen (conservative mode für Genauigkeit)
		config := createScanConfig()
		s := scanner.New(config)

		if !quiet {
			color.White("Scanning %d hosts with TCP ping...\n", len(hosts))
		}

		// Scan durchführen
		results, err := s.ScanHosts(hosts)
		if err != nil {
			return fmt.Errorf("scan failed: %v", err)
		}

		finalHosts = results
	}

	// Ergebnisse ausgeben
	return output.PrintResults(finalHosts, format)
}

func enhanceHostsWithDetails(arpHosts []scanner.Host) []scanner.Host {
	var enhancedHosts []scanner.Host
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Create a simple pinger for RTT measurement
	semaphore := make(chan struct{}, 20) // Limit concurrency

	for _, host := range arpHosts {
		wg.Add(1)
		go func(h scanner.Host) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Enhance this host with ping/port details
			enhanced := enhanceHost(h)

			mutex.Lock()
			enhancedHosts = append(enhancedHosts, enhanced)
			mutex.Unlock()
		}(host)
	}

	wg.Wait()
	return enhancedHosts
}

func enhanceHost(host scanner.Host) scanner.Host {
	// Start with ARP data (IP, MAC, Vendor)
	enhanced := host

	// Add RTT via TCP connect on common ports
	start := time.Now()
	// Try common web ports first (most devices)
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "80"), 500*time.Millisecond); err == nil {
		conn.Close()
		enhanced.RTT = time.Since(start)
	} else if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "443"), 500*time.Millisecond); err == nil {
		conn.Close()
		enhanced.RTT = time.Since(start)
	} else if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "22"), 500*time.Millisecond); err == nil {
		conn.Close()
		enhanced.RTT = time.Since(start)
	} else if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "445"), 500*time.Millisecond); err == nil {
		// Port 445 (SMB) - always open on Windows systems
		conn.Close()
		enhanced.RTT = time.Since(start)
	} else if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "135"), 500*time.Millisecond); err == nil {
		// Port 135 (RPC) - Windows RPC endpoint mapper
		conn.Close()
		enhanced.RTT = time.Since(start)
	}

	// Add hostname if not already present - use fast resolution for scans
	if enhanced.Hostname == "" {
		result := discovery.ResolveFast(host.IP, 500*time.Millisecond)
		if result.Hostname != "" {
			enhanced.Hostname = result.Hostname
			enhanced.HostnameSource = result.Source
		}
	}

	// Add port scanning if requested
	if len(ports) > 0 {
		enhanced.Ports = scanSpecificPorts(host.IP, ports)
	}

	// Grab HTTP banner from common web ports
	if banner := discovery.GrabHTTPBanner(host.IP.String(), 2*time.Second); banner != nil {
		enhanced.HTTPBanner = banner.String()
	}

	// Detect device type based on available information
	enhanced.DeviceType = discovery.DetectDeviceType(
		enhanced.Hostname,
		enhanced.MAC,
		enhanced.Vendor,
		enhanced.Ports,
	)

	return enhanced
}

func scanSpecificPorts(ip net.IP, portList []int) []int {
	var openPorts []int
	var mutex sync.Mutex
	var wg sync.WaitGroup

	for _, port := range portList {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip.String(), p), 300*time.Millisecond); err == nil {
				conn.Close()
				mutex.Lock()
				openPorts = append(openPorts, p)
				mutex.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

func readCurrentARPTable(network *net.IPNet) []scanner.Host {
	// Use the ARPScanner from discovery package (which has proper platform-specific parsing)
	arpScanner := discovery.NewARPScanner(500 * time.Millisecond)
	arpEntries, err := arpScanner.ScanARPTable(network)
	if err != nil {
		color.Red("[ERROR] Failed to read ARP table: %v\n", err)
		return nil
	}

	// Convert ARPEntry to scanner.Host
	var hosts []scanner.Host
	for _, entry := range arpEntries {
		vendor := discovery.GetMACVendor(entry.MAC.String())
		host := scanner.Host{
			IP:         entry.IP,
			MAC:        entry.MAC.String(),
			Vendor:     vendor,
			RTT:        entry.RTT,
			Online:     entry.Online,
			DeviceType: discovery.DetectDeviceType("", entry.MAC.String(), vendor, nil),
		}
		hosts = append(hosts, host)
	}

	return hosts
}

func populateARPTable(network *net.IPNet) error {
	quiet := isQuiet()

	// Generate all IPs in the network
	ips := discovery.GenerateIPsFromCIDR(network)

	if !quiet {
		color.Cyan("🔄 Pinging %d addresses to populate ARP table...\n", len(ips))
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // Limit concurrent pings

	start := time.Now()
	completed := int64(0)

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP net.IP) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Quick ping to populate ARP table
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP.String(), "80"), 200*time.Millisecond)
			if err == nil {
				conn.Close()
			}

			// Also try UDP
			conn, err = net.DialTimeout("udp", net.JoinHostPort(targetIP.String(), "53"), 100*time.Millisecond)
			if err == nil {
				conn.Close()
			}

			// Progress tracking
			if !quiet {
				done := atomic.AddInt64(&completed, 1)
				if done%50 == 0 || done == int64(len(ips)) {
					elapsed := time.Since(start)
					rate := float64(done) / elapsed.Seconds()
					color.White("   Progress: %d/%d (%.0f/sec)\n", done, len(ips), rate)
				}
			}
		}(ip)
	}

	wg.Wait()

	// Wait a moment for ARP entries to be written
	if !quiet {
		color.Cyan(" Waiting for ARP table to update...\n")
	}
	time.Sleep(1 * time.Second)

	return nil
}


func getModeName() string {
	return scanMode
}

func createScanConfig() scanner.Config {
	config := scanner.Config{
		Concurrency: concurrent,
		Timeout:     timeout,
		Ports:       ports,
		Fast:        scanMode == "fast",
		Thorough:    scanMode == "thorough",
		Quiet:       isQuiet(),
	}

	// Conservative defaults to avoid false positives
	if scanMode == "thorough" {
		if config.Concurrency == 0 {
			config.Concurrency = 20
		}
		if config.Timeout == 0 {
			config.Timeout = 1500 * time.Millisecond
		}
	} else if scanMode == "fast" {
		if config.Concurrency == 0 {
			config.Concurrency = 100
		}
		if config.Timeout == 0 {
			config.Timeout = 200 * time.Millisecond
		}
	} else {
		// Conservative mode (default)
		if config.Concurrency == 0 {
			config.Concurrency = 40
		}
		if config.Timeout == 0 {
			config.Timeout = 500 * time.Millisecond
		}
	}

	return config
}

func parseNetworkInput(input string) ([]net.IP, error) {
	// Try to parse as CIDR
	if _, network, err := net.ParseCIDR(input); err == nil {
		return discovery.GenerateIPsFromCIDR(network), nil
	}

	// Try to parse as single IP
	if ip := net.ParseIP(input); ip != nil {
		return []net.IP{ip}, nil
	}

	return nil, fmt.Errorf("unsupported network format: %s", input)
}
