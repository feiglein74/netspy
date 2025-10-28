package cmd

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
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
	fast       bool
	thorough   bool
	arp        bool
	hybrid     bool
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [network]",
	Short: "Scan a network for active hosts",
	Long: `Scan a network subnet to discover active hosts.

Scan modes:
  Default: Conservative TCP scan
  --fast:     Quick scan (may miss some devices)
  --thorough: Comprehensive scan (may have false positives)
  --arp:      ARP-based scan (most accurate for local networks)
  --hybrid:   ARP discovery + ping/port details (best accuracy + details)

Examples:
  netspy scan 192.168.1.0/24           # Conservative scan
  netspy scan 192.168.1.0/24 --arp     # ARP scan only
  netspy scan 192.168.1.0/24 --hybrid  # ARP + ping details (recommended!)
  netspy scan 192.168.1.0/24 --hybrid --ports 22,80,443  # ARP + specific ports`,
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
	scanCmd.Flags().BoolVar(&fast, "fast", false, "Fast scanning mode")
	scanCmd.Flags().BoolVar(&thorough, "thorough", false, "Thorough scanning mode")
	scanCmd.Flags().BoolVar(&arp, "arp", false, "ARP-based scanning only")
	scanCmd.Flags().BoolVar(&hybrid, "hybrid", false, "ARP discovery + ping/port details (recommended)")

	// Validate flags
	scanCmd.PreRun = func(cmd *cobra.Command, args []string) {
		modeCount := 0
		if fast {
			modeCount++
		}
		if thorough {
			modeCount++
		}
		if arp {
			modeCount++
		}
		if hybrid {
			modeCount++
		}

		if modeCount > 1 {
			color.Red("❌ Cannot combine scan modes")
			cmd.Usage()
			return
		}
	}
}

// isQuiet checks if quiet mode is enabled
func isQuiet() bool {
	return viper.GetBool("quiet")
}

func runScan(cmd *cobra.Command, args []string) error {
	network := args[0]

	// Use hybrid scanning if requested
	if hybrid {
		return runHybridScan(network)
	}

	// Use ARP scanning if requested
	if arp {
		return runARPScan(network)
	}

	// Validate network input for normal scans
	hosts, err := parseNetworkInput(network)
	if err != nil {
		return fmt.Errorf("invalid network specification: %v", err)
	}

	// Create scanner configuration
	config := createScanConfig()
	s := scanner.New(config)

	// Print scan info (unless quiet mode)
	if !isQuiet() {
		mode := getModeName()
		color.Cyan("🔍 Scanning %s (%d hosts) in %s mode\n", network, len(hosts), mode)
		color.White("⚙️  Workers: %d, Timeout: %v\n\n", config.Concurrency, config.Timeout)
	}

	// Perform scan
	results, err := s.ScanHosts(hosts)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}

	// Output results
	return output.PrintResults(results, format)
}

func runHybridScan(network string) error {
	quiet := isQuiet()

	if !quiet {
		color.Cyan("🚀 Hybrid scan: ARP discovery + ping/port details\n")
		color.Yellow("💡 This combines accuracy of ARP with details from ping/ports\n\n")
	}

	// Parse network
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Step 1: ARP Discovery
	if !quiet {
		color.Cyan("📋 Step 1: ARP-based host discovery...\n")
	}

	// Populate ARP table first
	if !quiet {
		color.Cyan("🔄 Populating ARP table...\n")
	}
	if err := populateARPTable(netCIDR); err != nil {
		if !quiet {
			color.Yellow("⚠️  Warning: %v\n", err)
		}
	}

	// Read ARP table
	arpHosts := readCurrentARPTable(netCIDR)
	if !quiet {
		color.Green("✅ ARP found %d active hosts\n\n", len(arpHosts))
	}

	if len(arpHosts) == 0 {
		if !quiet {
			color.Red("❌ No hosts found via ARP\n")
		}
		return nil
	}

	// Step 2: Ping + Port details for ARP-discovered hosts
	if !quiet {
		color.Cyan("📡 Step 2: Getting ping/port details for discovered hosts...\n")
	}
	enhancedHosts := enhanceHostsWithDetails(arpHosts)

	if !quiet {
		color.Green("✅ Enhanced %d hosts with ping/port details\n\n", len(enhancedHosts))
	}

	// Output results
	return output.PrintResults(enhancedHosts, format)
}

func runARPScan(network string) error {
	quiet := isQuiet()

	if !quiet {
		color.Yellow("🔧 ARP scan started for %s\n", network)
	}

	// Parse network
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	if !quiet {
		color.Yellow("🔧 Network parsed successfully: %s\n", netCIDR.String())
	}

	// Step 1: Check current ARP table
	if !quiet {
		color.Cyan("📋 Step 1: Checking current ARP table...\n")
	}
	currentHosts := readCurrentARPTable(netCIDR)
	if !quiet {
		color.Green("Found %d hosts in current ARP table\n", len(currentHosts))
	}

	// Step 2: Populate ARP table by pinging all IPs
	if !quiet {
		color.Cyan("🔄 Step 2: Populating ARP table (pinging subnet)...\n")
	}
	if err := populateARPTable(netCIDR); err != nil {
		if !quiet {
			color.Yellow("⚠️  Warning: %v\n", err)
		}
	}

	// Step 3: Read ARP table again
	if !quiet {
		color.Cyan("📋 Step 3: Reading refreshed ARP table...\n")
	}
	finalHosts := readCurrentARPTable(netCIDR)

	if !quiet {
		color.Green("✅ Final result: %d hosts found after ARP refresh\n", len(finalHosts))
	}

	// Output results
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

	// Add RTT via ping
	start := time.Now()
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "80"), 500*time.Millisecond); err == nil {
		conn.Close()
		enhanced.RTT = time.Since(start)
	} else if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "443"), 500*time.Millisecond); err == nil {
		conn.Close()
		enhanced.RTT = time.Since(start)
	} else if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host.IP.String(), "22"), 500*time.Millisecond); err == nil {
		conn.Close()
		enhanced.RTT = time.Since(start)
	}

	// Add hostname if not already present
	if enhanced.Hostname == "" {
		if names, err := net.LookupAddr(host.IP.String()); err == nil && len(names) > 0 {
			enhanced.Hostname = names[0]
		}
	}

	// Add port scanning if requested
	if len(ports) > 0 {
		enhanced.Ports = scanSpecificPorts(host.IP, ports)
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
	cmd := exec.Command("arp", "-a")
	cmdOutput, err := cmd.Output()
	if err != nil {
		color.Red("❌ Failed to run arp command: %v\n", err)
		return nil
	}

	lines := strings.Split(string(cmdOutput), "\n")
	var hosts []scanner.Host

	// Windows ARP format: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
	arpRegex := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9\-]{17})\s+\w+`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := arpRegex.FindStringSubmatch(line); matches != nil {
			ipStr := matches[1]
			macStr := matches[2]

			ip := net.ParseIP(ipStr)
			if ip != nil && network.Contains(ip) {
				// Skip broadcast and multicast MACs
				if !strings.Contains(macStr, "ff-ff-ff-ff-ff-ff") &&
					!strings.HasPrefix(macStr, "01-") {

					macFormatted := strings.ReplaceAll(macStr, "-", ":")
					vendor := discovery.GetMACVendor(macFormatted)

					host := scanner.Host{
						IP:         ip,
						MAC:        macFormatted,
						Vendor:     vendor,
						Online:     true,
						DeviceType: discovery.DetectDeviceType("", macFormatted, vendor, nil),
					}

					// SKIP hostname lookup here - it's too slow (blocks for 2-5 seconds per host!)
					// Hostname lookups should be done asynchronously if needed

					hosts = append(hosts, host)
				}
			}
		}
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
		color.Cyan("⏳ Waiting for ARP table to update...\n")
	}
	time.Sleep(1 * time.Second)

	return nil
}


func getModeName() string {
	if arp {
		return "ARP"
	} else if hybrid {
		return "hybrid"
	} else if fast {
		return "fast"
	} else if thorough {
		return "thorough"
	}
	return "conservative"
}

func createScanConfig() scanner.Config {
	config := scanner.Config{
		Concurrency: concurrent,
		Timeout:     timeout,
		Ports:       ports,
		Fast:        fast,
		Thorough:    thorough,
		Quiet:       isQuiet(),
	}

	// Conservative defaults to avoid false positives
	if thorough {
		if config.Concurrency == 0 {
			config.Concurrency = 20
		}
		if config.Timeout == 0 {
			config.Timeout = 1500 * time.Millisecond
		}
	} else if fast {
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
