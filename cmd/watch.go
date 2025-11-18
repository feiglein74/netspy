package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/scanner"
	"netspy/pkg/watch"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	watchInterval   time.Duration
	watchMode       string
	watchUI         string          // UI-Mode: "bubbletea" oder "legacy"
	maxThreads      int             // Maximum concurrent threads (0 = auto-calculate based on network size)
	screenBuffer    bytes.Buffer    // Buffer für aktuellen Screen-Inhalt (legacy mode)
	screenBufferMux sync.Mutex      // Mutex für Thread-Safe Zugriff (legacy mode)
	currentCIDR     *net.IPNet      // Current network CIDR for IP formatting
)

// watchCmd repräsentiert den watch-Befehl
var watchCmd = &cobra.Command{
	Use:   "watch [network]",
	Short: "Continuously monitor a network for changes",
	Long: `Watch a network subnet for changes in real-time.

Monitors the network at regular intervals and reports when devices appear or disappear.
Tracks timestamps for when each device was first seen, last seen, and status changes.

If no network is specified, you'll be prompted to select from available network interfaces.

Examples:
  netspy watch                                     # Auto-detect and select network
  netspy watch 192.168.1.0/24                      # Monitor with default 60s interval
  netspy watch 192.168.1.0/24 --interval 30s       # Check every 30 seconds
  netspy watch 192.168.1.0/24 --mode hybrid        # Use hybrid scanning mode
  netspy watch 192.168.1.0/24 --mode arp           # Use ARP scanning mode`,
	Args: cobra.RangeArgs(0, 1),
	RunE: runWatch,
}

func init() {
	rootCmd.AddCommand(watchCmd)

	// Flags für watch-Befehl hinzufügen
	watchCmd.Flags().DurationVar(&watchInterval, "interval", 60*time.Second, "Scan interval")
	watchCmd.Flags().StringVar(&watchMode, "mode", "hybrid", "Scan mode (hybrid, arp, fast, thorough, conservative)")
	watchCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{}, "Specific ports to scan")
	watchCmd.Flags().StringVar(&watchUI, "ui", "legacy", "UI mode (legacy, bubbletea)")
	watchCmd.Flags().IntVar(&maxThreads, "max-threads", 0, "Maximum concurrent threads (0 = auto-calculate based on network size)")
}

func runWatch(cmd *cobra.Command, args []string) error {
	var network string

	// Wenn kein Netzwerk angegeben, erkennen und Benutzer zur Auswahl auffordern
	if len(args) == 0 {
		detectedNetwork, err := detectAndSelectNetwork()
		if err != nil {
			return err
		}
		network = detectedNetwork
	} else {
		network = args[0]
	}

	// Netzwerk parsen
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Bubbletea UI verwenden wenn --ui=bubbletea
	if watchUI == "bubbletea" {
		return runWatchBubbletea(network, watchMode, watchInterval)
	}

	// Legacy UI (alte Implementierung)
	return runWatchLegacy(network, netCIDR)
}

// runWatchLegacy ist die alte ANSI-basierte Implementierung
func runWatchLegacy(network string, netCIDR *net.IPNet) error {
	// Store CIDR for IP formatting (bold host part)
	currentCIDR = netCIDR

	// Terminal in raw mode versetzen für ANSI/VT-Codes und direkte Tasteneingaben (platform-specific)
	// WICHTIG: Muss VOR allen ANSI-Ausgaben erfolgen!
	_ = setupTerminal()

	// Calculate optimal thread counts based on network size
	threadConfig := watch.CalculateThreads(netCIDR, maxThreads)
	ones, bits := netCIDR.Mask.Size()
	hostCount := 1 << uint(bits-ones)
	fmt.Printf("🔧 Thread Config: Scan=%d, Reachability=%d, DNS=%d (Network: %s, %d potential hosts)\n",
		threadConfig.Scan, threadConfig.Reachability, threadConfig.DNS,
		netCIDR.String(), hostCount)

	// Check if target subnet is local or remote (for UI indicators)
	isLocal, _ := discovery.IsLocalSubnet(netCIDR)

	// Clear screen and move cursor to home for clean UI start
	fmt.Print("\033[2J\033[H")

	// Geräte-Status-Map - Schlüssel ist IP-Adresse als String
	deviceStates := make(map[string]*watch.DeviceState)

	// Signal-Handling für graceful Shutdown und Window-Resize einrichten
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Window size change signal (platform-specific)
	winchChan := getResizeChannel()

	// Keyboard input channel für 'c' zum Kopieren
	keyChan := make(chan rune, 10)

	// Stelle sicher, dass wir beim Exit das Terminal wieder zurücksetzen
	defer func() {
		_ = resetTerminal()
	}()

	go func() {
		sig := <-sigChan
		fmt.Printf("\n\n[!] Received signal %v, shutting down...\n", sig)
		// Terminal-State wiederherstellen (platform-specific)
		_ = resetTerminal()
		cancel()
	}()

	// Keyboard-Listener für 'c' zum Kopieren, 'n'/'p' für Paging, '?' für Help und ESC zum Beenden
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				continue
			}

			// ESC key - send to channel (can be used to close help, or exit)
			if buf[0] == 27 {
				keyChan <- 27 // ESC
				continue
			}

			// Enter key - send to channel
			if buf[0] == 10 || buf[0] == 13 {
				keyChan <- 10 // Enter
				continue
			}

			// Space key
			if buf[0] == ' ' {
				keyChan <- ' '
				continue
			}

			// Question mark for help
			if buf[0] == '?' {
				keyChan <- '?'
				continue
			}

			// Pass all alphabetic keys to channel (handlers decide what to do)
			if (buf[0] >= 'a' && buf[0] <= 'z') || (buf[0] >= 'A' && buf[0] <= 'Z') {
				keyChan <- rune(buf[0])
			}
		}
	}()

	scanCount := 0
	var redrawMutex sync.Mutex // Prevent concurrent redraws
	var activeThreads int32    // Tracks active background DNS lookup threads (atomic counter)
	var currentPage int32 = 1  // Current page for host list pagination (atomic for thread-safety)
	sortState := &watch.SortState{Column: watch.SortByIP, Ascending: true} // Default sort by IP ascending

	for {
		// Check if context is cancelled before starting new scan
		if ctx.Err() != nil {
			fmt.Println("\n[OK] Shutdown complete")
			return nil
		}

		scanCount++
		scanStart := time.Now()

		// Perform scan quietly (no output during scan)
		hosts := performScanQuiet(ctx, network, netCIDR, watchMode, &activeThreads, threadConfig)

		// Check if cancelled during scan
		if ctx.Err() != nil {
			fmt.Println("\n[OK] Shutdown complete")
			return nil
		}

		// Update device states
		// Use scanStart for all timestamps to ensure consistency across all devices in the same scan
		currentIPs := make(map[string]bool)

		for _, host := range hosts {
			ipStr := host.IP.String()

			// Mark as seen if online
			if host.Online {
				currentIPs[ipStr] = true
			} else {
				// Skip offline hosts from this scan, but don't mark as seen
				continue
			}

			state, exists := deviceStates[ipStr]

			if exists {
				// Update existing device
				state.LastSeen = scanStart

				// Preserve hostname, source, and RTT if already resolved/measured
				oldHostname := state.Host.Hostname
				oldSource := state.Host.HostnameSource
				oldRTT := state.Host.RTT

				state.Host = host // Update host info (MAC, RTT, etc.)

				// Restore hostname if it was already resolved
				if oldSource != "" {
					state.Host.Hostname = oldHostname
					state.Host.HostnameSource = oldSource
				}

				// Preserve old RTT if new scan didn't measure it
				if state.Host.RTT == 0 && oldRTT > 0 {
					state.Host.RTT = oldRTT
				}

				if state.Status == "offline" {
					// Device came back online - accumulate the offline time
					offlineDuration := scanStart.Sub(state.StatusSince)
					state.TotalOfflineTime += offlineDuration
					state.Status = "online"
					state.StatusSince = scanStart
					state.FlapCount++ // Increment flap counter
				}
			} else {
				// New device - use scanStart so all devices in this scan have same FirstSeen
				deviceStates[ipStr] = &watch.DeviceState{
					Host:          host,
					FirstSeen:     scanStart,
					FirstSeenScan: scanCount,
					LastSeen:      scanStart,
					Status:        "online",
					StatusSince:   scanStart,
				}
			}
		}

		// Check for devices that went offline
		for ipStr, state := range deviceStates {
			if !currentIPs[ipStr] && state.Status == "online" {
				// Device went offline - use scanStart for consistency
				state.Status = "offline"
				state.StatusSince = scanStart
				state.FlapCount++ // Increment flap counter
			}
		}

		// Calculate scan duration
		scanDuration := time.Since(scanStart)

		// Phase 0: Pre-populate from DNS cache (instant, < 100ms!)
		// Must happen BEFORE first table draw for instant hostname display
		populateFromDNSCache(deviceStates)

		// Lock to prevent concurrent redraws (scan vs SIGWINCH)
		redrawMutex.Lock()

		// Calculate next scan time for status display
		nextScan := watchInterval - scanDuration
		if nextScan < 0 {
			nextScan = 0
		}

		// Move cursor to home and redraw (no clear = less flicker on slow terminals like Windows)
		fmt.Print("\033[H") // Move to home (0,0) without clearing

		// Draw layout (will overwrite old content)
		watch.DrawBtopLayout(deviceStates, scanStart, network, watchInterval, watchMode, scanCount, scanDuration, nextScan, &activeThreads, &currentPage, sortState, isLocal, watch.GetGitVersion, captureScreen, formatIPWithBoldHost, watch.IsLocallyAdministered, getZebraColor)

		// Clear any remaining lines from previous draw (if screen shrunk)
		fmt.Print("\033[J") // Clear from cursor to end of screen

		redrawMutex.Unlock()

		// Phase 1: Quick DNS lookups immediately after scan (blocks briefly for fast results)
		performInitialDNSLookups(ctx, deviceStates)

		// Phase 2: Start slow background lookups (mDNS/NetBIOS/LLMNR/HTTP) while countdown is running
		if nextScan > 0 {
			go performBackgroundDNSLookups(ctx, deviceStates, &activeThreads, threadConfig)

			// Show countdown with periodic table updates (pass scanStart for consistent uptime)
			showCountdownWithTableUpdates(ctx, cancel, nextScan, deviceStates, scanCount, scanDuration, scanStart, winchChan, keyChan, &redrawMutex, network, watchInterval, watchMode, &activeThreads, &currentPage, sortState, threadConfig, isLocal)
		}
	}
}

func performScanQuiet(ctx context.Context, network string, netCIDR *net.IPNet, mode string, activeThreads *int32, threadConfig watch.ThreadConfig) []scanner.Host {
	var hosts []scanner.Host
	var err error

	switch mode {
	case "hybrid":
		hosts, err = performHybridScanQuiet(ctx, netCIDR, activeThreads, threadConfig)
	case "arp":
		hosts, err = performARPScanQuiet(ctx, netCIDR, activeThreads, threadConfig)
	case "fast", "thorough", "conservative":
		hosts, err = performNormalScan(network, mode, activeThreads, threadConfig)
	default:
		return nil
	}

	if err != nil {
		return hosts
	}

	// Gateway-Flags setzen (heuristische Erkennung)
	scanner.SetGatewayFlags(hosts, netCIDR)

	return hosts
}

func performHybridScanQuiet(ctx context.Context, netCIDR *net.IPNet, activeThreads *int32, threadConfig watch.ThreadConfig) ([]scanner.Host, error) {
	// Prüfe ob das Ziel-Netzwerk lokal oder fremd ist
	isLocal, _ := discovery.IsLocalSubnet(netCIDR)

	var finalHosts []scanner.Host

	// Nur ARP versuchen wenn lokales Netzwerk
	if isLocal {
		allHosts := []scanner.Host{}

		// Read existing ARP table first (quietly)
		existingHosts := readCurrentARPTableQuiet(netCIDR)
		allHosts = append(allHosts, existingHosts...)

		// Populate ARP table
		if err := populateARPTableQuiet(ctx, netCIDR); err != nil {
			return allHosts, err
		}

		// Read refreshed ARP table (quietly)
		finalHosts = readCurrentARPTableQuiet(netCIDR)

		// Add localhost if it's in the network range
		localhostIP := getLocalhostIP(netCIDR)
		if localhostIP != nil {
			localMAC := getLocalMAC()
			finalHosts = append(finalHosts, scanner.Host{
				IP:         localhostIP,
				MAC:        localMAC,
				Vendor:     "localhost",
				DeviceType: "This Computer",
				Online:     true,
			})
		}
	}

	// SSDP/UPnP Discovery wird NICHT im ersten Scan gesetzt!
	// Grund: HTTP title detection (z.B. "Hue") hat höhere Priorität
	// SSDP wird später im Background-DNS-Lookup als letzter Fallback verwendet

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden (fremdes Subnet oder ARP fehlgeschlagen)
	if len(finalHosts) == 0 {
		// Generate all IPs in network
		ips := discovery.GenerateIPsFromCIDR(netCIDR)

		// Scanner configuration (dynamic based on network size)
		config := scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}

		s := scanner.New(config)
		tcpHosts, err := s.ScanHosts(ips, activeThreads)
		if err != nil {
			return nil, err
		}

		finalHosts = tcpHosts
	}

	// Skip RTT measurement in watch mode - we'll get RTT from reachability checks
	// This makes the first scan much faster
	return finalHosts, nil
}

// getLocalhostIP returns the local IP address in the given network, or nil if not found
func getLocalhostIP(network *net.IPNet) net.IP {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Check if IP is in the target network
			if ip != nil && network.Contains(ip) && ip.To4() != nil {
				return ip
			}
		}
	}
	return nil
}

// getLocalMAC returns the MAC address of the primary network interface
func getLocalMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		// Skip loopback and interfaces without MAC
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Check if interface has a valid IP
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.To4() != nil {
				return iface.HardwareAddr.String()
			}
		}
	}
	return ""
}

func performARPScanQuiet(ctx context.Context, netCIDR *net.IPNet, activeThreads *int32, threadConfig watch.ThreadConfig) ([]scanner.Host, error) {
	// Prüfe ob das Ziel-Netzwerk lokal oder fremd ist
	isLocal, _ := discovery.IsLocalSubnet(netCIDR)

	var hosts []scanner.Host

	// Nur ARP versuchen wenn lokales Netzwerk
	if isLocal {
		// Populate ARP table
		if err := populateARPTableQuiet(ctx, netCIDR); err != nil {
			return nil, err
		}

		// Read ARP table quietly
		hosts = readCurrentARPTableQuiet(netCIDR)
	}

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden (fremdes Subnet oder ARP fehlgeschlagen)
	if len(hosts) == 0 {
		// Generate all IPs in network
		ips := discovery.GenerateIPsFromCIDR(netCIDR)

		// Scanner configuration (dynamic based on network size)
		config := scanner.Config{
			Concurrency: threadConfig.Scan,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}

		s := scanner.New(config)
		tcpHosts, err := s.ScanHosts(ips, activeThreads)
		if err != nil {
			return nil, err
		}

		hosts = tcpHosts
	}

	return hosts, nil
}

// readCurrentARPTableQuiet reads ARP table without any output (for watch mode)
func readCurrentARPTableQuiet(network *net.IPNet) []scanner.Host {
	arpScanner := discovery.NewARPScanner(500 * time.Millisecond)
	arpEntries, err := arpScanner.ScanARPTableQuiet(network)
	if err != nil {
		return nil
	}

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

func populateARPTableQuiet(ctx context.Context, network *net.IPNet) error {
	ips := parseNetworkInputSimple(network)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 254)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(targetIP net.IP) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Quick ping to populate ARP table
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetIP.String(), "80"), 20*time.Millisecond)
			if err == nil {
				_ = conn.Close() // Ignore close error
			}
		}(ip)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Wait for ARP table to update
	return nil
}

// Old streaming functions removed - now using static table with redrawTable()

func performNormalScan(network string, mode string, activeThreads *int32, threadConfig watch.ThreadConfig) ([]scanner.Host, error) {
	hosts, err := parseNetworkInput(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network specification: %v", err)
	}

	// Set the global scanMode so createScanConfig() uses the right settings
	scanMode = mode

	config := createScanConfig()
	config.Quiet = true // Suppress verbose output in watch mode
	s := scanner.New(config)

	results, err := s.ScanHosts(hosts, activeThreads)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	return results, nil
}

// Old print functions removed - now using redrawTable() for static table updates

// splitIPNetworkHost splits an IP into network and host parts based on CIDR
// Returns (networkPart, hostPart, ok). If splitting fails, ok is false.
func splitIPNetworkHost(ip string) (string, string, bool) {
	if currentCIDR == nil {
		return "", "", false
	}

	// Parse the IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", "", false
	}

	// Get CIDR mask size (e.g., 24 for /24)
	maskBits, _ := currentCIDR.Mask.Size()

	// Split IP into octets
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", "", false
	}

	// Determine split point based on mask
	// /8 → 1 octet network, 3 octets host
	// /16 → 2 octets network, 2 octets host
	// /24 → 3 octets network, 1 octet host
	// /32 → all network, no host (special case)
	var networkOctets int
	if maskBits <= 8 {
		networkOctets = 1
	} else if maskBits <= 16 {
		networkOctets = 2
	} else if maskBits <= 24 {
		networkOctets = 3
	} else {
		// /32 or other edge cases - no host part
		return "", "", false
	}

	// Build network part + host part
	networkPart := strings.Join(octets[:networkOctets], ".") + "."
	hostPart := strings.Join(octets[networkOctets:], ".")

	return networkPart, hostPart, true
}

// formatIPWithBoldHost formats an IP address with the host part in bold
// based on the current CIDR mask. For example:
// - 10.0.0.1 with /24 → "10.0.0." + BOLD("1")
// - 192.168.1.10 with /16 → "192.168." + BOLD("1.10")
// Platform-specific implementation (see watch_windows.go, watch_darwin.go, watch_linux.go)

// formatDurationShort formats duration in compact format (e.g., "5m", "2h", "3d")
func formatDurationShort(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// copyScreenToClipboard kopiert den aktuellen Screen-Inhalt in die Zwischenablage
func copyScreenToClipboard() error {
	screenBufferMux.Lock()
	content := screenBuffer.String()
	screenBufferMux.Unlock()

	// Plattformabhängiges Kopieren in die Zwischenablage
	var cmd *exec.Cmd
	switch {
	case commandExists("pbcopy"): // macOS
		cmd = exec.Command("pbcopy")
	case commandExists("xclip"): // Linux mit X11
		cmd = exec.Command("xclip", "-selection", "clipboard")
	case commandExists("wl-copy"): // Linux mit Wayland
		cmd = exec.Command("wl-copy")
	case commandExists("clip.exe"): // Windows (WSL) oder Windows
		cmd = exec.Command("clip.exe")
	default:
		return fmt.Errorf("kein Clipboard-Tool gefunden (pbcopy/xclip/wl-copy/clip.exe)")
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("fehler beim Öffnen der stdin-Pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("fehler beim Starten des Clipboard-Tools: %v", err)
	}

	_, err = io.WriteString(stdin, content)
	if err != nil {
		return fmt.Errorf("fehler beim Schreiben in die Zwischenablage: %v", err)
	}

	stdin.Close()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("fehler beim Warten auf Clipboard-Tool: %v", err)
	}

	return nil
}

// commandExists prüft ob ein Kommando verfügbar ist
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// getGitVersion gibt die aktuelle Git-Version zurück (kurzer Hash)
func getGitVersion() string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "dev"
	}
	return "(" + strings.TrimSpace(string(output)) + ")"
}

// captureScreen wrapper for display.CaptureScreenSimple
func captureScreen() {
	watch.CaptureScreenSimple(nil, time.Now(), "", 0, "", 0, 0, 0, &screenBuffer, &screenBufferMux, formatIPWithBoldHost)
}

// parseNetworkInputSimple delegates to discovery package
func parseNetworkInputSimple(network *net.IPNet) []net.IP {
	return discovery.GenerateIPsFromCIDR(network)
}

// populateFromDNSCache fills deviceStates with cached DNS names
func populateFromDNSCache(deviceStates map[string]*watch.DeviceState) {
	cache := discovery.ReadDNSCache()
	for ip, hostname := range cache {
		if state, exists := deviceStates[ip]; exists {
			if state.Host.Hostname == "" {
				state.Host.Hostname = hostname
				state.Host.HostnameSource = "dns-cache"
				state.Host.DeviceType = discovery.DetectDeviceType(
					state.Host.Hostname,
					state.Host.MAC,
					state.Host.Vendor,
					state.Host.Ports,
				)
			}
		}
	}
}

// performInitialDNSLookups performs fast DNS lookups immediately after scan
func performInitialDNSLookups(ctx context.Context, deviceStates map[string]*watch.DeviceState) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50)
	for ipStr, state := range deviceStates {
		if state.Status != "online" || state.Host.Hostname != "" {
			continue
		}
		wg.Add(1)
		go func(ip string, s *watch.DeviceState) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			}
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if names, err := net.LookupAddr(parsedIP.String()); err == nil && len(names) > 0 {
					hostname := strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
					if hostname != "" {
						s.Host.Hostname = hostname
						s.Host.HostnameSource = "dns"
						s.LastHostnameLookup = time.Now()
						s.Host.DeviceType = discovery.DetectDeviceType(s.Host.Hostname, s.Host.MAC, s.Host.Vendor, s.Host.Ports)
					}
				}
			}
		}(ipStr, state)
	}
	wg.Wait()
}

// performBackgroundDNSLookups performs slow background hostname resolution
func performBackgroundDNSLookups(ctx context.Context, deviceStates map[string]*watch.DeviceState, activeThreads *int32, threadConfig watch.ThreadConfig) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threadConfig.DNS)
	retryInterval := 5 * time.Minute
	for ipStr, state := range deviceStates {
		if state.Status != "online" {
			continue
		}
		if state.Host.Hostname != "" && time.Since(state.LastHostnameLookup) < retryInterval {
			continue
		}
		if state.Host.Hostname == "" && !state.LastHostnameLookup.IsZero() && time.Since(state.LastHostnameLookup) < retryInterval {
			continue
		}
		wg.Add(1)
		go func(ip string, s *watch.DeviceState) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				atomic.AddInt32(activeThreads, 1)
				defer func() {
					atomic.AddInt32(activeThreads, -1)
					<-semaphore
				}()
			}
			s.LastHostnameLookup = time.Now()
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				result := discovery.ResolveBackground(parsedIP, 3*time.Second)
				if result.Hostname != "" {
					s.Host.Hostname = result.Hostname
					s.Host.HostnameSource = result.Source
				}
			}
			if s.Host.Hostname != "" || s.Host.HostnameSource != "" {
				s.Host.DeviceType = discovery.DetectDeviceType(s.Host.Hostname, s.Host.MAC, s.Host.Vendor, s.Host.Ports)
			}
		}(ipStr, state)
	}
	wg.Wait()
}

// NetworkInterface represents a detected network interface
type NetworkInterface struct {
	Name    string
	IP      string
	Network string
}

// detectAndSelectNetwork detects network interfaces and prompts user
func detectAndSelectNetwork() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to detect network interfaces: %v", err)
	}
	networkMap := make(map[string]NetworkInterface)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			var ipNet *net.IPNet
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				ipNet = v
			case *net.IPAddr:
				continue
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			networkAddr := ipNet.IP.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			networkCIDR := fmt.Sprintf("%s/%d", networkAddr.String(), ones)
			if _, exists := networkMap[networkCIDR]; !exists {
				networkMap[networkCIDR] = NetworkInterface{
					Name:    iface.Name,
					IP:      ip.String(),
					Network: networkCIDR,
				}
			}
		}
	}
	if len(networkMap) == 0 {
		return "", fmt.Errorf("no active network interfaces found")
	}
	var availableNetworks []NetworkInterface
	for _, netif := range networkMap {
		availableNetworks = append(availableNetworks, netif)
	}
	if len(availableNetworks) == 1 {
		color.Cyan("Auto-detected network: %s (your IP: %s on %s)\n\n",
			availableNetworks[0].Network, availableNetworks[0].IP, availableNetworks[0].Name)
		return availableNetworks[0].Network, nil
	}
	color.Cyan("Multiple networks detected:\n\n")
	for i, netif := range availableNetworks {
		fmt.Printf("  %d. %s (your IP: %s on %s)\n", i+1, netif.Network, netif.IP, netif.Name)
	}
	fmt.Print("\nSelect network [1-", len(availableNetworks), "]: ")
	var selection int
	_, err = fmt.Scanln(&selection)
	if err != nil || selection < 1 || selection > len(availableNetworks) {
		return "", fmt.Errorf("invalid selection")
	}
	selectedNetwork := availableNetworks[selection-1]
	color.Green("Selected: %s (your IP: %s on %s)\n\n",
		selectedNetwork.Network, selectedNetwork.IP, selectedNetwork.Name)
	return selectedNetwork.Network, nil
}

// showCountdownWithTableUpdates - placeholder, still needs full implementation
func showCountdownWithTableUpdates(ctx context.Context, cancel context.CancelFunc, duration time.Duration, states map[string]*watch.DeviceState, scanCount int, scanDuration time.Duration, scanStart time.Time, winchChan <-chan os.Signal, keyChan <-chan rune, redrawMutex *sync.Mutex, network string, watchInterval time.Duration, watchMode string, activeThreads *int32, currentPage *int32, sortState *watch.SortState, threadConfig watch.ThreadConfig, isLocal bool) {
	// This function is too large to inline - keeping placeholder for now
	// Full implementation needed from git history
	fmt.Println("showCountdownWithTableUpdates not yet implemented in refactored version")
}
