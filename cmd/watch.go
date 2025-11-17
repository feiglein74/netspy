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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/output"
	"netspy/pkg/scanner"

	"github.com/fatih/color"
	"github.com/mattn/go-runewidth"
	"github.com/spf13/cobra"
)

var (
	watchInterval   time.Duration
	watchMode       string
	watchUI         string          // UI-Mode: "bubbletea" oder "legacy"
	maxThreads      int             // Maximum concurrent threads (0 = auto-calculate based on network size)
	screenBuffer    bytes.Buffer    // Buffer für aktuellen Screen-Inhalt (legacy mode)
	screenBufferMux sync.Mutex      // Mutex für Thread-Safe Zugriff (legacy mode)
)

// DeviceState verfolgt den Zustand eines entdeckten Geräts über die Zeit
type DeviceState struct {
	Host                scanner.Host
	FirstSeen           time.Time
	FirstSeenScan       int           // Scan number when first detected (for "new" indicator)
	LastSeen            time.Time
	Status              string        // "online" or "offline"
	StatusSince         time.Time     // When current status started
	FlapCount           int           // Number of times status has changed (flapping counter)
	TotalOfflineTime    time.Duration // Accumulated time spent offline (for continuous uptime calculation)
	LastHostnameLookup  time.Time     // When we last tried to resolve hostname (for retry mechanism)
}

// ThreadConfig holds thread count configuration for different operations
type ThreadConfig struct {
	Scan        int // Scanner threads (TCP/Ping)
	Reachability int // Quick reachability check threads
	DNS         int // DNS/mDNS/NetBIOS lookup threads
}

// calculateThreads determines optimal thread counts based on network size
// Returns (scanThreads, reachabilityThreads, dnsThreads)
func calculateThreads(netCIDR *net.IPNet, maxThreadsOverride int) ThreadConfig {
	// Count hosts in network
	ones, bits := netCIDR.Mask.Size()
	hostCount := 1 << uint(bits-ones) // 2^(bits-ones)

	// If user specified max threads, scale all thread types proportionally
	if maxThreadsOverride > 0 {
		// Scale: 50% scan, 30% reachability, 20% DNS
		return ThreadConfig{
			Scan:        int(float64(maxThreadsOverride) * 0.50),
			Reachability: int(float64(maxThreadsOverride) * 0.30),
			DNS:         int(float64(maxThreadsOverride) * 0.20),
		}
	}

	// Auto-calculate based on network size
	switch {
	case hostCount <= 16: // /28 or smaller
		return ThreadConfig{Scan: 10, Reachability: 10, DNS: 5}
	case hostCount <= 64: // /26
		return ThreadConfig{Scan: 20, Reachability: 20, DNS: 8}
	case hostCount <= 256: // /24 (most common home/office networks)
		return ThreadConfig{Scan: 40, Reachability: 30, DNS: 10}
	case hostCount <= 1024: // /22
		return ThreadConfig{Scan: 80, Reachability: 50, DNS: 15}
	default: // /16+ (large enterprise networks)
		return ThreadConfig{Scan: 150, Reachability: 80, DNS: 20}
	}
}

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
	// Terminal in raw mode versetzen für ANSI/VT-Codes und direkte Tasteneingaben (platform-specific)
	// WICHTIG: Muss VOR allen ANSI-Ausgaben erfolgen!
	_ = setupTerminal()

	// Calculate optimal thread counts based on network size
	threadConfig := calculateThreads(netCIDR, maxThreads)
	ones, bits := netCIDR.Mask.Size()
	hostCount := 1 << uint(bits-ones)
	fmt.Printf("🔧 Thread Config: Scan=%d, Reachability=%d, DNS=%d (Network: %s, %d potential hosts)\n",
		threadConfig.Scan, threadConfig.Reachability, threadConfig.DNS,
		netCIDR.String(), hostCount)

	// Clear screen and move cursor to home for clean UI start
	fmt.Print("\033[2J\033[H")

	// Geräte-Status-Map - Schlüssel ist IP-Adresse als String
	deviceStates := make(map[string]*DeviceState)

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

	// Keyboard-Listener für 'c' zum Kopieren, 'n'/'p' für Paging und ESC zum Beenden
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				continue
			}
			if buf[0] == 'c' || buf[0] == 'C' {
				keyChan <- rune(buf[0])
			} else if buf[0] == 'n' || buf[0] == 'N' {
				keyChan <- 'n' // Next page
			} else if buf[0] == 'p' || buf[0] == 'P' {
				keyChan <- 'p' // Previous page
			} else if buf[0] == 27 { // ESC key
				cancel() // Beende das Programm
				return
			}
		}
	}()

	scanCount := 0
	var redrawMutex sync.Mutex // Prevent concurrent redraws
	var activeThreads int32    // Tracks active background DNS lookup threads (atomic counter)
	var currentPage int32 = 1  // Current page for host list pagination (atomic for thread-safety)

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
				deviceStates[ipStr] = &DeviceState{
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
		drawBtopLayout(deviceStates, scanStart, network, watchInterval, watchMode, scanCount, scanDuration, nextScan, &activeThreads, &currentPage)

		// Clear any remaining lines from previous draw (if screen shrunk)
		fmt.Print("\033[J") // Clear from cursor to end of screen

		redrawMutex.Unlock()

		// Phase 1: Quick DNS lookups immediately after scan (blocks briefly for fast results)
		performInitialDNSLookups(ctx, deviceStates)

		// Phase 2: Start slow background lookups (mDNS/NetBIOS/LLMNR/HTTP) while countdown is running
		if nextScan > 0 {
			go performBackgroundDNSLookups(ctx, deviceStates, &activeThreads, threadConfig)

			// Show countdown with periodic table updates (pass scanStart for consistent uptime)
			showCountdownWithTableUpdates(ctx, nextScan, deviceStates, scanCount, scanDuration, scanStart, winchChan, keyChan, &redrawMutex, network, watchInterval, watchMode, &activeThreads, &currentPage, threadConfig)
		}
	}
}

func performScanQuiet(ctx context.Context, network string, netCIDR *net.IPNet, mode string, activeThreads *int32, threadConfig ThreadConfig) []scanner.Host {
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

func performHybridScanQuiet(ctx context.Context, netCIDR *net.IPNet, activeThreads *int32, threadConfig ThreadConfig) ([]scanner.Host, error) {
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

func performARPScanQuiet(ctx context.Context, netCIDR *net.IPNet, activeThreads *int32, threadConfig ThreadConfig) ([]scanner.Host, error) {
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

func performNormalScan(network string, mode string, activeThreads *int32, threadConfig ThreadConfig) ([]scanner.Host, error) {
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

func getHostname(host scanner.Host) string {
	if host.Hostname != "" {
		// DEBUG: Farbige Kennzeichnung für SSDP-gelernte Namen
		if host.HostnameSource == "SSDP" {
			return color.MagentaString(host.Hostname)
		}
		return host.Hostname
	}
	return "-"
}

func getVendor(host scanner.Host) string {
	if host.Vendor != "" {
		return host.Vendor
	}
	return "-"
}

// isLocallyAdministered checks if a MAC address is locally administered
// The second hex digit being 2, 6, A, or E indicates a locally administered address
func isLocallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	// Check the second character of the MAC address
	secondChar := strings.ToUpper(string(mac[1]))
	return secondChar == "2" || secondChar == "6" || secondChar == "A" || secondChar == "E"
}

// formatMAC formats MAC address with color coding for locally-administered addresses
// Returns the formatted string with proper padding to maintain column alignment
func formatMAC(mac string) string {
	if mac == "" || mac == "-" {
		return "-"
	}

	// Pad the MAC address to 18 characters first, then apply color
	// This ensures ANSI color codes don't affect column alignment
	paddedMAC := fmt.Sprintf("%-18s", mac)

	if isLocallyAdministered(mac) {
		// Yellow color for locally-administered MACs
		return color.YellowString(paddedMAC)
	}
	return paddedMAC
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

// padLeft pads string on the left (right-aligns) to specified width
// Used for numeric/duration alignment (like decimal tabs in DTP)
func padLeft(s string, width int) string {
	currentLen := runeLen(s)
	if currentLen >= width {
		return s
	}
	return strings.Repeat(" ", width-currentLen) + s
}

// safeRepeat verhindert negative repeat counts die zu Panics führen
func safeRepeat(str string, count int) string {
	if count < 0 {
		return ""
	}
	return strings.Repeat(str, count)
}

func moveCursorUp(lines int) {
	for i := 0; i < lines; i++ {
		fmt.Print("\033[A") // Move up one line
	}
	fmt.Print("\r") // Move to start of line
}

func clearLine() {
	fmt.Print("\033[2K\r") // Clear entire line and move to start
}

// printBoxLine prints a line within the box with proper padding
func printBoxLine(content string, width int) {
	// Calculate visible length (without ANSI codes, UTF-8 aware)
	visibleContent := stripANSI(content)
	visibleLen := runeLen(visibleContent)

	// -4 für: "║" (1) + " " (1) + " " (1) + "║" (1)
	padding := width - visibleLen - 4
	if padding < 0 {
		padding = 0
	}
	fmt.Print(color.CyanString("║"))
	fmt.Print(" " + content)
	fmt.Print(strings.Repeat(" ", padding))
	fmt.Print(color.CyanString(" ║\n"))
}

// stripANSI removes ANSI escape codes to get actual visible length
func stripANSI(s string) string {
	// UTF-8-sicherer Ansatz: Arbeite mit Runes, nicht Bytes
	result := ""
	inEscape := false
	runes := []rune(s)

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\033' {  // ESC character
			inEscape = true
			continue
		}
		if inEscape {
			// ANSI Escape-Sequenzen enden mit einem Buchstaben
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		result += string(r)
	}
	return result
}

// runeLen gibt die Display-Breite eines Strings zurück (berücksichtigt wide characters)
func runeLen(s string) int {
	return runewidth.StringWidth(s)
}

// padRight padded einen String rechts mit Leerzeichen bis zur gewünschten Rune-Länge
func padRight(s string, length int) string {
	currentLen := runeLen(s)
	if currentLen >= length {
		return s
	}
	return s + strings.Repeat(" ", length-currentLen)
}

// padRightANSI pads a string to a certain length, accounting for invisible ANSI color codes
func padRightANSI(s string, length int) string {
	// Calculate visible length (without ANSI codes)
	visibleLen := runeLen(stripANSI(s))
	if visibleLen >= length {
		return s
	}
	// Add spaces based on visual length
	return s + strings.Repeat(" ", length-visibleLen)
}

// printTableRow druckt eine Tabellenzeile mit korrektem Padding (UTF-8 + ANSI aware)
func printTableRow(content string, width int) {
	// Berechne sichtbare Länge (ohne ANSI codes)
	visibleContent := stripANSI(content)
	visibleLen := runeLen(visibleContent)
	// -4 für: "║" (1) + " " (1) + " " (1) + "║" (1)
	padding := width - visibleLen - 4

	// Safety: Wenn Inhalt zu lang ist (z.B. schmales Terminal), truncate statt negative padding
	if padding < 0 {
		// Content ist zu lang - kürzen auf verfügbare Breite
		maxContentLen := width - 4 // -4 für "║ " und " ║"
		if maxContentLen < 3 {
			maxContentLen = 3 // Mindestens 3 Zeichen
		}
		// Truncate content (UTF-8-aware)
		contentRunes := []rune(stripANSI(content))
		if len(contentRunes) > maxContentLen {
			content = string(contentRunes[:maxContentLen-1]) + "…"
		}
		// Recalculate
		visibleContent = stripANSI(content)
		visibleLen = runeLen(visibleContent)
		padding = width - visibleLen - 4
		if padding < 0 {
			padding = 0
		}
	}

	fmt.Print(color.CyanString("║"))
	fmt.Print(" " + content)
	fmt.Print(strings.Repeat(" ", padding))
	fmt.Print(color.CyanString(" ║\n"))
}

// captureScreenSimple speichert eine vereinfachte Text-Version des Screens
// HINWEIS: Dies ist eine Fallback-Lösung. Ideally würden wir das exakte Layout capturen
func captureScreenSimple(states map[string]*DeviceState, referenceTime time.Time, network string, interval time.Duration, mode string, scanCount int, scanDuration time.Duration, nextScanIn time.Duration) {
	screenBufferMux.Lock()
	defer screenBufferMux.Unlock()

	// Buffer zurücksetzen
	screenBuffer.Reset()

	// Generiere Screen-Content ohne ANSI-Farben für Zwischenablage
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()

	// Safety check: skip if terminal is too small
	if width < 20 {
		screenBuffer.WriteString("Terminal too small for capture\n")
		return
	}

	// Count stats
	onlineCount := 0
	offlineCount := 0
	totalFlaps := 0
	for _, state := range states {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
		totalFlaps += state.FlapCount
	}

	// Helper: schreibt eine Zeile mit korrektem Padding (UTF-8-aware)
	writeLine := func(content string) {
		contentRunes := runeLen(content)
		padding := width - contentRunes - 3 // -3 für "║ " und " ║"
		if padding < 0 {
			padding = 0
		}
		screenBuffer.WriteString("║ " + content + strings.Repeat(" ", padding) + " ║\n")
	}

	// Top border
	screenBuffer.WriteString("╔" + safeRepeat("═", width-2) + "╗\n")

	// Title line
	title := "NetSpy - Network Monitor"
	scanInfo := fmt.Sprintf("[Scan #%d]", scanCount)
	spacesNeeded := width - runeLen(title) - runeLen(scanInfo) - 3
	titleLine := title + safeRepeat(" ", spacesNeeded) + scanInfo
	writeLine(titleLine)

	// Separator
	screenBuffer.WriteString("╠" + safeRepeat("═", width-2) + "╣\n")

	// Info line 1
	line1 := fmt.Sprintf("Network: %s  │  Mode: %s  │  Interval: %v", network, mode, interval)
	writeLine(line1)

	// Info line 2
	line2 := fmt.Sprintf("Devices: %d (↑%d ↓%d)  │  Flaps: %d  │  Scan: %s",
		len(states), onlineCount, offlineCount, totalFlaps, formatDuration(scanDuration))
	writeLine(line2)

	// Separator
	screenBuffer.WriteString("╠" + safeRepeat("═", width-2) + "╣\n")

	// Table header und Rows (vereinfacht - zeigt nur IPs und Status)
	// Sortiere IPs
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Header
	header := "IP               Stat Hostname               Vendor       Uptime"
	writeLine(header)

	// Rows
	for _, ipStr := range ips {
		state := states[ipStr]
		statusIcon := "+"
		if state.Status == "offline" {
			statusIcon = "-"
		}

		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP = ipStr + " G"
		}
		if len(displayIP) > 16 {
			displayIP = displayIP[:16]
		}

		hostname := getHostname(state.Host)
		// Hostname auf max 22 Zeichen (Runes) begrenzen
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 22 {
			hostname = string(hostnameRunes[:21]) + "…"
		}

		// Vendor from MAC lookup
		vendor := getVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		// Vendor auf max 12 Zeichen begrenzen
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > 12 {
			vendor = string(vendorRunes[:11]) + "…"
		}

		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}

		// Manuelles Padding mit UTF-8-awareness
		paddedIP := padRight(displayIP, 17)      // 17 Zeichen für IP
		paddedHostname := padRight(hostname, 22) // 22 Zeichen für Hostname
		paddedVendor := padRight(vendor, 12)     // 12 Zeichen für Vendor
		paddedUptime := padLeft(formatDurationShort(statusDuration), 6) // Right-align (Dezimaltabulator)

		row := paddedIP + statusIcon + "    " + paddedHostname + " " + paddedVendor + " " + paddedUptime
		writeLine(row)
	}

	// Separator
	screenBuffer.WriteString("╠" + safeRepeat("═", width-2) + "╣\n")

	// Status line
	statusLine := fmt.Sprintf("▶ Next scan in: %s │ Press Ctrl+C to exit or 'c' to copy",
		formatDuration(nextScanIn))
	writeLine(statusLine)

	// Bottom border
	screenBuffer.WriteString("╚" + safeRepeat("═", width-2) + "╝\n")
}

// drawTerminalTooSmallWarning zeigt Warnung wenn Terminal zu klein ist
func drawTerminalTooSmallWarning(termSize output.TerminalSize, width int, scanCount int, activeThreads *int32) {
	// Absolute minimum check - if window is EXTREMELY small, just print simple message
	if width < 20 {
		fmt.Println("Terminal too small!")
		fmt.Printf("Min: 80x15, Current: %dx%d\n", termSize.Width, termSize.Height)
		fmt.Println("Please resize window.")
		return
	}

	// Top border
	fmt.Print(color.CyanString("╔"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╗\n"))

	// Title line (abgeschnitten falls nötig)
	gitVersion := getGitVersion()
	title := fmt.Sprintf("NetSpy - Network Monitor %s", gitVersion)
	threadCount := atomic.LoadInt32(activeThreads)
	scanInfo := fmt.Sprintf("[Threads #%d / Scan #%d]", threadCount, scanCount)

	// Berechne Padding und verhindere negative Werte
	paddingSpace := width - runeLen(title) - runeLen(scanInfo) - 4
	titleLine := title + safeRepeat(" ", paddingSpace) + scanInfo
	if runeLen(titleLine) > width-4 {
		maxLen := width - 7
		if maxLen < 0 {
			maxLen = 0
		}
		if maxLen > runeLen(titleLine) {
			maxLen = runeLen(titleLine)
		}
		titleLine = string([]rune(titleLine)[:maxLen]) + "..."
	}
	printBoxLine(titleLine, width)

	// Separator
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Warning message
	printBoxLine("", width) // Empty line
	warningMsg := color.YellowString("⚠ Terminal zu klein!")
	printBoxLine(warningMsg, width)
	printBoxLine("", width) // Empty line

	minMsg := "Minimum: 80 Spalten x 15 Zeilen (VT100 Standard)"
	printBoxLine(minMsg, width)

	currentMsg := fmt.Sprintf("Aktuell: %d Spalten x %d Zeilen", termSize.Width, termSize.Height)
	printBoxLine(currentMsg, width)

	printBoxLine("", width) // Empty line
	helpMsg := "Bitte vergrößern Sie das Terminal-Fenster."
	printBoxLine(helpMsg, width)
	printBoxLine("", width) // Empty line

	// Bottom border
	fmt.Print(color.CyanString("╚"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╝\n"))
}

// drawBtopLayout renders a btop-inspired fullscreen layout
func drawBtopLayout(states map[string]*DeviceState, referenceTime time.Time, network string, interval time.Duration, mode string, scanCount int, scanDuration time.Duration, nextScanIn time.Duration, activeThreads *int32, currentPage *int32) {
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()

	// Check if terminal is too small for display
	if termSize.IsTooSmall() {
		drawTerminalTooSmallWarning(termSize, width, scanCount, activeThreads)
		return
	}

	// Count stats
	onlineCount := 0
	offlineCount := 0
	totalFlaps := 0
	for _, state := range states {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
		totalFlaps += state.FlapCount
	}

	// ╔═══════════════════════════════════════════════════════════════╗
	// ║ NetSpy - Network Monitor                          [Scan #123] ║
	// ╠═══════════════════════════════════════════════════════════════╣
	// ║ Network: 10.0.0.0/24  │  Mode: hybrid  │  Interval: 30s      ║
	// ║ Devices: 15 (↑14 ↓1)  │  Flaps: 3      │  Scan: 2.3s         ║
	// ╠═══════════════════════════════════════════════════════════════╣
	// ║ IP Address    Status   Hostname         MAC      Type    RTT ║
	// ╟───────────────────────────────────────────────────────────────╢
	// ║ 10.0.0.1 [G]  online   gateway          aa:bb... Router  2ms ║
	// ╠═══════════════════════════════════════════════════════════════╣
	// ║ ▶ Next scan in: 28s │ Press Ctrl+C to exit                  ║
	// ╚═══════════════════════════════════════════════════════════════╝

	// Top border with title
	fmt.Print(color.CyanString("╔"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╗\n"))

	// Title line - use printBoxLine with properly constructed content
	// Get git version info
	gitVersion := getGitVersion()
	title := color.HiWhiteString(fmt.Sprintf("NetSpy - Network Monitor %s", gitVersion))
	// Load active thread count atomically
	threadCount := atomic.LoadInt32(activeThreads)
	scanInfo := color.HiYellowString(fmt.Sprintf("[Threads #%d / Scan #%d]", threadCount, scanCount))
	titleStripped := stripANSI(title)
	scanInfoStripped := stripANSI(scanInfo)
	spacesNeeded := width - runeLen(titleStripped) - runeLen(scanInfoStripped) - 4
	titleLine := title + safeRepeat(" ", spacesNeeded) + scanInfo
	printBoxLine(titleLine, width)

	// Separator
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Fixed column widths from left (not dynamically divided)
	// Content-based sizing instead of equal thirds
	// Total: col1(24) + sep(5) + col2(18) + sep(5) + col3(20) = 72 chars
	// Box: "║ " (2) + content(72) + padding(4) + " ║" (2) = 80 chars (VT100 Standard)
	col1Width := 24  // "Network: 10.0.0.0/24" + padding
	col2Width := 18  // "Mode : hybrid" + padding
	col3Width := 20  // "Interval: 30s" + padding

	// Dezimaltabulator: Labels mit Doppelpunkt vertikal aligned in jeder Spalte
	// Spalte 1: "Network" und "Devices" beide 7 chars → Doppelpunkt an Position 8
	// Spalte 2: "Mode" (4) und "Flaps" (5) → max 5 → Doppelpunkt an Position 6
	// Spalte 3: "Interval" (8) und "Scan" (4) → max 8 → Doppelpunkt an Position 9

	// Info line 1 (static - doesn't change)
	col1_line1 := padRight("Network: "+network, col1Width)
	col2_line1 := padRight(padRight("Mode", 5)+": "+mode, col2Width)
	intervalValue := fmt.Sprintf("%v", interval)
	col3_line1 := padRight(padRight("Interval", 8)+": "+intervalValue, col3Width)
	line1 := fmt.Sprintf("%s  │  %s  │  %s", col1_line1, col2_line1, col3_line1)
	printBoxLine(line1, width)

	// Info line 2 (dynamic - changes with each scan, but stays aligned)
	devicesValue := fmt.Sprintf("%d (%s%d %s%d)", len(states),
		color.GreenString("↑"), onlineCount,
		color.RedString("↓"), offlineCount)
	col1_line2 := padRightANSI("Devices: "+devicesValue, col1Width)
	flapsValue := fmt.Sprintf("%d", totalFlaps)
	col2_line2 := padRight(padRight("Flaps", 5)+": "+flapsValue, col2Width)
	scanValue := formatDuration(scanDuration)
	col3_line2 := padRight(padRight("Scan", 8)+": "+scanValue, col3Width)
	line2 := fmt.Sprintf("%s  │  %s  │  %s", col1_line2, col2_line2, col3_line2)
	printBoxLine(line2, width)

	// Separator before table (directly from info to table)
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Delegate to existing responsive table rendering
	redrawTable(states, referenceTime, currentPage, scanCount)

	// Separator before status line
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Status line (inside box) - use same fixed column widths as header
	col1Status := padRightANSI(color.CyanString("▶")+" Next scan in: "+color.CyanString(formatDuration(nextScanIn)), col1Width)
	col2Status := padRight("n/p: page, c: copy", col2Width)
	col3Status := padRight("[G]=GW [!]=Offline", col3Width)  // Gekürzt: GW statt Gateway für 80-Spalten-Limit
	statusLine := fmt.Sprintf("%s  │  %s  │  %s", col1Status, col2Status, col3Status)
	printBoxLine(statusLine, width)

	// Bottom border
	fmt.Print(color.CyanString("╚"))
	fmt.Print(color.CyanString(safeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╝\n"))

	// Capture screen content für späteres Kopieren - VEREINFACHT
	// Verwende die gleiche Logik wie oben, nur ohne Farben
	go captureScreenSimple(states, referenceTime, network, interval, mode, scanCount, scanDuration, nextScanIn)
}

// calculateMaxVisibleHosts berechnet wie viele Hosts auf den Bildschirm passen
// basierend auf der Terminal-Höhe
func calculateMaxVisibleHosts(termHeight int) int {
	// Layout-Overhead:
	// - Top Border: 1
	// - Title: 1
	// - Separator: 1
	// - Info Line 1: 1
	// - Info Line 2: 1
	// - Separator: 1
	// - Table Header: 1
	// = 7 Zeilen Header
	//
	// - Paging Info: 1
	// - Separator: 1
	// - Status Line: 1
	// - Bottom Border: 1
	// - Cursor Line (space after ╝): 1
	// = 5 Zeilen Footer
	//
	// Total: 12 Zeilen Overhead
	overhead := 12
	availableLines := termHeight - overhead

	// Mindestens 1 Host anzeigen (auch wenn Terminal sehr klein)
	if availableLines < 1 {
		return 1
	}

	return availableLines
}

func redrawTable(states map[string]*DeviceState, referenceTime time.Time, currentPage *int32, scanCount int) {
	// Hide cursor during redraw to prevent visible cursor jumping
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h") // Show cursor when done

	// Count stats
	onlineCount := 0
	offlineCount := 0
	for _, state := range states {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
	}

	// Get terminal size for responsive layout
	termSize := output.GetTerminalSize()

	// Choose layout based on terminal width
	if termSize.IsNarrow() {
		redrawNarrowTable(states, referenceTime, termSize, currentPage, scanCount)
	} else if termSize.IsMedium() {
		redrawMediumTable(states, referenceTime, termSize, currentPage, scanCount)
	} else {
		redrawWideTable(states, referenceTime, termSize, currentPage, scanCount)
	}
}

// redrawNarrowTable - Kompakte Ansicht für schmale Terminals (< 100 cols)
func redrawNarrowTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize, currentPage *int32, scanCount int) {
	width := termSize.GetDisplayWidth()

	// Table header - use padRight für UTF-8-aware padding
	headerContent := padRight("IP", 16) + " " +
		padRight("Hostname", 22) + " " +
		padRight("Vendor", 12) + " " +
		padRight("Uptime", 6)
	printTableRow(color.CyanString(headerContent), width)

	// Sort IPs (stable order for consistent paging)
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Calculate paging
	totalHosts := len(ips)
	maxVisible := calculateMaxVisibleHosts(termSize.Height)

	// Calculate total pages
	totalPages := (totalHosts + maxVisible - 1) / maxVisible
	if totalPages < 1 {
		totalPages = 1
	}

	// Ensure currentPage is within bounds
	page := atomic.LoadInt32(currentPage)
	if page < 1 {
		atomic.StoreInt32(currentPage, 1)
		page = 1
	}
	if int(page) > totalPages {
		atomic.StoreInt32(currentPage, int32(totalPages))
		page = int32(totalPages)
	}

	// Calculate slice range for current page
	startIdx := int(page-1) * maxVisible
	endIdx := startIdx + maxVisible
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	visibleIPs := ips[startIdx:endIdx]

	// Print each device
	for i, ipStr := range visibleIPs {
		state := states[ipStr]

		// Build IP with markers (Gateway, Offline, New)
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		// Mark as new if detected in last 2 scans (but not first scan)
		isNew := state.FirstSeenScan > 1 && (scanCount - state.FirstSeenScan) < 2
		if isNew {
			displayIP += " [+]"
		}

		// UTF-8-aware truncation
		displayIPRunes := []rune(displayIP)
		if len(displayIPRunes) > 16 {
			displayIP = string(displayIPRunes[:16])
		}

		// Color IP: red if offline, green if new, otherwise use zebra striping
		displayIPPadded := padRight(displayIP, 16)
		if state.Status == "offline" {
			displayIPPadded = color.RedString(displayIPPadded)
		} else if isNew {
			displayIPPadded = color.GreenString(displayIPPadded)
		} else if i%2 == 1 {
			// Zebra striping: odd rows darker
			displayIPPadded = color.New(color.FgHiBlack).Sprint(displayIPPadded)
		}

		hostname := getHostname(state.Host)
		// UTF-8-aware truncation
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 22 {
			hostname = string(hostnameRunes[:21]) + "…"
		}

		// Vendor from MAC lookup
		vendor := getVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		// UTF-8-aware truncation
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > 12 {
			vendor = string(vendorRunes[:11]) + "…"
		}

		// Calculate status duration
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}

		// Apply zebra striping to other columns (except IP which has its own color logic)
		hostnamePadded := padRight(hostname, 22)
		vendorPadded := padRight(vendor, 12)
		uptimePadded := padLeft(formatDurationShort(statusDuration), 6)

		if i%2 == 1 && state.Status != "offline" && !isNew {
			// Zebra striping for odd rows (only if not offline/new - they have priority colors)
			hostnamePadded = color.New(color.FgHiBlack).Sprint(hostnamePadded)
			vendorPadded = color.New(color.FgHiBlack).Sprint(vendorPadded)
			uptimePadded = color.New(color.FgHiBlack).Sprint(uptimePadded)
		}

		// Assemble row with UTF-8-aware padding
		rowContent := displayIPPadded + " " + hostnamePadded + " " + vendorPadded + " " + uptimePadded

		printTableRow(rowContent, width)
	}

	// Show paging indicator if multiple pages exist
	if totalPages > 1 {
		indicator := fmt.Sprintf("  Page %d/%d (%d hosts total) - Press 'n' for next, 'p' for previous", page, totalPages, totalHosts)
		printTableRow(color.CyanString(indicator), width)
	}
}

// redrawMediumTable - Standard-Ansicht für mittlere Terminals (100-139 cols)
func redrawMediumTable(states map[string]*DeviceState, _ time.Time, termSize output.TerminalSize, currentPage *int32, scanCount int) {
	width := termSize.GetDisplayWidth()

	// Table header - use padRight für UTF-8-aware padding
	headerContent := padRight("IP Address", 18) + " " +
		padRight("Hostname", 20) + " " +
		padRight("MAC Address", 18) + " " +
		padRight("Vendor", 15) + " " +
		padRight("Type", 12) + " " +
		padRight("RTT", 8) + " " +
		padRight("Flaps", 5)
	printTableRow(color.CyanString(headerContent), width)

	// Sort IPs (stable order for consistent paging)
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Calculate paging
	totalHosts := len(ips)
	maxVisible := calculateMaxVisibleHosts(termSize.Height)

	// Calculate total pages
	totalPages := (totalHosts + maxVisible - 1) / maxVisible
	if totalPages < 1 {
		totalPages = 1
	}

	// Ensure currentPage is within bounds
	page := atomic.LoadInt32(currentPage)
	if page < 1 {
		atomic.StoreInt32(currentPage, 1)
		page = 1
	}
	if int(page) > totalPages {
		atomic.StoreInt32(currentPage, int32(totalPages))
		page = int32(totalPages)
	}

	// Calculate slice range for current page
	startIdx := int(page-1) * maxVisible
	endIdx := startIdx + maxVisible
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	visibleIPs := ips[startIdx:endIdx]

	// Print each device
	for i, ipStr := range visibleIPs {
		state := states[ipStr]

		// Build IP with markers (Gateway, Offline, New)
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		// Mark as new if detected in last 2 scans (but not first scan)
		isNew := state.FirstSeenScan > 1 && (scanCount - state.FirstSeenScan) < 2
		if isNew {
			displayIP += " [+]"
		}

		// Color IP: red if offline, green if new, otherwise use zebra striping
		displayIPPadded := padRight(displayIP, 18)
		if state.Status == "offline" {
			displayIPPadded = color.RedString(displayIPPadded)
		} else if isNew {
			displayIPPadded = color.GreenString(displayIPPadded)
		} else if i%2 == 1 {
			// Zebra striping: odd rows darker
			displayIPPadded = color.New(color.FgHiBlack).Sprint(displayIPPadded)
		}

		hostname := getHostname(state.Host)
		// UTF-8-aware truncation
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 20 {
			hostname = string(hostnameRunes[:19]) + "…"
		}

		// Format MAC
		mac := state.Host.MAC
		if mac == "" {
			mac = "-"
		}
		macPadded := padRight(mac, 18)
		if isLocallyAdministered(mac) {
			macPadded = color.YellowString(macPadded)
		}

		// Vendor from MAC lookup
		vendor := getVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		// UTF-8-aware truncation
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > 15 {
			vendor = string(vendorRunes[:14]) + "…"
		}

		// Device type classification
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
		}
		// UTF-8-aware truncation
		deviceTypeRunes := []rune(deviceType)
		if len(deviceTypeRunes) > 12 {
			deviceType = string(deviceTypeRunes[:11]) + "…"
		}

		// Format RTT
		rttText := "-"
		if state.Host.RTT > 0 {
			rtt := state.Host.RTT
			if rtt < time.Millisecond {
				rttText = fmt.Sprintf("%.0fµs", float64(rtt.Microseconds()))
			} else {
				rttText = fmt.Sprintf("%.0fms", float64(rtt.Microseconds())/1000.0)
			}
		}

		// Format flap count - UTF-8 aware padding
		flapStr := fmt.Sprintf("%d", state.FlapCount)
		flapNum := padRight(flapStr, 5)
		if state.FlapCount > 0 {
			flapNum = color.YellowString(flapNum)
		}

		// Apply zebra striping to columns (except IP and Flaps which have their own color logic)
		hostnamePadded := padRight(hostname, 20)
		vendorPadded := padRight(vendor, 15)
		deviceTypePadded := padRight(deviceType, 12)
		rttPadded := padLeft(rttText, 8)

		if i%2 == 1 && state.Status != "offline" && !isNew {
			// Zebra striping for odd rows (only if not offline/new - they have priority colors)
			hostnamePadded = color.New(color.FgHiBlack).Sprint(hostnamePadded)
			// MAC only if not yellow (locally-administered)
			if !isLocallyAdministered(mac) {
				macPadded = color.New(color.FgHiBlack).Sprint(macPadded)
			}
			vendorPadded = color.New(color.FgHiBlack).Sprint(vendorPadded)
			deviceTypePadded = color.New(color.FgHiBlack).Sprint(deviceTypePadded)
			rttPadded = color.New(color.FgHiBlack).Sprint(rttPadded)
		}

		// Assemble row with UTF-8-aware padding
		rowContent := displayIPPadded + " " +
			hostnamePadded + " " +
			macPadded + " " +
			vendorPadded + " " +
			deviceTypePadded + " " +
			rttPadded + " " +
			flapNum

		printTableRow(rowContent, width)
	}

	// Show paging indicator if multiple pages exist
	if totalPages > 1 {
		indicator := fmt.Sprintf("  Page %d/%d (%d hosts total) - Press 'n' for next, 'p' for previous", page, totalPages, totalHosts)
		printTableRow(color.CyanString(indicator), width)
	}
}

// redrawWideTable - Volle Ansicht für breite Terminals (>= 140 cols)
func redrawWideTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize, currentPage *int32, scanCount int) {
	// Calculate dynamic column widths based on terminal size
	termWidth := termSize.GetDisplayWidth()

	// Fixed columns: IP(17) + MAC(18) + RTT(8) + FirstSeen(13) + Uptime(12) + Flaps(5) = 73
	// Spaces between columns: 8 spaces = 8
	// Borders: "║ " + " ║" = 4
	// Total fixed: 73 + 8 + 4 = 85
	// Remaining for Hostname + Vendor + Type
	remainingWidth := termWidth - 85

	// Distribute remaining width: 50% hostname, 25% vendor, 25% type (with minimums)
	hostnameWidth := max(20, min(40, int(float64(remainingWidth)*0.5)))
	vendorWidth := max(15, int(float64(remainingWidth)*0.25))
	typeWidth := max(12, remainingWidth-hostnameWidth-vendorWidth)

	// Table header with box drawing - use padRight for UTF-8 safety
	headerContent := padRight("IP Address", 17) + " " +
		padRight("Hostname", hostnameWidth) + " " +
		padRight("MAC Address", 18) + " " +
		padRight("Vendor", vendorWidth) + " " +
		padRight("Type", typeWidth) + " " +
		padRight("RTT", 8) + " " +
		padRight("First Seen", 13) + " " +
		padRight("Uptime", 12) + " " +
		padRight("Flaps", 5)

	printTableRow(color.CyanString(headerContent), termWidth)

	// Sort IPs (stable order for consistent paging)
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Calculate paging
	totalHosts := len(ips)
	maxVisible := calculateMaxVisibleHosts(termSize.Height)

	// Calculate total pages
	totalPages := (totalHosts + maxVisible - 1) / maxVisible
	if totalPages < 1 {
		totalPages = 1
	}

	// Ensure currentPage is within bounds
	page := atomic.LoadInt32(currentPage)
	if page < 1 {
		atomic.StoreInt32(currentPage, 1)
		page = 1
	}
	if int(page) > totalPages {
		atomic.StoreInt32(currentPage, int32(totalPages))
		page = int32(totalPages)
	}

	// Calculate slice range for current page
	startIdx := int(page-1) * maxVisible
	endIdx := startIdx + maxVisible
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	visibleIPs := ips[startIdx:endIdx]

	// Print each device
	for i, ipStr := range visibleIPs {
		state := states[ipStr]

		// Build IP with markers (Gateway, Offline, New)
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		// Mark as new if detected in last 2 scans (but not first scan)
		isNew := state.FirstSeenScan > 1 && (scanCount - state.FirstSeenScan) < 2
		if isNew {
			displayIP += " [+]"
		}

		// Color IP: red if offline, green if new, otherwise use zebra striping
		displayIPPadded := padRight(displayIP, 17)
		if state.Status == "offline" {
			displayIPPadded = color.RedString(displayIPPadded)
		} else if isNew {
			displayIPPadded = color.GreenString(displayIPPadded)
		} else if i%2 == 1 {
			// Zebra striping: odd rows darker
			displayIPPadded = color.New(color.FgHiBlack).Sprint(displayIPPadded)
		}

		// Hostname - use dynamic width with UTF-8 awareness
		hostname := getHostname(state.Host)
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > hostnameWidth {
			hostname = string(hostnameRunes[:hostnameWidth-1]) + "…"
		}
		hostnamePadded := padRight(hostname, hostnameWidth)

		// Format MAC address - handle color after padding
		mac := state.Host.MAC
		if mac == "" || mac == "-" {
			mac = "-"
		}
		macPadded := padRight(mac, 18)
		if isLocallyAdministered(mac) {
			macPadded = color.YellowString(macPadded)
		}

		// Vendor from MAC lookup - use dynamic width
		vendor := getVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > vendorWidth {
			vendor = string(vendorRunes[:vendorWidth-1]) + "…"
		}
		vendorPadded := padRight(vendor, vendorWidth)

		// Device type classification - use dynamic width
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
		}
		deviceTypeRunes := []rune(deviceType)
		if len(deviceTypeRunes) > typeWidth {
			deviceType = string(deviceTypeRunes[:typeWidth-1]) + "…"
		}
		deviceTypePadded := padRight(deviceType, typeWidth)

		firstSeen := state.FirstSeen.Format("15:04:05")
		firstSeenPadded := padRight(firstSeen, 13)

		// Calculate uptime/downtime based on status
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}
		uptimePadded := padLeft(formatDuration(statusDuration), 12)

		// Format RTT
		rttText := "-"
		if state.Host.RTT > 0 {
			rtt := state.Host.RTT
			if rtt < time.Millisecond {
				rttText = fmt.Sprintf("%.1fµs", float64(rtt.Microseconds()))
			} else if rtt < time.Second {
				rttText = fmt.Sprintf("%.1fms", float64(rtt.Microseconds())/1000.0)
			} else {
				rttText = fmt.Sprintf("%.2fs", rtt.Seconds())
			}
		}
		rttPadded := padLeft(rttText, 8)

		// Format flap count - UTF-8 aware padding
		flapStr := fmt.Sprintf("%d", state.FlapCount)
		flapNum := padRight(flapStr, 5)
		if state.FlapCount > 0 {
			flapNum = color.YellowString(flapNum)
		}

		// Apply zebra striping to non-colored columns (odd rows get darker)
		if i%2 == 1 && state.Status != "offline" && !isNew {
			hostnamePadded = color.New(color.FgHiBlack).Sprint(hostnamePadded)
			// MAC only if not yellow (locally-administered)
			if !isLocallyAdministered(mac) {
				macPadded = color.New(color.FgHiBlack).Sprint(macPadded)
			}
			vendorPadded = color.New(color.FgHiBlack).Sprint(vendorPadded)
			deviceTypePadded = color.New(color.FgHiBlack).Sprint(deviceTypePadded)
			rttPadded = color.New(color.FgHiBlack).Sprint(rttPadded)
			firstSeenPadded = color.New(color.FgHiBlack).Sprint(firstSeenPadded)
			uptimePadded = color.New(color.FgHiBlack).Sprint(uptimePadded)
		}

		// Manuelles Zusammenbauen der Row mit UTF-8-aware padding
		rowContent := displayIPPadded + " " +
			hostnamePadded + " " +
			macPadded + " " +
			vendorPadded + " " +
			deviceTypePadded + " " +
			rttPadded + " " + // Right-align (Dezimaltabulator)
			firstSeenPadded + " " +
			uptimePadded + " " + // Right-align (Dezimaltabulator)
			flapNum

		printTableRow(rowContent, termWidth)
	}

	// Show paging indicator if multiple pages exist
	if totalPages > 1 {
		indicator := fmt.Sprintf("  Page %d/%d (%d hosts total) - Press 'n' for next, 'p' for previous", page, totalPages, totalHosts)
		printTableRow(color.CyanString(indicator), termWidth)
	}
}

// updateHeaderLineOnly updates only the header line with thread count (fast, no flicker)
func updateHeaderLineOnly(scanCount int, activeThreads *int32) {
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()
	gitVersion := getGitVersion()
	title := color.HiWhiteString(fmt.Sprintf("NetSpy - Network Monitor %s", gitVersion))

	// Load active thread count atomically
	threadCount := atomic.LoadInt32(activeThreads)
	scanInfo := color.HiYellowString(fmt.Sprintf("[Threads #%d / Scan #%d]", threadCount, scanCount))

	titleStripped := stripANSI(title)
	scanInfoStripped := stripANSI(scanInfo)
	spacesNeeded := width - runeLen(titleStripped) - runeLen(scanInfoStripped) - 4
	titleLine := title + safeRepeat(" ", spacesNeeded) + scanInfo

	// Move cursor to line 2, column 1 (header line is 2nd line after top border)
	fmt.Print("\033[2;1H")
	// Print the updated header line
	printBoxLine(titleLine, width)
}

func showCountdownWithTableUpdates(ctx context.Context, duration time.Duration, states map[string]*DeviceState, scanCount int, scanDuration time.Duration, scanStart time.Time, winchChan <-chan os.Signal, keyChan <-chan rune, redrawMutex *sync.Mutex, network string, watchInterval time.Duration, watchMode string, activeThreads *int32, currentPage *int32, threadConfig ThreadConfig) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastRedraw := -1 // Track last redraw second to avoid double-redraw

	// Helper function to redraw entire screen with btop layout
	redrawFullScreen := func(refTime time.Time, currentScanDuration time.Duration, remaining time.Duration) {
		// Move to home and redraw (no clear = less flicker)
		fmt.Print("\033[H")
		// Draw btop-inspired layout (includes status line inside box)
		drawBtopLayout(states, refTime, network, watchInterval, watchMode, scanCount, currentScanDuration, remaining, activeThreads, currentPage)
		// Clear any leftover content
		fmt.Print("\033[J")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case key := <-keyChan:
			// Handle keyboard input
			if key == 'c' || key == 'C' {
				// Benutzer hat 'c' gedrückt - Kopiere Screen in Zwischenablage
				if err := copyScreenToClipboard(); err != nil {
					// Zeige Fehler kurz an (ohne Layout zu zerstören)
					fmt.Print("\r")
					fmt.Printf("%s %s ", color.RedString("✗"), err.Error())
					time.Sleep(2 * time.Second)
				} else {
					// Zeige Erfolg kurz an
					fmt.Print("\r")
					fmt.Printf("%s Screen in Zwischenablage kopiert! ", color.GreenString("✓"))
					time.Sleep(2 * time.Second)
				}
			} else if key == 'n' || key == 'N' {
				// Next page
				atomic.AddInt32(currentPage, 1)
				// Kurzes visuelles Feedback
				fmt.Print("\r")
				fmt.Printf("%s Next page... ", color.CyanString("→"))
				time.Sleep(300 * time.Millisecond)
			} else if key == 'p' || key == 'P' {
				// Previous page
				page := atomic.LoadInt32(currentPage)
				if page > 1 {
					atomic.AddInt32(currentPage, -1)
					// Kurzes visuelles Feedback
					fmt.Print("\r")
					fmt.Printf("%s Previous page... ", color.CyanString("←"))
					time.Sleep(300 * time.Millisecond)
				}
			}
			// Redraw screen nach Nachricht/Aktion
			redrawMutex.Lock()
			elapsed := time.Since(startTime)
			currentRefTime := scanStart.Add(elapsed)
			remaining := duration - elapsed
			if remaining < 0 {
				remaining = 0
			}
			redrawFullScreen(currentRefTime, scanDuration, remaining)
			redrawMutex.Unlock()
		case <-winchChan:
			// Try to acquire lock - skip if already redrawing
			if !redrawMutex.TryLock() {
				continue
			}

			// Terminal size changed - redraw entire screen
			elapsed := time.Since(startTime)
			currentRefTime := scanStart.Add(elapsed)

			remaining := duration - elapsed
			if remaining < 0 {
				remaining = 0
			}

			// Hide cursor during redraw
			fmt.Print("\033[?25l")

			// Full screen redraw (includes status line inside box)
			redrawFullScreen(currentRefTime, scanDuration, remaining)

			// Show cursor again
			fmt.Print("\033[?25h")

			redrawMutex.Unlock()
		case <-ticker.C:
			elapsed := time.Since(startTime)
			currentSecond := int(elapsed.Seconds())

			// Check if we're done BEFORE any processing
			if elapsed >= duration {
				return
			}

			// ALWAYS calculate remaining time fresh (accounts for any processing delays)
			remaining := duration - time.Since(startTime)
			if remaining < 0 {
				remaining = 0
			}

			// Every 5 seconds, do something useful: alternate between DNS updates and reachability checks
			// But only once per 5-second mark (avoid double-processing if slow)
			if currentSecond%5 == 0 && currentSecond != lastRedraw {
				lastRedraw = currentSecond

				// Alternate: DNS update on odd multiples (5, 15, 25...), reachability on even (10, 20, 30...)
				if (currentSecond/5)%2 == 1 {
					// DNS update: full screen redraw
					redrawMutex.Lock()
					currentRefTime := scanStart.Add(elapsed)
					redrawFullScreen(currentRefTime, scanDuration, remaining)
					redrawMutex.Unlock()
				} else {
					// Reachability check: quickly check if devices are still online
					performQuickReachabilityCheck(states, activeThreads, threadConfig)
					redrawMutex.Lock()
					currentRefTime := scanStart.Add(elapsed)
					redrawFullScreen(currentRefTime, scanDuration, remaining)
					redrawMutex.Unlock()
				}
			} else {
				// NOT a 5-second mark: Update only the header line with thread count (fast!)
				// This gives live thread count updates every second without full redraw flicker
				redrawMutex.Lock()
				updateHeaderLineOnly(scanCount, activeThreads)
				redrawMutex.Unlock()
			}
		}
	}
}

// performQuickReachabilityCheck quickly checks if online devices are still reachable
// Updates RTT and online/offline status without full ARP scan
func performQuickReachabilityCheck(deviceStates map[string]*DeviceState, activeThreads *int32, threadConfig ThreadConfig) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threadConfig.Reachability) // Dynamic based on network size

	for ipStr, state := range deviceStates {
		// Only check devices that were online
		if state.Status != "online" {
			continue
		}

		wg.Add(1)
		go func(ip string, s *DeviceState) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Increment active thread counter
			atomic.AddInt32(activeThreads, 1)
			defer atomic.AddInt32(activeThreads, -1)

			// Quick RTT check on the most likely port
			parsedIP := net.ParseIP(ip)
			if parsedIP == nil {
				return
			}

			// Try to measure RTT (same logic as measureRTTForHosts but faster timeout)
			measured := false
			start := time.Now()

			// Try common ports with short timeout
			ports := []string{"80", "443", "22", "445", "135"}
			for _, port := range ports {
				if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 200*time.Millisecond); err == nil {
					_ = conn.Close() // Ignore close error
					s.Host.RTT = time.Since(start)
					measured = true
					break
				}
			}

			// Update RTT and LastSeen if reachable
			// NOTE: We don't change online/offline status here - that's only done by full ARP scans
			// This is because many devices (IoT, phones with privacy) have no open ports
			if measured {
				now := time.Now()
				s.LastSeen = now
				// RTT already updated above
			}
			// If not measured, we just keep the old RTT - device might still be online but with no open ports
		}(ipStr, state)
	}

	wg.Wait()
}

func performBackgroundDNSLookups(ctx context.Context, deviceStates map[string]*DeviceState, activeThreads *int32, threadConfig ThreadConfig) {
	// Phase 2: Slow background lookups for hosts without DNS names
	// DNS was already tried in Phase 1 (performInitialDNSLookups)
	// This focuses on alternative methods: mDNS/Bonjour, NetBIOS, LLMNR, and HTTP
	// Only processes hosts without hostnames or retries after 5 minutes
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, threadConfig.DNS) // Dynamic based on network size

	retryInterval := 5 * time.Minute // Retry every 5 minutes if no hostname found

	for ipStr, state := range deviceStates {
		// Skip offline hosts
		if state.Status != "online" {
			continue
		}

		// Skip if we have a hostname AND last lookup was recent (< 5 min ago)
		if state.Host.Hostname != "" && time.Since(state.LastHostnameLookup) < retryInterval {
			continue
		}

		// Skip if no hostname but we tried recently (< 5 min ago)
		if state.Host.Hostname == "" && !state.LastHostnameLookup.IsZero() && time.Since(state.LastHostnameLookup) < retryInterval {
			continue
		}

		wg.Add(1)
		go func(ip string, s *DeviceState) {
			defer wg.Done()

			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				// Increment active thread counter
				atomic.AddInt32(activeThreads, 1)
				defer func() {
					// Decrement counter when done
					atomic.AddInt32(activeThreads, -1)
					<-semaphore
				}()
			}

			// Mark that we're attempting a lookup now
			s.LastHostnameLookup = time.Now()

			// Use the new comprehensive hostname resolution (now includes HTTP!)
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				result := discovery.ResolveBackground(parsedIP, 3*time.Second) // Increased timeout
				if result.Hostname != "" {
					s.Host.Hostname = result.Hostname
					s.Host.HostnameSource = result.Source
				}
			}

			// Update device type after hostname is resolved
			if s.Host.Hostname != "" || s.Host.HostnameSource != "" {
				s.Host.DeviceType = discovery.DetectDeviceType(
					s.Host.Hostname,
					s.Host.MAC,
					s.Host.Vendor,
					s.Host.Ports,
				)
			}
		}(ipStr, state)
	}

	wg.Wait()
}

// performInitialDNSLookups performs fast DNS lookups immediately after scan
// Only uses DNS (no mDNS/NetBIOS/etc) for quick wins
func performInitialDNSLookups(ctx context.Context, deviceStates map[string]*DeviceState) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // High concurrency for fast DNS

	for ipStr, state := range deviceStates {
		// Skip offline hosts
		if state.Status != "online" {
			continue
		}

		// Skip if we already have a hostname
		if state.Host.Hostname != "" {
			continue
		}

		wg.Add(1)
		go func(ip string, s *DeviceState) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			}

			// Only DNS - super fast!
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				if names, err := net.LookupAddr(parsedIP.String()); err == nil && len(names) > 0 {
					hostname := names[0]
					// Clean hostname
					hostname = strings.TrimSuffix(hostname, ".")
					hostname = strings.TrimSpace(hostname)

					if hostname != "" {
						s.Host.Hostname = hostname
						s.Host.HostnameSource = "dns"
						s.LastHostnameLookup = time.Now()

						// Update device type
						s.Host.DeviceType = discovery.DetectDeviceType(
							s.Host.Hostname,
							s.Host.MAC,
							s.Host.Vendor,
							s.Host.Ports,
						)
					}
				}
			}
		}(ipStr, state)
	}

	wg.Wait()
}

// populateFromDNSCache fills deviceStates with cached DNS names from system DNS cache
// This is instant (< 100ms) and provides hostnames for recently accessed devices
func populateFromDNSCache(deviceStates map[string]*DeviceState) {
	cache := discovery.ReadDNSCache()

	for ip, hostname := range cache {
		if state, exists := deviceStates[ip]; exists {
			// Only populate if we don't already have a hostname
			if state.Host.Hostname == "" {
				state.Host.Hostname = hostname
				state.Host.HostnameSource = "dns-cache"

				// Update device type based on hostname
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

func compareIPs(ip1, ip2 string) bool {
	// Parse IPs for proper binary comparison
	parsedIP1 := net.ParseIP(ip1)
	parsedIP2 := net.ParseIP(ip2)

	if parsedIP1 == nil || parsedIP2 == nil {
		// Fallback to string comparison if parsing fails
		return ip1 < ip2
	}

	// Convert to 4-byte representation for IPv4
	parsedIP1 = parsedIP1.To4()
	parsedIP2 = parsedIP2.To4()

	if parsedIP1 == nil || parsedIP2 == nil {
		// Fallback to string comparison
		return ip1 < ip2
	}

	// Compare byte by byte
	for i := 0; i < len(parsedIP1); i++ {
		if parsedIP1[i] != parsedIP2[i] {
			return parsedIP1[i] < parsedIP2[i]
		}
	}

	return false
}

// populateAndStreamARP removed - now using populateARPTableQuiet() for batch scanning

func parseNetworkInputSimple(network *net.IPNet) []net.IP {
	// Use the already-fixed function from discovery package
	return discovery.GenerateIPsFromCIDR(network)
}

// NetworkInterface represents a detected network interface with its subnet
type NetworkInterface struct {
	Name    string
	IP      string
	Network string // CIDR notation
}

// detectAndSelectNetwork detects available network interfaces and prompts user to select one
func detectAndSelectNetwork() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to detect network interfaces: %v", err)
	}

	// Use a map to deduplicate networks (same CIDR might appear on multiple interfaces)
	networkMap := make(map[string]NetworkInterface)

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
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
				// Skip if we can't get the network
				continue
			}

			// Only IPv4 for now
			if ip == nil || ip.To4() == nil {
				continue
			}

			// Get the network address (not the host IP)
			networkAddr := ipNet.IP.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			networkCIDR := fmt.Sprintf("%s/%d", networkAddr.String(), ones)

			// Store by network CIDR to deduplicate
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

	// Convert map to slice for ordering
	var availableNetworks []NetworkInterface
	for _, netif := range networkMap {
		availableNetworks = append(availableNetworks, netif)
	}

	// If only one network, use it automatically
	if len(availableNetworks) == 1 {
		color.Cyan(" Auto-detected network: %s (your IP: %s on %s)\n\n",
			availableNetworks[0].Network,
			availableNetworks[0].IP,
			availableNetworks[0].Name)
		return availableNetworks[0].Network, nil
	}

	// Multiple networks - ask user to select
	color.Cyan(" Multiple networks detected:\n\n")

	for i, netif := range availableNetworks {
		fmt.Printf("  %d. %s (your IP: %s on %s)\n",
			i+1,
			netif.Network,
			netif.IP,
			netif.Name)
	}

	fmt.Print("\nSelect network [1-", len(availableNetworks), "]: ")

	var selection int
	_, err = fmt.Scanln(&selection)
	if err != nil || selection < 1 || selection > len(availableNetworks) {
		return "", fmt.Errorf("invalid selection")
	}

	selectedNetwork := availableNetworks[selection-1]
	color.Green(" Selected: %s (your IP: %s on %s)\n\n",
		selectedNetwork.Network,
		selectedNetwork.IP,
		selectedNetwork.Name)

	return selectedNetwork.Network, nil
}

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
