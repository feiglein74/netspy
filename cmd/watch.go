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
	"syscall"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/output"
	"netspy/pkg/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	watchInterval   time.Duration
	watchMode       string
	screenBuffer    bytes.Buffer // Buffer für aktuellen Screen-Inhalt
	screenBufferMux sync.Mutex   // Mutex für Thread-Safe Zugriff
)

// DeviceState verfolgt den Zustand eines entdeckten Geräts über die Zeit
type DeviceState struct {
	Host             scanner.Host
	FirstSeen        time.Time
	LastSeen         time.Time
	Status           string        // "online" or "offline"
	StatusSince      time.Time     // When current status started
	FlapCount        int           // Number of times status has changed (flapping counter)
	TotalOfflineTime time.Duration // Accumulated time spent offline (for continuous uptime calculation)
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

	// Geräte-Status-Map - Schlüssel ist IP-Adresse als String
	deviceStates := make(map[string]*DeviceState)

	// Signal-Handling für graceful Shutdown und Window-Resize einrichten
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Window size change signal
	winchChan := make(chan os.Signal, 1)
	signal.Notify(winchChan, syscall.SIGWINCH)

	// Keyboard input channel für 'c' zum Kopieren
	keyChan := make(chan rune, 10)

	// Terminal in raw mode versetzen für direkte Tasteneingaben (macOS/Linux)
	rawModeCmd := exec.Command("stty", "-icanon", "min", "1", "-echo")
	rawModeCmd.Stdin = os.Stdin
	_ = rawModeCmd.Run()

	// Stelle sicher, dass wir beim Exit wieder zurücksetzen
	defer func() {
		resetCmd := exec.Command("stty", "icanon", "echo")
		resetCmd.Stdin = os.Stdin
		_ = resetCmd.Run()
	}()

	go func() {
		sig := <-sigChan
		fmt.Printf("\n\n[!] Received signal %v, shutting down...\n", sig)
		// Terminal-State wiederherstellen
		resetCmd := exec.Command("stty", "icanon", "echo")
		resetCmd.Stdin = os.Stdin
		_ = resetCmd.Run()
		cancel()
	}()

	// Keyboard-Listener für 'c' zum Kopieren
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				continue
			}
			if buf[0] == 'c' || buf[0] == 'C' {
				keyChan <- rune(buf[0])
			}
		}
	}()

	scanCount := 0
	var redrawMutex sync.Mutex // Prevent concurrent redraws

	for {
		// Check if context is cancelled before starting new scan
		if ctx.Err() != nil {
			fmt.Println("\n[OK] Shutdown complete")
			return nil
		}

		scanCount++
		scanStart := time.Now()

		// Perform scan quietly (no output during scan)
		hosts := performScanQuiet(ctx, network, netCIDR, watchMode)

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

				// Preserve hostname and source if already resolved
				oldHostname := state.Host.Hostname
				oldSource := state.Host.HostnameSource

				state.Host = host // Update host info (MAC, RTT, etc.)

				// Restore hostname if it was already resolved
				if oldSource != "" {
					state.Host.Hostname = oldHostname
					state.Host.HostnameSource = oldSource
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
					Host:        host,
					FirstSeen:   scanStart,
					LastSeen:    scanStart,
					Status:      "online",
					StatusSince: scanStart,
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

		// Lock to prevent concurrent redraws (scan vs SIGWINCH)
		redrawMutex.Lock()

		// Clear screen and redraw everything (fullscreen mode)
		fmt.Print("\033[2J\033[H") // Clear screen + move to home

		// Calculate next scan time for status display
		nextScan := watchInterval - scanDuration
		if nextScan < 0 {
			nextScan = 0
		}

		// Draw btop-inspired layout (includes status line now)
		drawBtopLayout(deviceStates, scanStart, network, watchInterval, watchMode, scanCount, scanDuration, nextScan)

		redrawMutex.Unlock()

		// Start background DNS lookups while countdown is running
		if nextScan > 0 {
			go performBackgroundDNSLookups(ctx, deviceStates)

			// Show countdown with periodic table updates (pass scanStart for consistent uptime)
			showCountdownWithTableUpdates(ctx, nextScan, deviceStates, scanCount, scanDuration, scanStart, winchChan, keyChan, &redrawMutex, network, watchInterval, watchMode)
		}
	}
}

func performScanQuiet(ctx context.Context, network string, netCIDR *net.IPNet, mode string) []scanner.Host {
	var hosts []scanner.Host
	var err error

	switch mode {
	case "hybrid":
		hosts, err = performHybridScanQuiet(ctx, netCIDR)
	case "arp":
		hosts, err = performARPScanQuiet(ctx, netCIDR)
	case "fast", "thorough", "conservative":
		hosts, err = performNormalScan(network, mode)
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

func performHybridScanQuiet(ctx context.Context, netCIDR *net.IPNet) ([]scanner.Host, error) {
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

	// Fallback zu TCP-Scanning wenn keine ARP-Hosts gefunden (fremdes Subnet oder ARP fehlgeschlagen)
	if len(finalHosts) == 0 {
		// Generate all IPs in network
		ips := discovery.GenerateIPsFromCIDR(netCIDR)

		// Scanner configuration (conservative mode for watch)
		config := scanner.Config{
			Concurrency: 40,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}

		s := scanner.New(config)
		tcpHosts, err := s.ScanHosts(ips)
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

func performARPScanQuiet(ctx context.Context, netCIDR *net.IPNet) ([]scanner.Host, error) {
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

		// Scanner configuration (conservative mode for watch)
		config := scanner.Config{
			Concurrency: 40,
			Timeout:     500 * time.Millisecond,
			Fast:        false,
			Thorough:    false,
			Quiet:       true,
		}

		s := scanner.New(config)
		tcpHosts, err := s.ScanHosts(ips)
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

func performNormalScan(network string, mode string) ([]scanner.Host, error) {
	hosts, err := parseNetworkInput(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network specification: %v", err)
	}

	// Set the global scanMode so createScanConfig() uses the right settings
	scanMode = mode

	config := createScanConfig()
	config.Quiet = true // Suppress verbose output in watch mode
	s := scanner.New(config)

	results, err := s.ScanHosts(hosts)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	return results, nil
}

// Old print functions removed - now using redrawTable() for static table updates

func getHostname(host scanner.Host) string {
	if host.Hostname != "" {
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
	// Calculate visible length (without ANSI codes)
	visibleLen := len(stripANSI(content))
	padding := width - visibleLen - 3 // -3 for "║ " and " ║"
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
	// Simple regex-free approach: count non-escape characters
	result := ""
	inEscape := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if (s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z') {
				inEscape = false
			}
			continue
		}
		result += string(s[i])
	}
	return result
}

// runeLen gibt die Anzahl der Runes (Zeichen) in einem String zurück
func runeLen(s string) int {
	return len([]rune(s))
}

// padRight padded einen String rechts mit Leerzeichen bis zur gewünschten Rune-Länge
func padRight(s string, length int) string {
	currentLen := runeLen(s)
	if currentLen >= length {
		return s
	}
	return s + strings.Repeat(" ", length-currentLen)
}

// printTableRow druckt eine Tabellenzeile mit korrektem Padding (UTF-8 + ANSI aware)
func printTableRow(content string, width int) {
	// Berechne sichtbare Länge (ohne ANSI codes)
	visibleContent := stripANSI(content)
	visibleLen := runeLen(visibleContent)
	padding := width - visibleLen - 3 // -3 for "║ " and " ║"
	if padding < 0 {
		padding = 0
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
	screenBuffer.WriteString("╔" + strings.Repeat("═", width-2) + "╗\n")

	// Title line
	title := "NetSpy - Network Monitor"
	scanInfo := fmt.Sprintf("[Scan #%d]", scanCount)
	spacesNeeded := width - runeLen(title) - runeLen(scanInfo) - 3
	if spacesNeeded < 0 {
		spacesNeeded = 0
	}
	titleLine := title + strings.Repeat(" ", spacesNeeded) + scanInfo
	writeLine(titleLine)

	// Separator
	screenBuffer.WriteString("╠" + strings.Repeat("═", width-2) + "╣\n")

	// Info line 1
	line1 := fmt.Sprintf("Network: %s  │  Mode: %s  │  Interval: %v", network, mode, interval)
	writeLine(line1)

	// Info line 2
	line2 := fmt.Sprintf("Devices: %d (↑%d ↓%d)  │  Flaps: %d  │  Scan: %s",
		len(states), onlineCount, offlineCount, totalFlaps, formatDuration(scanDuration))
	writeLine(line2)

	// Separator
	screenBuffer.WriteString("╠" + strings.Repeat("═", width-2) + "╣\n")

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
	header := "IP               Stat Hostname           Uptime"
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
		// Hostname auf max 18 Zeichen (Runes) begrenzen
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 18 {
			hostname = string(hostnameRunes[:17]) + "…"
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
		paddedHostname := padRight(hostname, 18) // 18 Zeichen für Hostname
		paddedUptime := padRight(formatDurationShort(statusDuration), 8)

		row := paddedIP + statusIcon + "    " + paddedHostname + paddedUptime
		writeLine(row)
	}

	// Separator
	screenBuffer.WriteString("╠" + strings.Repeat("═", width-2) + "╣\n")

	// Status line
	statusLine := fmt.Sprintf("▶ Next scan in: %s │ Press Ctrl+C to exit or 'c' to copy",
		formatDuration(nextScanIn))
	writeLine(statusLine)

	// Bottom border
	screenBuffer.WriteString("╚" + strings.Repeat("═", width-2) + "╝\n")
}

// drawBtopLayout renders a btop-inspired fullscreen layout
func drawBtopLayout(states map[string]*DeviceState, referenceTime time.Time, network string, interval time.Duration, mode string, scanCount int, scanDuration time.Duration, nextScanIn time.Duration) {
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()

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
	fmt.Print(color.CyanString(strings.Repeat("═", width-2)))
	fmt.Print(color.CyanString("╗\n"))

	// Title line - use printBoxLine with properly constructed content
	title := color.HiWhiteString(" NetSpy - Network Monitor")
	scanInfo := color.HiYellowString(fmt.Sprintf("[Scan #%d]", scanCount))
	titleLine := title + strings.Repeat(" ", width-len(stripANSI(title))-len(stripANSI(scanInfo))-3) + scanInfo
	printBoxLine(titleLine, width)

	// Separator
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(strings.Repeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Info line 1
	line1 := fmt.Sprintf(" Network: %s  │  Mode: %s  │  Interval: %v", network, mode, interval)
	printBoxLine(line1, width)

	// Info line 2
	line2 := fmt.Sprintf(" Devices: %d (%s%d %s%d)  │  Flaps: %d  │  Scan: %s",
		len(states),
		color.GreenString("↑"), onlineCount,
		color.RedString("↓"), offlineCount,
		totalFlaps,
		formatDuration(scanDuration))
	printBoxLine(line2, width)

	// Separator before table (directly from info to table)
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(strings.Repeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Delegate to existing responsive table rendering
	redrawTable(states, referenceTime)

	// Separator before status line
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(strings.Repeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Status line (inside box)
	statusLine := fmt.Sprintf(" %s Next scan in: %s │ Press Ctrl+C to exit or 'c' to copy",
		color.HiBlackString("▶"),
		color.CyanString(formatDuration(nextScanIn)))
	printBoxLine(statusLine, width)

	// Bottom border
	fmt.Print(color.CyanString("╚"))
	fmt.Print(color.CyanString(strings.Repeat("═", width-2)))
	fmt.Print(color.CyanString("╝\n"))

	// Capture screen content für späteres Kopieren - VEREINFACHT
	// Verwende die gleiche Logik wie oben, nur ohne Farben
	go captureScreenSimple(states, referenceTime, network, interval, mode, scanCount, scanDuration, nextScanIn)
}

func redrawTable(states map[string]*DeviceState, referenceTime time.Time) {
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
		redrawNarrowTable(states, referenceTime, termSize)
	} else if termSize.IsMedium() {
		redrawMediumTable(states, referenceTime, termSize)
	} else {
		redrawWideTable(states, referenceTime, termSize)
	}
}

// redrawNarrowTable - Kompakte Ansicht für schmale Terminals (< 100 cols)
func redrawNarrowTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize) {
	width := termSize.GetDisplayWidth()

	// Table header with box drawing
	// Content: " IP(16) Stat(4) Hostname(18) Uptime(8) " = 48 chars + 3 spaces = 51
	// Plus: "║ " (2) and " ║" (2) = 55 total
	fmt.Print(color.CyanString("║"))
	fmt.Print(color.CyanString(" %-16s %-4s %-18s %-8s", "IP", "Stat", "Hostname", "Uptime"))
	contentLen := 1 + 16 + 1 + 4 + 1 + 18 + 1 + 8 // "║ " + columns + spaces
	padLen := width - contentLen - 2 // -2 for final " ║"
	if padLen < 0 {
		padLen = 0
	}
	fmt.Print(strings.Repeat(" ", padLen))
	fmt.Print(color.CyanString(" ║\n"))

	// Sort IPs
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Print each device
	for _, ipStr := range ips {
		state := states[ipStr]

		statusIcon := "+"
		statusColor := color.GreenString
		if state.Status == "offline" {
			statusIcon = "-"
			statusColor = color.RedString
		}

		// Check if this is the gateway and add marker to IP
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP = ipStr + " G"
		}
		if len(displayIP) > 16 {
			displayIP = displayIP[:16]
		}

		hostname := getHostname(state.Host)
		if len(hostname) > 16 {
			hostname = hostname[:13] + "…"
		}

		// Calculate status duration
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}

		// Format and pad before coloring to maintain alignment
		coloredStatus := statusColor(fmt.Sprintf("%-3s", ""))

		// Device row with box drawing
		fmt.Print(color.CyanString("║"))
		fmt.Printf(" %-16s %s%s %-18s %-8s",
			displayIP,
			statusIcon,
			coloredStatus,
			hostname,
			formatDurationShort(statusDuration),
		)
		padLen = width - contentLen - 2 // Same calculation as header
		if padLen < 0 {
			padLen = 0
		}
		fmt.Print(strings.Repeat(" ", padLen))
		fmt.Print(color.CyanString(" ║\n"))
	}
}

// redrawMediumTable - Standard-Ansicht für mittlere Terminals (100-139 cols)
func redrawMediumTable(states map[string]*DeviceState, _ time.Time, termSize output.TerminalSize) {
	width := termSize.GetDisplayWidth()

	// Table header with box drawing
	// Content: " IP(18) Status(11) Hostname(20) MAC(18) Type(14) RTT(8) Flaps(5) "
	// = 18+11+20+18+14+8+5 = 94 chars + 6 spaces = 100
	// Plus "║ " (2) and " ║" (2) = 104 total
	fmt.Print(color.CyanString("║"))
	fmt.Print(color.CyanString(" %-18s %-11s %-20s %-18s %-14s %-8s %-5s",
		"IP Address", "Status", "Hostname", "MAC Address", "Device Type", "RTT", "Flaps"))
	contentLen := 1 + 18 + 1 + 11 + 1 + 20 + 1 + 18 + 1 + 14 + 1 + 8 + 1 + 5
	padLen := width - contentLen - 2
	if padLen < 0 {
		padLen = 0
	}
	fmt.Print(strings.Repeat(" ", padLen))
	fmt.Print(color.CyanString(" ║\n"))

	// Sort IPs
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Print each device
	for _, ipStr := range ips {
		state := states[ipStr]

		statusIcon := "[+]"
		statusColor := color.GreenString
		statusText := "online"
		if state.Status == "offline" {
			statusIcon = "[-]"
			statusColor = color.RedString
			statusText = "offline"
		}

		// Check if this is the gateway and add marker to IP
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP = ipStr + " [G]"
		}

		hostname := getHostname(state.Host)
		if len(hostname) > 18 {
			hostname = hostname[:15] + "…"
		}

		// Format MAC
		mac := state.Host.MAC
		if mac == "" {
			mac = "-"
		}

		// Show device type if available, otherwise show vendor
		deviceInfo := state.Host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = getVendor(state.Host)
		}
		if len(deviceInfo) > 12 {
			deviceInfo = deviceInfo[:9] + "…"
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

		// Format flap count - pad before coloring
		flapNum := fmt.Sprintf("%-5s", fmt.Sprintf("%d", state.FlapCount))
		if state.FlapCount > 0 {
			flapNum = color.YellowString(flapNum)
		}

		// Pad status text before coloring
		coloredStatus := statusColor(fmt.Sprintf("%-7s", statusText))

		// Device row with box drawing
		fmt.Print(color.CyanString("║"))
		fmt.Printf(" %-18s %s %s %-20s %-18s %-14s %-8s %s",
			displayIP,
			statusIcon,
			coloredStatus,
			hostname,
			mac,
			deviceInfo,
			rttText,
			flapNum,
		)
		padLen = width - contentLen - 2
		if padLen < 0 {
			padLen = 0
		}
		fmt.Print(strings.Repeat(" ", padLen))
		fmt.Print(color.CyanString(" ║\n"))
	}
}

// redrawWideTable - Volle Ansicht für breite Terminals (>= 140 cols)
func redrawWideTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize) {
	// Calculate dynamic column widths based on terminal size
	termWidth := termSize.GetDisplayWidth()

	// Fixed columns: IP(20) + Status(10) + MAC(18) + RTT(8) + FirstSeen(13) + Uptime(16) + Flaps(5) = 90
	// Spaces between columns: 8 spaces = 8
	// Total fixed: 98
	// Remaining for Hostname + DeviceType
	remainingWidth := termWidth - 98

	// Distribute remaining width: 60% hostname, 40% deviceType (with minimums)
	hostnameWidth := max(25, min(50, int(float64(remainingWidth)*0.6)))
	deviceTypeWidth := max(17, remainingWidth-hostnameWidth)

	// Table header with box drawing - use padRight for UTF-8 safety
	headerContent := padRight("IP Address", 20) + " " +
		padRight("Status", 10) + " " +
		padRight("Hostname", hostnameWidth) + " " +
		padRight("MAC Address", 18) + " " +
		padRight("Device Type", deviceTypeWidth) + " " +
		padRight("RTT", 8) + " " +
		padRight("First Seen", 13) + " " +
		padRight("Uptime/Down", 16) + " " +
		padRight("Flaps", 5)

	printTableRow(color.CyanString(headerContent), termWidth)

	// Sort IPs
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Print each device
	for _, ipStr := range ips {
		state := states[ipStr]

		statusIcon := "[+]"
		statusColor := color.GreenString
		statusText := "online"
		if state.Status == "offline" {
			statusIcon = "[-]"
			statusColor = color.RedString
			statusText = "offline"
		}

		// Check if this is the gateway and add marker to IP
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP = ipStr + " [G]"
		}

		// Hostname - use dynamic width with UTF-8 awareness
		hostname := getHostname(state.Host)
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > hostnameWidth {
			hostname = string(hostnameRunes[:hostnameWidth-1]) + "…"
		}

		// Format MAC address - handle color after padding
		mac := state.Host.MAC
		if mac == "" || mac == "-" {
			mac = "-"
		}
		macPadded := padRight(mac, 18)
		if isLocallyAdministered(mac) {
			macPadded = color.YellowString(macPadded)
		}

		// Show device type if available, otherwise show vendor - use dynamic width
		deviceInfo := state.Host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = getVendor(state.Host)
		}
		deviceInfoRunes := []rune(deviceInfo)
		if len(deviceInfoRunes) > deviceTypeWidth {
			deviceInfo = string(deviceInfoRunes[:deviceTypeWidth-1]) + "…"
		}

		firstSeen := state.FirstSeen.Format("15:04:05")

		// Calculate uptime/downtime based on status
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}

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

		// Format flap count - UTF-8 aware padding
		flapStr := fmt.Sprintf("%d", state.FlapCount)
		flapNum := padRight(flapStr, 5)
		if state.FlapCount > 0 {
			flapNum = color.YellowString(flapNum)
		}

		// Pad status text before coloring
		coloredStatus := statusColor(padRight(statusText, 6))

		// Manuelles Zusammenbauen der Row mit UTF-8-aware padding
		rowContent := padRight(displayIP, 20) + " " +
			statusIcon + " " +
			coloredStatus + " " +
			padRight(hostname, hostnameWidth) + " " +
			macPadded + " " +
			padRight(deviceInfo, deviceTypeWidth) + " " +
			padRight(rttText, 8) + " " +
			padRight(firstSeen, 13) + " " +
			padRight(formatDuration(statusDuration), 16) + " " +
			flapNum

		printTableRow(rowContent, termWidth)
	}
}

func showCountdownWithTableUpdates(ctx context.Context, duration time.Duration, states map[string]*DeviceState, scanCount int, scanDuration time.Duration, scanStart time.Time, winchChan <-chan os.Signal, keyChan <-chan rune, redrawMutex *sync.Mutex, network string, watchInterval time.Duration, watchMode string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastRedraw := -1 // Track last redraw second to avoid double-redraw

	// Helper function to redraw entire screen with btop layout
	redrawFullScreen := func(refTime time.Time, currentScanDuration time.Duration, remaining time.Duration) {
		// Clear screen and move to home
		fmt.Print("\033[2J\033[H")
		// Draw btop-inspired layout (includes status line inside box)
		drawBtopLayout(states, refTime, network, watchInterval, watchMode, scanCount, currentScanDuration, remaining)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-keyChan:
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
			// Redraw screen nach Nachricht
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
					performQuickReachabilityCheck(states)
					redrawMutex.Lock()
					currentRefTime := scanStart.Add(elapsed)
					redrawFullScreen(currentRefTime, scanDuration, remaining)
					redrawMutex.Unlock()
				}
			}
		}
	}
}

// performQuickReachabilityCheck quickly checks if online devices are still reachable
// Updates RTT and online/offline status without full ARP scan
func performQuickReachabilityCheck(deviceStates map[string]*DeviceState) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 30) // Limit concurrent checks

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

func performBackgroundDNSLookups(ctx context.Context, deviceStates map[string]*DeviceState) {
	// Perform comprehensive hostname lookups for all online hosts in the background
	// Uses: DNS, mDNS/Bonjour, NetBIOS, and LLMNR
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent lookups

	for ipStr, state := range deviceStates {
		// Only lookup for online hosts that don't have a hostname yet AND haven't been resolved before
		if state.Status != "online" || state.Host.Hostname != "" || state.Host.HostnameSource != "" {
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
				defer func() { <-semaphore }()
			}

			// Use the new comprehensive hostname resolution
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				result := discovery.ResolveBackground(parsedIP, 1*time.Second)
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
