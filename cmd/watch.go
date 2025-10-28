package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/scanner"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	watchInterval time.Duration
	watchMode     string
)

// DeviceState tracks the state of a discovered device over time
type DeviceState struct {
	Host        scanner.Host
	FirstSeen   time.Time
	LastSeen    time.Time
	Status      string // "online" or "offline"
	StatusSince time.Time
	FlapCount   int    // Number of times status has changed (flapping counter)
}

// watchCmd represents the watch command
var watchCmd = &cobra.Command{
	Use:   "watch [network]",
	Short: "Continuously monitor a network for changes",
	Long: `Watch a network subnet for changes in real-time.

Monitors the network at regular intervals and reports when devices appear or disappear.
Tracks timestamps for when each device was first seen, last seen, and status changes.

Examples:
  netspy watch 192.168.1.0/24                      # Monitor with default 60s interval
  netspy watch 192.168.1.0/24 --interval 30s       # Check every 30 seconds
  netspy watch 192.168.1.0/24 --mode hybrid        # Use hybrid scanning mode
  netspy watch 192.168.1.0/24 --mode arp           # Use ARP scanning mode`,
	Args: cobra.ExactArgs(1),
	RunE: runWatch,
}

func init() {
	rootCmd.AddCommand(watchCmd)

	// Add flags for watch command
	watchCmd.Flags().DurationVar(&watchInterval, "interval", 60*time.Second, "Scan interval")
	watchCmd.Flags().StringVar(&watchMode, "mode", "hybrid", "Scan mode (hybrid, arp, fast, thorough, conservative)")
	watchCmd.Flags().IntSliceVarP(&ports, "ports", "p", []int{}, "Specific ports to scan")
}

func runWatch(cmd *cobra.Command, args []string) error {
	network := args[0]

	// Parse network
	_, netCIDR, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}

	// Device state map - key is IP address string
	deviceStates := make(map[string]*DeviceState)

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	// Print header once
	color.Cyan("🔍 NetSpy Watch Mode\n")
	color.White("Network: %s | Interval: %v | Mode: %s\n", network, watchInterval, watchMode)
	color.Yellow("Press Ctrl+C to stop\n\n")

	scanCount := 0
	tableStartLine := 0 // Track where table starts for repainting

	for {
		// Check if context is cancelled before starting new scan
		if ctx.Err() != nil {
			fmt.Println("\n✅ Shutdown complete")
			return nil
		}

		scanCount++
		scanStart := time.Now()

		// Perform scan quietly (no output during scan)
		hosts := performScanQuiet(ctx, network, netCIDR, watchMode)

		// Check if cancelled during scan
		if ctx.Err() != nil {
			fmt.Println("\n✅ Shutdown complete")
			return nil
		}

		// Update device states
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
			now := time.Now()

			if exists {
				// Update existing device
				state.LastSeen = now

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
					// Device came back online
					state.Status = "online"
					state.StatusSince = now
					state.FlapCount++ // Increment flap counter
				}
			} else {
				// New device
				deviceStates[ipStr] = &DeviceState{
					Host:        host,
					FirstSeen:   now,
					LastSeen:    now,
					Status:      "online",
					StatusSince: now,
				}
			}
		}

		// Check for devices that went offline
		for ipStr, state := range deviceStates {
			if !currentIPs[ipStr] && state.Status == "online" {
				// Device went offline
				state.Status = "offline"
				state.StatusSince = time.Now()
				state.FlapCount++ // Increment flap counter
			}
		}

		// If first scan, just print table
		// Otherwise, move cursor up and redraw
		if scanCount > 1 {
			// Move cursor up from status line to table header
			linesToClear := len(deviceStates) + 2 // separator + devices (we're ON status line)
			moveCursorUp(linesToClear)
		}

		// Redraw entire table
		redrawTable(deviceStates, scanCount, time.Since(scanStart))
		// Lines to move UP from status line to header: separator + devices + status line
		// (We're ON the status line, need to go up to reach header)
		tableStartLine = len(deviceStates) + 2

		// Calculate next scan time
		scanDuration := time.Since(scanStart)
		nextScan := watchInterval - scanDuration
		if nextScan < 0 {
			nextScan = 0
		}

		// Start background DNS lookups while countdown is running
		if nextScan > 0 {
			go performBackgroundDNSLookups(ctx, deviceStates)

			// Show countdown with periodic table updates
			showCountdownWithTableUpdates(ctx, nextScan, deviceStates, scanCount, scanDuration, tableStartLine)
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
	case "fast":
		fast = true
		thorough = false
		hosts, err = performNormalScan(network)
	case "thorough":
		fast = false
		thorough = true
		hosts, err = performNormalScan(network)
	case "conservative":
		fast = false
		thorough = false
		hosts, err = performNormalScan(network)
	default:
		return nil
	}

	if err != nil {
		return hosts
	}

	return hosts
}

func performHybridScanQuiet(ctx context.Context, netCIDR *net.IPNet) ([]scanner.Host, error) {
	allHosts := []scanner.Host{}

	// Read existing ARP table first
	existingHosts := readCurrentARPTable(netCIDR)
	allHosts = append(allHosts, existingHosts...)

	// Populate ARP table
	if err := populateARPTableQuiet(ctx, netCIDR); err != nil {
		return allHosts, err
	}

	// Read refreshed ARP table
	finalHosts := readCurrentARPTable(netCIDR)

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

	// Measure RTT for all discovered hosts
	finalHosts = measureRTTForHosts(finalHosts)

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
	// Populate ARP table
	if err := populateARPTableQuiet(ctx, netCIDR); err != nil {
		return nil, err
	}

	// Read ARP table
	hosts := readCurrentARPTable(netCIDR)
	return hosts, nil
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
				conn.Close()
			}
		}(ip)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond) // Wait for ARP table to update
	return nil
}

// Old streaming functions removed - now using static table with redrawTable()

func performNormalScan(network string) ([]scanner.Host, error) {
	hosts, err := parseNetworkInput(network)
	if err != nil {
		return nil, fmt.Errorf("invalid network specification: %v", err)
	}

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

func redrawTable(states map[string]*DeviceState, scanCount int, scanDuration time.Duration) {
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

	// Print header (no clear needed - fixed width columns will overwrite)
	fmt.Print("\r")  // Go to start of line
	color.Cyan("IP Address      Status    Hostname                  MAC Address        Device Type       RTT      First Seen    Uptime/Downtime  Flaps\n")
	fmt.Print("\r")  // Go to start of line
	color.White("%s\n", strings.Repeat("─", 136))

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

		// Prepare ALL data BEFORE clearing the line (to minimize flicker)
		statusIcon := "🟢"
		statusColor := color.GreenString
		statusText := "online "  // Extra space to match "offline" length
		if state.Status == "offline" {
			statusIcon = "🔴"
			statusColor = color.RedString
			statusText = "offline"
		}

		hostname := getHostname(state.Host)
		if len(hostname) > 23 {
			hostname = hostname[:20] + "..."
		}

		// Format MAC address with color coding for local MACs
		mac := formatMAC(state.Host.MAC)

		// Show device type if available, otherwise show vendor
		deviceInfo := state.Host.DeviceType
		if deviceInfo == "" || deviceInfo == "Unknown" {
			deviceInfo = getVendor(state.Host)
		}
		if len(deviceInfo) > 16 {
			deviceInfo = deviceInfo[:13] + "..."
		}

		firstSeen := state.FirstSeen.Format("15:04:05")
		statusDuration := formatDuration(time.Since(state.StatusSince))

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

		// Format flap count with warning color if > 0
		flapText := fmt.Sprintf("%d", state.FlapCount)
		if state.FlapCount > 0 {
			flapText = color.YellowString(flapText)
		}

		// Check if this is the gateway
		gatewayMarker := " "
		parsedIP := net.ParseIP(ipStr)
		if parsedIP != nil && discovery.IsGateway(parsedIP) {
			gatewayMarker = "G"
		}

		// Print device line (no clear needed - fixed width will overwrite)
		fmt.Print("\r")  // Go to start of line
		fmt.Printf("%-15s %s%s %-7s %-25s %s %-17s %-8s %-13s %-16s %s\n",
			ipStr,
			gatewayMarker,
			statusIcon,
			statusColor(statusText),
			hostname,
			mac, // Already padded by formatMAC
			deviceInfo,
			rttText,
			firstSeen,
			statusDuration,
			flapText,
		)
	}

	// Don't print status line here - showCountdownWithTableUpdates handles it
	// This prevents "calculating..." from appearing during table redraws
}

func showCountdownWithTableUpdates(ctx context.Context, duration time.Duration, states map[string]*DeviceState, scanCount int, scanDuration time.Duration, tableLines int) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastRedraw := -1 // Track last redraw second to avoid double-redraw

	// Initial countdown display
	fmt.Print("\r")
	clearLine()
	onlineCount := 0
	offlineCount := 0
	for _, state := range states {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
	}
	fmt.Printf("📊 Scan #%d | %d devices (%d online, %d offline) | Scan: %s | ⏳ Next: %s",
		scanCount, len(states), onlineCount, offlineCount, formatDuration(scanDuration), formatDuration(duration))

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			elapsed := time.Since(startTime)
			currentSecond := int(elapsed.Seconds())

			// Check if we're done BEFORE any processing
			if elapsed >= duration {
				return
			}

			// Every 5 seconds, do something useful: alternate between DNS updates and reachability checks
			// But only once per 5-second mark (avoid double-processing if slow)
			if currentSecond%5 == 0 && currentSecond != lastRedraw {
				lastRedraw = currentSecond

				// Alternate: DNS update on odd multiples (5, 15, 25...), reachability on even (10, 20, 30...)
				if (currentSecond/5)%2 == 1 {
					// DNS update: just redraw table
					moveCursorUp(tableLines)
					redrawTable(states, scanCount, scanDuration)
					fmt.Print("\033[2K")
				} else {
					// Reachability check: quickly check if devices are still online
					performQuickReachabilityCheck(states)
					moveCursorUp(tableLines)
					redrawTable(states, scanCount, scanDuration)
					fmt.Print("\033[2K")
				}
			} else {
				// Not doing anything special, just update status line in place
				fmt.Print("\r")
				clearLine()
			}

			// ALWAYS calculate remaining time fresh (accounts for any processing delays)
			remaining := duration - time.Since(startTime)
			if remaining < 0 {
				remaining = 0
			}

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

			fmt.Printf("📊 Scan #%d | %d devices (%d online, %d offline) | Scan: %s | ⏳ Next: %s",
				scanCount, len(states), onlineCount, offlineCount, formatDuration(scanDuration), formatDuration(remaining))
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
					conn.Close()
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

// measureRTTForHosts measures response time for each host
func measureRTTForHosts(hosts []scanner.Host) []scanner.Host {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	semaphore := make(chan struct{}, 30) // Limit concurrent RTT measurements

	for i := range hosts {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Measure RTT by trying common ports
			start := time.Now()
			measured := false

			// Try port 80 (HTTP)
			if conn, err := net.DialTimeout("tcp", net.JoinHostPort(hosts[index].IP.String(), "80"), 300*time.Millisecond); err == nil {
				conn.Close()
				mutex.Lock()
				hosts[index].RTT = time.Since(start)
				mutex.Unlock()
				measured = true
			}

			// Try port 443 (HTTPS) if 80 failed
			if !measured {
				start = time.Now()
				if conn, err := net.DialTimeout("tcp", net.JoinHostPort(hosts[index].IP.String(), "443"), 300*time.Millisecond); err == nil {
					conn.Close()
					mutex.Lock()
					hosts[index].RTT = time.Since(start)
					mutex.Unlock()
					measured = true
				}
			}

			// Try port 22 (SSH) if both failed
			if !measured {
				start = time.Now()
				if conn, err := net.DialTimeout("tcp", net.JoinHostPort(hosts[index].IP.String(), "22"), 300*time.Millisecond); err == nil {
					conn.Close()
					mutex.Lock()
					hosts[index].RTT = time.Since(start)
					mutex.Unlock()
					measured = true
				}
			}

			// Try port 445 (SMB - Windows) if previous failed
			if !measured {
				start = time.Now()
				if conn, err := net.DialTimeout("tcp", net.JoinHostPort(hosts[index].IP.String(), "445"), 300*time.Millisecond); err == nil {
					conn.Close()
					mutex.Lock()
					hosts[index].RTT = time.Since(start)
					mutex.Unlock()
					measured = true
				}
			}

			// Try port 135 (RPC - Windows) if previous failed
			if !measured {
				start = time.Now()
				if conn, err := net.DialTimeout("tcp", net.JoinHostPort(hosts[index].IP.String(), "135"), 300*time.Millisecond); err == nil {
					conn.Close()
					mutex.Lock()
					hosts[index].RTT = time.Since(start)
					mutex.Unlock()
					measured = true
				}
			}

			// Fallback: If no port is open, try common closed ports to measure network RTT
			// Even connection refused/filtered gives us RTT (time to get RST or timeout)
			if !measured {
				// Try several ports to maximize chance of getting a response
				// (445 and 135 already tried above, so use RDP and NetBIOS here)
				testPorts := []string{"3389", "139", "8080", "5900"}
				var bestRTT time.Duration

				for _, port := range testPorts {
					start = time.Now()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(hosts[index].IP.String(), port), 300*time.Millisecond)
					if err == nil {
						conn.Close()
					}
					rtt := time.Since(start)
					// Record RTT if we got any response (success or fast failure)
					if rtt < 280*time.Millisecond && (bestRTT == 0 || rtt < bestRTT) {
						bestRTT = rtt
					}
				}

				if bestRTT > 0 {
					mutex.Lock()
					hosts[index].RTT = bestRTT
					mutex.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()
	return hosts
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
	ip := network.IP.Mask(network.Mask)
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	numHosts := 1 << hostBits
	maxHosts := numHosts - 2

	ips := make([]net.IP, 0, maxHosts)

	for i := 1; i < numHosts-1; i++ {
		currentIP := make(net.IP, len(ip))
		copy(currentIP, ip)

		for j := len(currentIP) - 1; j >= 0; j-- {
			currentIP[j] += byte(i >> (8 * (len(currentIP) - 1 - j)))
			if currentIP[j] != 0 {
				break
			}
		}

		if network.Contains(currentIP) {
			ips = append(ips, currentIP)
		}
	}

	return ips
}
