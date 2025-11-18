package watch

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"netspy/pkg/discovery"
	"netspy/pkg/output"

	"github.com/fatih/color"
)

// WatchCallbacks contains platform-specific callback functions for watch mode
type WatchCallbacks struct {
	// DrawBtopLayout renders the btop-inspired layout
	DrawBtopLayout func(
		states map[string]*DeviceState,
		referenceTime time.Time,
		network string,
		interval time.Duration,
		mode string,
		scanCount int,
		scanDuration time.Duration,
		nextScanIn time.Duration,
		activeThreads *int32,
		currentPage *int32,
		sortState *SortState,
		isLocal bool,
		getGitVersionFunc func() string,
		captureScreenFunc func(),
		formatIPWithBoldHostFunc func(string) string,
		isLocallyAdministeredFunc func(string) bool,
		getZebraColorFunc func() *color.Color,
	)

	// UpdateHeaderLineOnly updates only the header line with thread count
	UpdateHeaderLineOnly func(scanCount int, activeThreads *int32, getGitVersionFunc func() string)

	// ShowHelpOverlay displays the help overlay
	ShowHelpOverlay func(termWidth int, keyChan <-chan rune)

	// CopyScreenToClipboard copies screen to clipboard
	CopyScreenToClipboard func() error

	// GetGitVersion returns git version string
	GetGitVersion func() string

	// CaptureScreen captures screen for clipboard
	CaptureScreen func()

	// FormatIPWithBoldHost formats IP with bold host part
	FormatIPWithBoldHost func(string) string

	// IsLocallyAdministered checks if MAC is locally administered
	IsLocallyAdministered func(string) bool

	// GetZebraColor returns zebra stripe color
	GetZebraColor func() *color.Color
}

// RunWatchLegacy is the main watch loop using ANSI-based display
// This function orchestrates the continuous network monitoring with live updates
func RunWatchLegacy(
	network string,
	netCIDR *net.IPNet,
	watchInterval time.Duration,
	watchMode string,
	maxThreads int,
	sigChan <-chan os.Signal,
	setupTerminalFunc func() error,
	resetTerminalFunc func() error,
	getResizeChannelFunc func() <-chan os.Signal,
	callbacks WatchCallbacks,
) error {
	// Terminal in raw mode versetzen für ANSI/VT-Codes und direkte Tasteneingaben (platform-specific)
	// WICHTIG: Muss VOR allen ANSI-Ausgaben erfolgen!
	_ = setupTerminalFunc()

	// Calculate optimal thread counts based on network size
	threadConfig := CalculateThreads(netCIDR, maxThreads)
	ones, bits := netCIDR.Mask.Size()
	hostCount := 1 << uint(bits - ones)
	fmt.Printf("🔧 Thread Config: Scan=%d, Reachability=%d, DNS=%d (Network: %s, %d potential hosts)\n",
		threadConfig.Scan, threadConfig.Reachability, threadConfig.DNS,
		netCIDR.String(), hostCount)

	// Check if target subnet is local or remote (for UI indicators)
	isLocal, _ := discovery.IsLocalSubnet(netCIDR)

	// Clear screen and move cursor to home for clean UI start
	fmt.Print("\033[2J\033[H")

	// Geräte-Status-Map - Schlüssel ist IP-Adresse als String
	deviceStates := make(map[string]*DeviceState)

	// Signal-Handling für graceful Shutdown und Window-Resize einrichten
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Window size change signal (platform-specific)
	winchChan := getResizeChannelFunc()

	// Keyboard input channel für 'c' zum Kopieren
	keyChan := make(chan rune, 10)

	// Stelle sicher, dass wir beim Exit das Terminal wieder zurücksetzen
	defer func() {
		_ = resetTerminalFunc()
	}()

	go func() {
		sig := <-sigChan
		fmt.Printf("\n\n[!] Received signal %v, shutting down...\n", sig)
		// Terminal-State wiederherstellen (platform-specific)
		_ = resetTerminalFunc()
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
	sortState := &SortState{Column: SortByIP, Ascending: true} // Default sort by IP ascending

	for {
		// Check if context is cancelled before starting new scan
		if ctx.Err() != nil {
			fmt.Println("\n[OK] Shutdown complete")
			return nil
		}

		scanCount++
		scanStart := time.Now()

		// Perform scan quietly (no output during scan)
		hosts := PerformScanQuiet(ctx, network, netCIDR, watchMode, &activeThreads, threadConfig)

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
		PopulateFromDNSCache(deviceStates)

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
		callbacks.DrawBtopLayout(deviceStates, scanStart, network, watchInterval, watchMode, scanCount, scanDuration, nextScan, &activeThreads, &currentPage, sortState, isLocal, callbacks.GetGitVersion, callbacks.CaptureScreen, callbacks.FormatIPWithBoldHost, callbacks.IsLocallyAdministered, callbacks.GetZebraColor)

		// Clear any remaining lines from previous draw (if screen shrunk)
		fmt.Print("\033[J") // Clear from cursor to end of screen

		redrawMutex.Unlock()

		// Phase 1: Quick DNS lookups immediately after scan (blocks briefly for fast results)
		PerformInitialDNSLookups(ctx, deviceStates)

		// Phase 2: Start slow background lookups (mDNS/NetBIOS/LLMNR/HTTP) while countdown is running
		if nextScan > 0 {
			go PerformBackgroundDNSLookups(ctx, deviceStates, &activeThreads, threadConfig)

			// Show countdown with periodic table updates (pass scanStart for consistent uptime)
			ShowCountdownWithTableUpdates(ctx, cancel, nextScan, deviceStates, scanCount, scanDuration, scanStart, winchChan, keyChan, &redrawMutex, network, watchInterval, watchMode, &activeThreads, &currentPage, sortState, threadConfig, isLocal, callbacks)
		}
	}
}

// ShowCountdownWithTableUpdates shows countdown timer with periodic table updates
// Handles keyboard input, window resize, and periodic refreshes
func ShowCountdownWithTableUpdates(
	ctx context.Context,
	cancel context.CancelFunc,
	duration time.Duration,
	states map[string]*DeviceState,
	scanCount int,
	scanDuration time.Duration,
	scanStart time.Time,
	winchChan <-chan os.Signal,
	keyChan <-chan rune,
	redrawMutex *sync.Mutex,
	network string,
	watchInterval time.Duration,
	watchMode string,
	activeThreads *int32,
	currentPage *int32,
	sortState *SortState,
	threadConfig ThreadConfig,
	isLocal bool,
	callbacks WatchCallbacks,
) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	lastRedraw := -1 // Track last redraw second to avoid double-redraw

	// Helper function to redraw entire screen with btop layout
	redrawFullScreen := func(refTime time.Time, currentScanDuration time.Duration, remaining time.Duration) {
		// Move to home and redraw (no clear = less flicker)
		fmt.Print("\033[H")
		// Draw btop-inspired layout (includes status line inside box)
		callbacks.DrawBtopLayout(states, refTime, network, watchInterval, watchMode, scanCount, currentScanDuration, remaining, activeThreads, currentPage, sortState, isLocal, callbacks.GetGitVersion, callbacks.CaptureScreen, callbacks.FormatIPWithBoldHost, callbacks.IsLocallyAdministered, callbacks.GetZebraColor)
		// Clear any leftover content
		fmt.Print("\033[J")
	}

	for {
		select {
		case <-ctx.Done():
			return
		case key := <-keyChan:
			// Handle keyboard input
			// ESC key - exit program
			if key == 27 {
				cancel()
				return
			}
			if key == 'c' || key == 'C' {
				// Benutzer hat 'c' gedrückt - Kopiere Screen in Zwischenablage
				if err := callbacks.CopyScreenToClipboard(); err != nil {
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
			} else if key == 'i' || key == 'I' {
				// Sort by IP
				sortState.Toggle(SortByIP)
				atomic.StoreInt32(currentPage, 1) // Reset to page 1
			} else if key == 'h' || key == 'H' {
				// Sort by Hostname
				sortState.Toggle(SortByHostname)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 'm' || key == 'M' {
				// Sort by MAC
				sortState.Toggle(SortByMAC)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 'v' || key == 'V' {
				// Sort by Vendor
				sortState.Toggle(SortByVendor)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 'd' || key == 'D' {
				// Sort by Device Type
				sortState.Toggle(SortByDeviceType)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 'r' || key == 'R' {
				// Sort by RTT
				sortState.Toggle(SortByRTT)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 't' || key == 'T' {
				// Sort by First Seen Time
				sortState.Toggle(SortByFirstSeen)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 'u' || key == 'U' {
				// Sort by Uptime
				sortState.Toggle(SortByUptime)
				atomic.StoreInt32(currentPage, 1)
			} else if key == 'f' || key == 'F' {
				// Sort by Flaps
				sortState.Toggle(SortByFlaps)
				atomic.StoreInt32(currentPage, 1)
			} else if key == '?' {
				// ? - Show help overlay
				termSize := output.GetTerminalSize()
				callbacks.ShowHelpOverlay(termSize.GetDisplayWidth(), keyChan)
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
					PerformQuickReachabilityCheck(ctx, states, activeThreads, threadConfig)
					redrawMutex.Lock()
					currentRefTime := scanStart.Add(elapsed)
					redrawFullScreen(currentRefTime, scanDuration, remaining)
					redrawMutex.Unlock()
				}
			} else {
				// NOT a 5-second mark: Update only the header line with thread count (fast!)
				// This gives live thread count updates every second without full redraw flicker
				redrawMutex.Lock()
				callbacks.UpdateHeaderLineOnly(scanCount, activeThreads, callbacks.GetGitVersion)
				redrawMutex.Unlock()
			}
		}
	}
}
