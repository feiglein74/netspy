package cmd

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"netspy/pkg/watch"

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
		detectedNetwork, err := watch.DetectAndSelectNetwork()
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

	// Setup signal handling BEFORE calling RunWatchLegacy
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create callbacks structure with platform-specific functions
	callbacks := watch.WatchCallbacks{
		DrawBtopLayout:        watch.DrawBtopLayout,
		UpdateHeaderLineOnly:  watch.UpdateHeaderLineOnly,
		ShowHelpOverlay:       watch.ShowHelpOverlay,
		CopyScreenToClipboard: copyScreenToClipboard,
		GetGitVersion:         getGitVersion,
		CaptureScreen:         captureScreen,
		FormatIPWithBoldHost:  formatIPWithBoldHost,
		IsLocallyAdministered: watch.IsLocallyAdministered,
		GetZebraColor:         getZebraColor,
	}

	// Call the extracted watch loop function
	return watch.RunWatchLegacy(
		network,
		netCIDR,
		watchInterval,
		watchMode,
		maxThreads,
		sigChan,
		setupTerminal,
		resetTerminal,
		getResizeChannel,
		callbacks,
	)
}

// Removed: All scan-related functions have been moved to pkg/watch/scanner.go
// The functions are now exported and called directly from pkg/watch package

// Old print functions removed - now using redrawTable() for static table updates

// splitIPNetworkHost wrapper for watch.SplitIPNetworkHost
func splitIPNetworkHost(ip string) (string, string, bool) {
	return watch.SplitIPNetworkHost(ip, currentCIDR)
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

// copyScreenToClipboard wrapper for watch.CopyScreenToClipboard
func copyScreenToClipboard() error {
	return watch.CopyScreenToClipboard(&screenBuffer, &screenBufferMux)
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
