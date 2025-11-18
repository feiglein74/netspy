//go:build windows

package cmd

import (
	"os"

	"github.com/fatih/color"
)

// setupTerminal sets up the terminal for raw mode (Windows no-op)
// Windows Terminal handles ANSI codes by default, no special setup needed
func setupTerminal() error {
	return nil
}

// resetTerminal resets the terminal to normal mode (Windows no-op)
func resetTerminal() error {
	return nil
}

// getResizeChannel returns a channel for terminal resize signals (Windows stub)
// Windows doesn't have SIGWINCH, return a dummy channel
func getResizeChannel() <-chan os.Signal {
	// Return a channel that never receives signals
	// This prevents crashes but means no auto-resize on Windows
	ch := make(chan os.Signal, 1)
	return ch
}

// getZebraColor returns the color for zebra striping on Windows
// Windows Terminal handles FgHiBlack well for alternating row colors
func getZebraColor() *color.Color {
	return color.New(color.FgHiBlack)
}

// formatIPWithBoldHost formats an IP address with the host part in bold (Windows)
// Uses ANSI escape codes which work well on Windows Terminal
func formatIPWithBoldHost(ip string) string {
	networkPart, hostPart, ok := splitIPNetworkHost(ip)
	if !ok {
		return ip // Fallback: return original IP
	}

	// Return with ANSI bold escape codes
	return networkPart + "\033[1m" + hostPart + "\033[22m"
}
