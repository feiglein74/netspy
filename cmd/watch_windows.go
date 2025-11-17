//go:build windows

package cmd

import "github.com/fatih/color"

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
