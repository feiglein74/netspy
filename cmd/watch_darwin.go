//go:build darwin

package cmd

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
)

// getZebraColor returns the color for zebra striping on macOS
// Uses FgHiYellow which adapts well to most terminal themes
func getZebraColor() *color.Color {
	return color.New(color.FgHiYellow)
}

// formatIPWithBoldHost formats an IP address with the host part in bold (macOS)
// Uses lipgloss Bold() which adapts to terminal themes properly
func formatIPWithBoldHost(ip string) string {
	networkPart, hostPart, ok := splitIPNetworkHost(ip)
	if !ok {
		return ip // Fallback: return original IP
	}

	// Use lipgloss for theme-aware bold formatting
	boldStyle := lipgloss.NewStyle().Bold(true)
	return networkPart + boldStyle.Render(hostPart)
}
