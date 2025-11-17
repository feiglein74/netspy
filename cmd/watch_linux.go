//go:build linux

package cmd

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
)

// getZebraColor returns the color for zebra striping on Linux
// Most Linux terminals handle FgWhite with Faint well for subtle alternating rows
func getZebraColor() *color.Color {
	return color.New(color.FgWhite, color.Faint)
}

// formatIPWithBoldHost formats an IP address with the host part in bold (Linux)
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
