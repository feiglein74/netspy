//go:build windows

package cmd

import (
	"os"
)

// setupTerminal is a no-op on Windows (raw mode not supported)
func setupTerminal() error {
	// Windows terminal doesn't support stty-like raw mode
	// Keyboard input will still work, just not in raw mode
	return nil
}

// resetTerminal is a no-op on Windows
func resetTerminal() error {
	// Nothing to reset
	return nil
}

// getResizeChannel returns a dummy channel on Windows (SIGWINCH not available)
// Terminal resize detection is not supported on Windows
func getResizeChannel() chan os.Signal {
	// Return a channel that will never receive signals
	// This prevents the resize handler from ever triggering
	return make(chan os.Signal, 1)
}
