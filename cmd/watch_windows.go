//go:build windows

package cmd

import (
	"os"
	"syscall"
	"time"

	"netspy/pkg/output"
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

// getResizeChannel returns a channel that detects terminal resize via polling
// Windows doesn't have SIGWINCH, so we poll terminal size every 500ms
func getResizeChannel() chan os.Signal {
	resizeChan := make(chan os.Signal, 1)

	// Start polling goroutine
	go func() {
		lastSize := output.GetTerminalSize()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for range ticker.C {
			currentSize := output.GetTerminalSize()

			// Check if size changed
			if currentSize.Width != lastSize.Width || currentSize.Height != lastSize.Height {
				// Send a dummy signal to trigger redraw
				// We use SIGTERM as a dummy value (compatible with chan os.Signal)
				resizeChan <- syscall.SIGTERM
				lastSize = currentSize
			}
		}
	}()

	return resizeChan
}
