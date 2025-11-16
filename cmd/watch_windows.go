//go:build windows

package cmd

import (
	"os"
	"syscall"
	"time"
	"unsafe"

	"netspy/pkg/output"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetStdHandle               = kernel32.NewProc("GetStdHandle")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	stdOutputHandle        uintptr = 0xFFFFFFF5 // STD_OUTPUT_HANDLE
	enableVirtualTerminal  uint32  = 0x0004     // ENABLE_VIRTUAL_TERMINAL_PROCESSING
)

// setupTerminal enables ANSI/VT100 escape code support on Windows
func setupTerminal() error {
	// Try to enable VT processing for native Windows terminals (cmd.exe, PowerShell, Windows Terminal)
	// This will silently fail in Git Bash/MSYS2 (which is fine - they have native ANSI support)

	handle, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if handle == 0 || handle == uintptr(syscall.InvalidHandle) {
		// Not a Windows console (e.g., Git Bash, MSYS2, pipe, file)
		// These environments typically support ANSI natively, so just return
		return nil
	}

	// Get current console mode
	var mode uint32
	ret, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if ret == 0 {
		// GetConsoleMode failed - probably not a console (Git Bash, redirected output)
		// Return success - ANSI might work anyway
		return nil
	}

	// Enable Virtual Terminal Processing
	mode |= enableVirtualTerminal
	procSetConsoleMode.Call(handle, uintptr(mode))
	// Don't check return value - even if it fails, we tried our best

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
