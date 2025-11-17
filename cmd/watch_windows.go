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
	stdOutputHandle        uintptr = 0xFFFFFFF5 // STD_OUTPUT_HANDLE (-11)
	stdInputHandle         uintptr = 0xFFFFFFF6 // STD_INPUT_HANDLE (-10)
	enableVirtualTerminal  uint32  = 0x0004     // ENABLE_VIRTUAL_TERMINAL_PROCESSING (stdout)
	enableEchoInput        uint32  = 0x0004     // ENABLE_ECHO_INPUT (stdin)
	enableLineInput        uint32  = 0x0002     // ENABLE_LINE_INPUT (stdin)
	enableProcessedInput   uint32  = 0x0001     // ENABLE_PROCESSED_INPUT (stdin)

	// Store original modes for restoration
	originalStdinMode  uint32
	originalStdoutMode uint32
)

// setupTerminal enables ANSI/VT100 escape code support and disables echo on Windows
func setupTerminal() error {
	// 1. Setup stdout: Enable VT processing for ANSI escape codes
	handleOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if handleOut != 0 && handleOut != uintptr(syscall.InvalidHandle) {
		ret, _, _ := procGetConsoleMode.Call(handleOut, uintptr(unsafe.Pointer(&originalStdoutMode)))
		if ret != 0 {
			// Enable Virtual Terminal Processing
			newMode := originalStdoutMode | enableVirtualTerminal
			procSetConsoleMode.Call(handleOut, uintptr(newMode))
		}
	}

	// 2. Setup stdin: Disable echo and line buffering for raw keyboard input
	handleIn, _, _ := procGetStdHandle.Call(stdInputHandle)
	if handleIn != 0 && handleIn != uintptr(syscall.InvalidHandle) {
		ret, _, _ := procGetConsoleMode.Call(handleIn, uintptr(unsafe.Pointer(&originalStdinMode)))
		if ret != 0 {
			// Disable echo and line input for raw character-by-character input
			newMode := originalStdinMode
			newMode &^= enableEchoInput    // Disable echo (don't print typed characters)
			newMode &^= enableLineInput    // Disable line buffering (read char-by-char)
			procSetConsoleMode.Call(handleIn, uintptr(newMode))
		}
	}

	return nil
}

// resetTerminal restores original terminal modes on Windows
func resetTerminal() error {
	// Restore stdout mode
	handleOut, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if handleOut != 0 && handleOut != uintptr(syscall.InvalidHandle) {
		procSetConsoleMode.Call(handleOut, uintptr(originalStdoutMode))
	}

	// Restore stdin mode
	handleIn, _, _ := procGetStdHandle.Call(stdInputHandle)
	if handleIn != 0 && handleIn != uintptr(syscall.InvalidHandle) {
		procSetConsoleMode.Call(handleIn, uintptr(originalStdinMode))
	}

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
