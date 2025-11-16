//go:build unix

package cmd

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// setupTerminal sets up the terminal in raw mode for direct keyboard input (Unix only)
func setupTerminal() error {
	rawModeCmd := exec.Command("stty", "-icanon", "min", "1", "-echo")
	rawModeCmd.Stdin = os.Stdin
	return rawModeCmd.Run()
}

// resetTerminal resets the terminal to normal mode (Unix only)
func resetTerminal() error {
	resetCmd := exec.Command("stty", "icanon", "echo")
	resetCmd.Stdin = os.Stdin
	return resetCmd.Run()
}

// getResizeChannel returns a channel that receives signals when terminal is resized (Unix only)
func getResizeChannel() chan os.Signal {
	winchChan := make(chan os.Signal, 1)
	signal.Notify(winchChan, syscall.SIGWINCH)
	return winchChan
}
