package output

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// TerminalSize repräsentiert die Größe des Terminals
type TerminalSize struct {
	Width  int
	Height int
}

// GetTerminalSize ermittelt die aktuelle Terminal-Größe
func GetTerminalSize() TerminalSize {
	// Versuche zuerst über golang.org/x/term
	if width, height, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		return TerminalSize{Width: width, Height: height}
	}

	// Fallback: tput verwenden
	if size := getTputSize(); size.Width > 0 {
		return size
	}

	// Standard-Fallback
	return TerminalSize{Width: 120, Height: 30}
}

// getTputSize versucht Terminal-Größe via tput zu ermitteln
func getTputSize() TerminalSize {
	var size TerminalSize

	// Width via tput cols
	if cmd := exec.Command("tput", "cols"); cmd.Err == nil {
		if output, err := cmd.Output(); err == nil {
			if width, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
				size.Width = width
			}
		}
	}

	// Height via tput lines
	if cmd := exec.Command("tput", "lines"); cmd.Err == nil {
		if output, err := cmd.Output(); err == nil {
			if height, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
				size.Height = height
			}
		}
	}

	return size
}

// GetDisplayWidth berechnet verfügbare Breite für Tabelle (mit etwas Puffer)
func (ts TerminalSize) GetDisplayWidth() int {
	// Abzug für Margins und Padding
	return ts.Width - 2
}

// IsNarrow prüft ob Terminal schmal ist (< 100 Spalten)
func (ts TerminalSize) IsNarrow() bool {
	return ts.Width < 100
}

// IsWide prüft ob Terminal breit ist (>= 140 Spalten)
func (ts TerminalSize) IsWide() bool {
	return ts.Width >= 140
}

// IsMedium prüft ob Terminal mittelgroß ist (100-139 Spalten)
func (ts TerminalSize) IsMedium() bool {
	return !ts.IsNarrow() && !ts.IsWide()
}
