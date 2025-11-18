package watch

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netspy/pkg/output"

	"github.com/fatih/color"
	"github.com/mattn/go-runewidth"
)

// ============================================================================
// ANSI/Cursor Control Functions
// ============================================================================

// MoveCursorUp moves the cursor up by the specified number of lines
func MoveCursorUp(lines int) {
	for i := 0; i < lines; i++ {
		fmt.Print("\033[A") // Move up one line
	}
	fmt.Print("\r") // Move to start of line
}

// ClearLine clears the entire line and moves cursor to start
func ClearLine() {
	fmt.Print("\033[2K\r") // Clear entire line and move to start
}

// ============================================================================
// String Formatting Functions
// ============================================================================

// StripANSI removes ANSI escape codes to get actual visible length
// UTF-8-safe: works with runes instead of bytes
func StripANSI(s string) string {
	result := ""
	inEscape := false
	runes := []rune(s)

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\033' { // ESC character
			inEscape = true
			continue
		}
		if inEscape {
			// ANSI Escape-Sequenzen enden mit einem Buchstaben
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEscape = false
			}
			continue
		}
		result += string(r)
	}
	return result
}

// RuneLen returns the display width of a string (accounts for wide characters)
func RuneLen(s string) int {
	return runewidth.StringWidth(s)
}

// PadRight pads a string on the right with spaces to the desired rune length
func PadRight(s string, length int) string {
	currentLen := RuneLen(s)
	if currentLen >= length {
		return s
	}
	return s + strings.Repeat(" ", length-currentLen)
}

// PadRightANSI pads a string to a certain length, accounting for invisible ANSI color codes
func PadRightANSI(s string, length int) string {
	// Calculate visible length (without ANSI codes)
	visibleLen := RuneLen(StripANSI(s))
	if visibleLen >= length {
		return s
	}
	// Add spaces based on visual length
	return s + strings.Repeat(" ", length-visibleLen)
}

// PadLeft pads a string on the left (right-aligns) to specified width
// Used for numeric/duration alignment (like decimal tabs in DTP)
func PadLeft(s string, width int) string {
	currentLen := RuneLen(s)
	if currentLen >= width {
		return s
	}
	return strings.Repeat(" ", width-currentLen) + s
}

// SafeRepeat prevents negative repeat counts that lead to panics
func SafeRepeat(str string, count int) string {
	if count < 0 {
		return ""
	}
	return strings.Repeat(str, count)
}

// PrintBoxLine prints a line within the box with proper padding
func PrintBoxLine(content string, width int) {
	// Calculate visible length (without ANSI codes, UTF-8 aware)
	visibleContent := StripANSI(content)
	visibleLen := RuneLen(visibleContent)

	// -4 for: "║" (1) + " " (1) + " " (1) + "║" (1)
	padding := width - visibleLen - 4
	if padding < 0 {
		padding = 0
	}
	fmt.Print(color.CyanString("║"))
	fmt.Print(" " + content)
	fmt.Print(strings.Repeat(" ", padding))
	fmt.Print(color.CyanString(" ║\n"))
}

// PrintTableRow prints a table row with correct padding (UTF-8 + ANSI aware)
func PrintTableRow(content string, width int) {
	// Calculate visible length (without ANSI codes)
	visibleContent := StripANSI(content)
	visibleLen := RuneLen(visibleContent)
	// -4 for: "║" (1) + " " (1) + " " (1) + "║" (1)
	padding := width - visibleLen - 4

	// Safety: If content is too long (e.g., narrow terminal), truncate instead of negative padding
	if padding < 0 {
		// Content is too long - truncate to available width
		maxContentLen := width - 4 // -4 for "║ " and " ║"
		if maxContentLen < 3 {
			maxContentLen = 3 // Minimum 3 characters
		}
		// Truncate content (UTF-8-aware)
		contentRunes := []rune(StripANSI(content))
		if len(contentRunes) > maxContentLen {
			content = string(contentRunes[:maxContentLen-1]) + "…"
		}
		// Recalculate
		visibleContent = StripANSI(content)
		visibleLen = RuneLen(visibleContent)
		padding = width - visibleLen - 4
		if padding < 0 {
			padding = 0
		}
	}

	fmt.Print(color.CyanString("║"))
	fmt.Print(" " + content)
	fmt.Print(strings.Repeat(" ", padding))
	fmt.Print(color.CyanString(" ║\n"))
}

// ============================================================================
// Help Overlay
// ============================================================================

// ShowHelpOverlay displays a help screen overlay with colored symbols
// Returns when any key is pressed
func ShowHelpOverlay(termWidth int, keyChan <-chan rune) {
	// Save current screen state
	fmt.Print("\033[?25l") // Hide cursor

	// Modal box dimensions (narrower than screen)
	boxWidth := 64
	if boxWidth > termWidth-4 {
		boxWidth = termWidth - 4
	}

	// Calculate centering offset
	leftMargin := (termWidth - boxWidth) / 2
	if leftMargin < 0 {
		leftMargin = 0
	}

	// Start at row 3 (leave room at top)
	startRow := 3

	// Build help content with colors and proper spacing
	title := color.HiWhiteString("NetSpy Hilfe")

	sortHeader := color.CyanString("SORTIERUNG:")
	sortLine1 := "  Drücke Buchstaben im Header:"
	sortLine2 := "  " + color.HiWhiteString("i") + "=IP  " + color.HiWhiteString("h") + "=Host  " + color.HiWhiteString("m") + "=MAC  " + color.HiWhiteString("v") + "=Vendor  " + color.HiWhiteString("d") + "=Device"
	sortLine3 := "  " + color.HiWhiteString("r") + "=RTT  " + color.HiWhiteString("f") + "=Flaps  " + color.HiWhiteString("u") + "=Up"
	sortLine4 := "  Nochmals drücken = Reihenfolge umkehren"

	navHeader := color.CyanString("NAVIGATION:")
	navLine := "  " + color.HiWhiteString("n") + "=Nächste  " + color.HiWhiteString("p") + "=Zurück  " + color.HiWhiteString("c") + "=Kopieren  " + color.HiWhiteString("q") + "=Beenden"

	symbolHeader := color.CyanString("SYMBOLE:")
	symbolLine := "  [G]=Gateway  " + color.RedString("[!]") + "=Offline  " + color.GreenString("[+]") + "=Neu"

	colorHeader := color.CyanString("FARBEN:")
	colorLine := "  " + color.RedString("Rot") + "=Offline  " + color.GreenString("Grün") + "=Neu  " + color.YellowString("Gelb") + "=Lokal-MAC"

	closeText := color.HiBlackString("Beliebige Taste zum Schließen...")

	// Helper function to print a centered box line with shadow
	currentRow := startRow
	printCenteredLine := func(content string) {
		// Move to position
		fmt.Printf("\033[%d;%dH", currentRow, leftMargin+1)

		// Print the line
		if content == "TOP" {
			fmt.Print(color.CyanString("╔"))
			fmt.Print(color.CyanString(SafeRepeat("═", boxWidth-2)))
			fmt.Print(color.CyanString("╗"))
		} else if content == "SEP" {
			fmt.Print(color.CyanString("╠"))
			fmt.Print(color.CyanString(SafeRepeat("═", boxWidth-2)))
			fmt.Print(color.CyanString("╣"))
		} else if content == "BOTTOM" {
			fmt.Print(color.CyanString("╚"))
			fmt.Print(color.CyanString(SafeRepeat("═", boxWidth-2)))
			fmt.Print(color.CyanString("╝"))
		} else {
			// Regular content line
			visibleContent := StripANSI(content)
			visibleLen := RuneLen(visibleContent)
			padding := boxWidth - visibleLen - 4
			if padding < 0 {
				padding = 0
			}
			fmt.Print(color.CyanString("║"))
			fmt.Print(" " + content)
			fmt.Print(strings.Repeat(" ", padding))
			fmt.Print(color.CyanString(" ║"))
		}
		currentRow++
	}

	// Draw the modal box
	printCenteredLine("TOP")
	printCenteredLine(title)
	printCenteredLine("SEP")
	printCenteredLine(sortHeader)
	printCenteredLine(sortLine1)
	printCenteredLine(sortLine2)
	printCenteredLine(sortLine3)
	printCenteredLine(sortLine4)
	printCenteredLine("")
	printCenteredLine(navHeader)
	printCenteredLine(navLine)
	printCenteredLine("")
	printCenteredLine(symbolHeader)
	printCenteredLine(symbolLine)
	printCenteredLine("")
	printCenteredLine(colorHeader)
	printCenteredLine(colorLine)
	printCenteredLine("SEP")
	printCenteredLine(closeText)
	printCenteredLine("BOTTOM")

	// Wait for any key from keyChan (don't read directly from stdin to avoid race)
	<-keyChan

	// Show cursor again
	fmt.Print("\033[?25h")

	// Main loop will redraw everything
}

// ============================================================================
// Screen Capture
// ============================================================================

// CaptureScreenSimple saves a simplified text version of the screen
// HINT: This is a fallback solution. Ideally we would capture the exact layout
func CaptureScreenSimple(states map[string]*DeviceState, referenceTime time.Time, network string, interval time.Duration, mode string, scanCount int, scanDuration time.Duration, nextScanIn time.Duration, screenBuffer *bytes.Buffer, screenBufferMux *sync.Mutex, formatIPWithBoldHostFunc func(string) string) {
	screenBufferMux.Lock()
	defer screenBufferMux.Unlock()

	// Reset buffer
	screenBuffer.Reset()

	// Generate screen content without ANSI colors for clipboard
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()

	// Safety check: skip if terminal is too small
	if width < 20 {
		screenBuffer.WriteString("Terminal too small for capture\n")
		return
	}

	// Count stats
	onlineCount := 0
	offlineCount := 0
	totalFlaps := 0
	for _, state := range states {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
		totalFlaps += state.FlapCount
	}

	// Helper: writes a line with correct padding (UTF-8-aware)
	writeLine := func(content string) {
		contentRunes := RuneLen(content)
		padding := width - contentRunes - 3 // -3 for "║ " and " ║"
		if padding < 0 {
			padding = 0
		}
		screenBuffer.WriteString("║ " + content + strings.Repeat(" ", padding) + " ║\n")
	}

	// Top border
	screenBuffer.WriteString("╔" + SafeRepeat("═", width-2) + "╗\n")

	// Title line
	title := "NetSpy - Network Monitor"
	scanInfo := fmt.Sprintf("[Scan #%d]", scanCount)
	spacesNeeded := width - RuneLen(title) - RuneLen(scanInfo) - 3
	titleLine := title + SafeRepeat(" ", spacesNeeded) + scanInfo
	writeLine(titleLine)

	// Separator
	screenBuffer.WriteString("╠" + SafeRepeat("═", width-2) + "╣\n")

	// Info line 1
	line1 := fmt.Sprintf("Network: %s  │  Mode: %s  │  Interval: %v", network, mode, interval)
	writeLine(line1)

	// Info line 2
	line2 := fmt.Sprintf("Devices: %d (↑%d ↓%d)  │  Flaps: %d  │  Scan: %s",
		len(states), onlineCount, offlineCount, totalFlaps, FormatDuration(scanDuration))
	writeLine(line2)

	// Separator
	screenBuffer.WriteString("╠" + SafeRepeat("═", width-2) + "╣\n")

	// Table header and rows (simplified - shows only IPs and status)
	// Sort IPs
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return CompareIPs(ips[i], ips[j])
	})

	// Header
	header := "IP               Stat Hostname               Vendor       Uptime"
	writeLine(header)

	// Rows
	for _, ipStr := range ips {
		state := states[ipStr]
		statusIcon := "+"
		if state.Status == "offline" {
			statusIcon = "-"
		}

		displayIP := formatIPWithBoldHostFunc(ipStr)
		if state.Host.IsGateway {
			displayIP = formatIPWithBoldHostFunc(ipStr) + " G"
		}
		if len(displayIP) > 16 {
			displayIP = displayIP[:16]
		}

		hostname := GetHostname(state.Host)
		// Limit hostname to max 22 characters (runes)
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 22 {
			hostname = string(hostnameRunes[:21]) + "…"
		}

		// Vendor from MAC lookup
		vendor := GetVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		// Limit vendor to max 12 characters
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > 12 {
			vendor = string(vendorRunes[:11]) + "…"
		}

		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}

		// Manual padding with UTF-8 awareness
		paddedIP := PadRight(displayIP, 17)          // 17 characters for IP
		paddedHostname := PadRight(hostname, 22)     // 22 characters for hostname
		paddedVendor := PadRight(vendor, 12)         // 12 characters for vendor
		paddedUptime := PadLeft(FormatDurationShort(statusDuration), 6) // Right-align

		row := paddedIP + statusIcon + "    " + paddedHostname + " " + paddedVendor + " " + paddedUptime
		writeLine(row)
	}

	// Separator
	screenBuffer.WriteString("╠" + SafeRepeat("═", width-2) + "╣\n")

	// Status line
	statusLine := fmt.Sprintf("▶ Next scan in: %s │ ? = Help",
		FormatDuration(nextScanIn))
	writeLine(statusLine)

	// Bottom border
	screenBuffer.WriteString("╚" + SafeRepeat("═", width-2) + "╝\n")
}

// ============================================================================
// Table Rendering Functions
// ============================================================================

// DrawTerminalTooSmallWarning shows warning when terminal is too small
func DrawTerminalTooSmallWarning(termSize output.TerminalSize, width int, scanCount int, activeThreads *int32, getGitVersionFunc func() string) {
	// Absolute minimum check - if window is EXTREMELY small, just print simple message
	if width < 20 {
		fmt.Println("Terminal too small!")
		fmt.Printf("Min: 80x15, Current: %dx%d\n", termSize.Width, termSize.Height)
		fmt.Println("Please resize window.")
		return
	}

	// Top border
	fmt.Print(color.CyanString("╔"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╗\n"))

	// Title line (truncated if necessary)
	gitVersion := getGitVersionFunc()
	title := fmt.Sprintf("NetSpy - Network Monitor %s", gitVersion)
	threadCount := atomic.LoadInt32(activeThreads)
	scanInfo := fmt.Sprintf("[Threads #%d / Scan #%d]", threadCount, scanCount)

	// Calculate padding and prevent negative values
	paddingSpace := width - RuneLen(title) - RuneLen(scanInfo) - 4
	titleLine := title + SafeRepeat(" ", paddingSpace) + scanInfo
	if RuneLen(titleLine) > width-4 {
		maxLen := width - 7
		if maxLen < 0 {
			maxLen = 0
		}
		if maxLen > RuneLen(titleLine) {
			maxLen = RuneLen(titleLine)
		}
		titleLine = string([]rune(titleLine)[:maxLen]) + "..."
	}
	PrintBoxLine(titleLine, width)

	// Separator
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Warning message
	PrintBoxLine("", width) // Empty line
	warningMsg := color.YellowString("⚠ Terminal zu klein!")
	PrintBoxLine(warningMsg, width)
	PrintBoxLine("", width) // Empty line

	minMsg := "Minimum: 80 Spalten x 15 Zeilen (VT100 Standard)"
	PrintBoxLine(minMsg, width)

	currentMsg := fmt.Sprintf("Aktuell: %d Spalten x %d Zeilen", termSize.Width, termSize.Height)
	PrintBoxLine(currentMsg, width)

	PrintBoxLine("", width) // Empty line
	helpMsg := "Bitte vergrößern Sie das Terminal-Fenster."
	PrintBoxLine(helpMsg, width)
	PrintBoxLine("", width) // Empty line

	// Bottom border
	fmt.Print(color.CyanString("╚"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╝\n"))
}

// DrawBtopLayout renders a btop-inspired fullscreen layout
func DrawBtopLayout(states map[string]*DeviceState, referenceTime time.Time, network string, interval time.Duration, mode string, scanCount int, scanDuration time.Duration, nextScanIn time.Duration, activeThreads *int32, currentPage *int32, sortState *SortState, isLocal bool, getGitVersionFunc func() string, captureScreenFunc func(), formatIPWithBoldHostFunc func(string) string, isLocallyAdministeredFunc func(string) bool, getZebraColorFunc func() *color.Color) {
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()

	// Check if terminal is too small for display
	if termSize.IsTooSmall() {
		DrawTerminalTooSmallWarning(termSize, width, scanCount, activeThreads, getGitVersionFunc)
		return
	}

	// Count stats
	onlineCount := 0
	offlineCount := 0
	totalFlaps := 0
	for _, state := range states {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
		totalFlaps += state.FlapCount
	}

	// Top border with title
	fmt.Print(color.CyanString("╔"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╗\n"))

	// Title line - use PrintBoxLine with properly constructed content
	// Get git version info
	gitVersion := getGitVersionFunc()
	title := color.HiWhiteString(fmt.Sprintf("NetSpy - Network Monitor %s", gitVersion))
	// Load active thread count atomically
	threadCount := atomic.LoadInt32(activeThreads)
	scanInfo := color.HiYellowString(fmt.Sprintf("[Threads #%d / Scan #%d]", threadCount, scanCount))
	titleStripped := StripANSI(title)
	scanInfoStripped := StripANSI(scanInfo)
	spacesNeeded := width - RuneLen(titleStripped) - RuneLen(scanInfoStripped) - 4
	titleLine := title + SafeRepeat(" ", spacesNeeded) + scanInfo
	PrintBoxLine(titleLine, width)

	// Separator
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Fixed column widths from left (not dynamically divided)
	col1Width := 24 // "Network: 10.0.0.0/24" + padding
	col2Width := 18 // "Mode : hybrid" + padding
	col3Width := 20 // "Interval: 30s" + padding

	// Info line 1 (static - doesn't change)
	networkDisplay := network
	if !isLocal {
		networkDisplay += " (remote)"
	}
	col1_line1 := PadRight("Network: "+networkDisplay, col1Width)
	col2_line1 := PadRight(PadRight("Mode", 5)+": "+mode, col2Width)
	intervalValue := fmt.Sprintf("%v", interval)
	col3_line1 := PadRight(PadRight("Interval", 8)+": "+intervalValue, col3Width)
	line1 := fmt.Sprintf("%s  │  %s  │  %s", col1_line1, col2_line1, col3_line1)
	PrintBoxLine(line1, width)

	// Info line 2 (dynamic - changes with each scan, but stays aligned)
	devicesValue := fmt.Sprintf("%d (%s%d %s%d)", len(states),
		color.GreenString("↑"), onlineCount,
		color.RedString("↓"), offlineCount)
	col1_line2 := PadRightANSI("Devices: "+devicesValue, col1Width)
	flapsValue := fmt.Sprintf("%d", totalFlaps)
	col2_line2 := PadRight(PadRight("Flaps", 5)+": "+flapsValue, col2Width)
	scanValue := FormatDuration(scanDuration)
	col3_line2 := PadRight(PadRight("Scan", 8)+": "+scanValue, col3Width)
	line2 := fmt.Sprintf("%s  │  %s  │  %s", col1_line2, col2_line2, col3_line2)
	PrintBoxLine(line2, width)

	// Separator before table (directly from info to table)
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Delegate to existing responsive table rendering
	RedrawTable(states, referenceTime, currentPage, scanCount, sortState, formatIPWithBoldHostFunc, isLocallyAdministeredFunc, getZebraColorFunc)

	// Separator before status line
	fmt.Print(color.CyanString("╠"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╣\n"))

	// Status line (inside box) - simplified with ? help
	statusText := color.CyanString("▶") + " Next scan in: " + color.CyanString(FormatDuration(nextScanIn)) +
		"       │  " + color.CyanString("?") + " = Help"
	PrintBoxLine(statusText, width)

	// Bottom border
	fmt.Print(color.CyanString("╚"))
	fmt.Print(color.CyanString(SafeRepeat("═", width-2)))
	fmt.Print(color.CyanString("╝\n"))

	// Capture screen content for later copying - SIMPLIFIED
	// Use the same logic as above, just without colors
	go captureScreenFunc()
}

// CalculateMaxVisibleHosts calculates how many hosts fit on the screen
// based on terminal height
func CalculateMaxVisibleHosts(termHeight int) int {
	// Layout overhead:
	// - Top Border: 1
	// - Title: 1
	// - Separator: 1
	// - Info Line 1: 1
	// - Info Line 2: 1
	// - Separator: 1
	// - Table Header: 1
	// = 7 lines header
	//
	// - Paging Info: 1
	// - Separator: 1
	// - Status Line: 1
	// - Bottom Border: 1
	// - Cursor Line (space after ╝): 1
	// = 5 lines footer
	//
	// Total: 12 lines overhead
	overhead := 12
	availableLines := termHeight - overhead

	// Show at least 1 host (even if terminal is very small)
	if availableLines < 1 {
		return 1
	}

	return availableLines
}

// RedrawTable delegates to the appropriate table layout based on terminal width
func RedrawTable(states map[string]*DeviceState, referenceTime time.Time, currentPage *int32, scanCount int, sortState *SortState, formatIPWithBoldHostFunc func(string) string, isLocallyAdministeredFunc func(string) bool, getZebraColorFunc func() *color.Color) {
	// Hide cursor during redraw to prevent visible cursor jumping
	fmt.Print("\033[?25l")
	defer fmt.Print("\033[?25h") // Show cursor when done

	// Get terminal size for responsive layout
	termSize := output.GetTerminalSize()

	// Choose layout based on terminal width
	if termSize.IsNarrow() {
		RedrawNarrowTable(states, referenceTime, termSize, currentPage, scanCount, sortState, formatIPWithBoldHostFunc, isLocallyAdministeredFunc, getZebraColorFunc)
	} else if termSize.IsMedium() {
		RedrawMediumTable(states, referenceTime, termSize, currentPage, scanCount, sortState, formatIPWithBoldHostFunc, isLocallyAdministeredFunc, getZebraColorFunc)
	} else {
		RedrawWideTable(states, referenceTime, termSize, currentPage, scanCount, sortState, formatIPWithBoldHostFunc, isLocallyAdministeredFunc, getZebraColorFunc)
	}
}

// RedrawNarrowTable - Compact view for narrow terminals (< 100 cols)
func RedrawNarrowTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize, currentPage *int32, scanCount int, sortState *SortState, formatIPWithBoldHostFunc func(string) string, isLocallyAdministeredFunc func(string) bool, getZebraColorFunc func() *color.Color) {
	width := termSize.GetDisplayWidth()

	// Get current sort state for indicators
	sortCol, sortAsc := sortState.Get()

	// Table header with sort indicators and underlined shortcut keys (compact for 80-char terminals)
	headerContent := PadRightANSI(UnderlineChar("IP", 'i')+GetSortIndicator(sortCol, SortByIP, sortAsc), 15) + " " +
		PadRightANSI(UnderlineChar("Hostname", 'h')+GetSortIndicator(sortCol, SortByHostname, sortAsc), 12) + " " +
		PadRightANSI(UnderlineChar("MAC", 'm')+GetSortIndicator(sortCol, SortByMAC, sortAsc), 17) + " " +
		PadRightANSI(UnderlineChar("Vendor", 'v')+GetSortIndicator(sortCol, SortByVendor, sortAsc), 7) + " " +
		PadRightANSI(UnderlineChar("Device", 'd')+GetSortIndicator(sortCol, SortByDeviceType, sortAsc), 6) + " " +
		PadRightANSI(UnderlineChar("RTT", 'r')+GetSortIndicator(sortCol, SortByRTT, sortAsc), 4) + " " +
		PadRightANSI(UnderlineChar("Flp", 'f')+GetSortIndicator(sortCol, SortByFlaps, sortAsc), 3) + " " +
		PadRightANSI(UnderlineChar("Up", 'u')+GetSortIndicator(sortCol, SortByUptime, sortAsc), 5)
	PrintTableRow(color.CyanString(headerContent), width)

	// Create IPs slice and sort based on current sort state
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	SortIPs(ips, states, sortState, referenceTime)

	// Calculate paging
	totalHosts := len(ips)
	maxVisible := CalculateMaxVisibleHosts(termSize.Height)

	// Calculate total pages
	totalPages := (totalHosts + maxVisible - 1) / maxVisible
	if totalPages < 1 {
		totalPages = 1
	}

	// Ensure currentPage is within bounds
	page := atomic.LoadInt32(currentPage)
	if page < 1 {
		atomic.StoreInt32(currentPage, 1)
		page = 1
	}
	if int(page) > totalPages {
		atomic.StoreInt32(currentPage, int32(totalPages))
		page = int32(totalPages)
	}

	// Calculate slice range for current page
	startIdx := int(page-1) * maxVisible
	endIdx := startIdx + maxVisible
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	visibleIPs := ips[startIdx:endIdx]

	// Print each device
	for i, ipStr := range visibleIPs {
		state := states[ipStr]

		// Build IP with markers (Gateway, Offline, New) - with bold host part
		displayIP := formatIPWithBoldHostFunc(ipStr)
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		// Mark as new if detected in last 2 scans (but not first scan)
		isNew := state.FirstSeenScan > 1 && (scanCount-state.FirstSeenScan) < 2
		if isNew {
			displayIP += " [+]"
		}

		// UTF-8-aware truncation
		displayIPRunes := []rune(displayIP)
		if len(displayIPRunes) > 15 {
			displayIP = string(displayIPRunes[:15])
		}

		// Color IP: red if offline, green if new, otherwise use zebra striping
		displayIPPadded := PadRightANSI(displayIP, 15)
		if state.Status == "offline" {
			displayIPPadded = color.RedString(displayIPPadded)
		} else if isNew {
			displayIPPadded = color.GreenString(displayIPPadded)
		} else if i%2 == 1 {
			// Zebra striping: odd rows darker
			displayIPPadded = getZebraColorFunc().Sprint(displayIPPadded)
		}

		hostname := GetHostname(state.Host)
		// UTF-8-aware truncation (compact: 12 chars)
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 12 {
			hostname = string(hostnameRunes[:11]) + "…"
		}

		// Format MAC address
		mac := state.Host.MAC
		if mac == "" {
			mac = "-"
		}

		// Vendor from MAC lookup (compact: 7 chars)
		vendor := GetVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		// UTF-8-aware truncation
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > 7 {
			vendor = string(vendorRunes[:6]) + "…"
		}

		// Device type (compact: 6 chars)
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
		}
		// UTF-8-aware truncation
		deviceTypeRunes := []rune(deviceType)
		if len(deviceTypeRunes) > 6 {
			deviceType = string(deviceTypeRunes[:5]) + "…"
		}

		// Format RTT (compact: max 4 chars like "1ms" or "99ms")
		rttText := "-"
		if state.Host.RTT > 0 {
			rtt := state.Host.RTT
			if rtt < time.Millisecond {
				// Microseconds without decimal
				rttText = fmt.Sprintf("%.0fµ", float64(rtt.Microseconds()))
			} else if rtt < time.Second {
				// Milliseconds without "ms" if > 99
				ms := float64(rtt.Microseconds()) / 1000.0
				if ms < 100 {
					rttText = fmt.Sprintf("%.0fm", ms)
				} else {
					rttText = fmt.Sprintf("%.0f", ms)
				}
			} else {
				rttText = fmt.Sprintf("%.1fs", rtt.Seconds())
			}
		}

		// Format flap count
		flapStr := fmt.Sprintf("%d", state.FlapCount)

		// Calculate status duration
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}

		// Apply padding (compact for 80-char terminals)
		hostnamePadded := PadRight(hostname, 12)
		macPadded := PadRight(mac, 17)
		vendorPadded := PadRight(vendor, 7)
		deviceTypePadded := PadRight(deviceType, 6)
		rttPadded := PadLeft(rttText, 4)
		flapPadded := PadLeft(flapStr, 3)
		uptimePadded := PadLeft(FormatDurationShort(statusDuration), 5)

		// Apply colors: locally-administered MAC in yellow, flaps in yellow if > 0
		if isLocallyAdministeredFunc(mac) {
			macPadded = color.YellowString(macPadded)
		}
		if state.FlapCount > 0 {
			flapPadded = color.YellowString(flapPadded)
		}

		// Apply zebra striping to other columns (except IP which has its own color logic)
		if i%2 == 1 && state.Status != "offline" && !isNew {
			// Zebra striping for odd rows (only if not offline/new - they have priority colors)
			hostnamePadded = getZebraColorFunc().Sprint(hostnamePadded)
			if !isLocallyAdministeredFunc(mac) {
				macPadded = getZebraColorFunc().Sprint(macPadded)
			}
			vendorPadded = getZebraColorFunc().Sprint(vendorPadded)
			deviceTypePadded = getZebraColorFunc().Sprint(deviceTypePadded)
			rttPadded = getZebraColorFunc().Sprint(rttPadded)
			if state.FlapCount == 0 {
				flapPadded = getZebraColorFunc().Sprint(flapPadded)
			}
			uptimePadded = getZebraColorFunc().Sprint(uptimePadded)
		}

		// Assemble row with UTF-8-aware padding
		rowContent := displayIPPadded + " " + hostnamePadded + " " + macPadded + " " + vendorPadded + " " + deviceTypePadded + " " + rttPadded + " " + flapPadded + " " + uptimePadded

		PrintTableRow(rowContent, width)
	}

	// Show paging indicator if multiple pages exist
	if totalPages > 1 {
		indicator := fmt.Sprintf("  Page %d/%d (%d hosts total)", page, totalPages, totalHosts)
		PrintTableRow(color.CyanString(indicator), width)
	}
}

// RedrawMediumTable - Standard view for medium terminals (100-139 cols)
func RedrawMediumTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize, currentPage *int32, scanCount int, sortState *SortState, formatIPWithBoldHostFunc func(string) string, isLocallyAdministeredFunc func(string) bool, getZebraColorFunc func() *color.Color) {
	width := termSize.GetDisplayWidth()

	// Get current sort state for indicators
	sortCol, sortAsc := sortState.Get()

	// Table header with sort indicators and underlined shortcut keys
	headerContent := PadRightANSI(UnderlineChar("IP Address", 'i')+GetSortIndicator(sortCol, SortByIP, sortAsc), 18) + " " +
		PadRightANSI(UnderlineChar("Hostname", 'h')+GetSortIndicator(sortCol, SortByHostname, sortAsc), 20) + " " +
		PadRightANSI(UnderlineChar("MAC Address", 'm')+GetSortIndicator(sortCol, SortByMAC, sortAsc), 18) + " " +
		PadRightANSI(UnderlineChar("Vendor", 'v')+GetSortIndicator(sortCol, SortByVendor, sortAsc), 15) + " " +
		PadRightANSI(UnderlineChar("Device", 'd')+GetSortIndicator(sortCol, SortByDeviceType, sortAsc), 12) + " " +
		PadRightANSI(UnderlineChar("RTT", 'r')+GetSortIndicator(sortCol, SortByRTT, sortAsc), 8) + " " +
		PadRightANSI(UnderlineChar("Flaps", 'f')+GetSortIndicator(sortCol, SortByFlaps, sortAsc), 5)
	PrintTableRow(color.CyanString(headerContent), width)

	// Create IPs slice and sort based on current sort state
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	SortIPs(ips, states, sortState, referenceTime)

	// Calculate paging
	totalHosts := len(ips)
	maxVisible := CalculateMaxVisibleHosts(termSize.Height)

	// Calculate total pages
	totalPages := (totalHosts + maxVisible - 1) / maxVisible
	if totalPages < 1 {
		totalPages = 1
	}

	// Ensure currentPage is within bounds
	page := atomic.LoadInt32(currentPage)
	if page < 1 {
		atomic.StoreInt32(currentPage, 1)
		page = 1
	}
	if int(page) > totalPages {
		atomic.StoreInt32(currentPage, int32(totalPages))
		page = int32(totalPages)
	}

	// Calculate slice range for current page
	startIdx := int(page-1) * maxVisible
	endIdx := startIdx + maxVisible
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	visibleIPs := ips[startIdx:endIdx]

	// Print each device
	for i, ipStr := range visibleIPs {
		state := states[ipStr]

		// Build IP with markers (Gateway, Offline, New) - with bold host part
		displayIP := formatIPWithBoldHostFunc(ipStr)
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		// Mark as new if detected in last 2 scans (but not first scan)
		isNew := state.FirstSeenScan > 1 && (scanCount-state.FirstSeenScan) < 2
		if isNew {
			displayIP += " [+]"
		}

		// Color IP: red if offline, green if new, otherwise use zebra striping
		displayIPPadded := PadRightANSI(displayIP, 18)
		if state.Status == "offline" {
			displayIPPadded = color.RedString(displayIPPadded)
		} else if isNew {
			displayIPPadded = color.GreenString(displayIPPadded)
		} else if i%2 == 1 {
			// Zebra striping: odd rows darker
			displayIPPadded = getZebraColorFunc().Sprint(displayIPPadded)
		}

		hostname := GetHostname(state.Host)
		// UTF-8-aware truncation
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > 20 {
			hostname = string(hostnameRunes[:19]) + "…"
		}
		hostnamePadded := PadRight(hostname, 20)

		// Format MAC address
		mac := state.Host.MAC
		if mac == "" || mac == "-" {
			mac = "-"
		}
		macPadded := PadRight(mac, 18)
		if isLocallyAdministeredFunc(mac) {
			macPadded = color.YellowString(macPadded)
		}

		// Vendor from MAC lookup
		vendor := GetVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		// UTF-8-aware truncation
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > 15 {
			vendor = string(vendorRunes[:14]) + "…"
		}
		vendorPadded := PadRight(vendor, 15)

		// Device type classification
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
		}
		// UTF-8-aware truncation
		deviceTypeRunes := []rune(deviceType)
		if len(deviceTypeRunes) > 12 {
			deviceType = string(deviceTypeRunes[:11]) + "…"
		}
		deviceTypePadded := PadRight(deviceType, 12)

		// Format RTT
		rttText := "-"
		if state.Host.RTT > 0 {
			rtt := state.Host.RTT
			if rtt < time.Millisecond {
				rttText = fmt.Sprintf("%.1fµs", float64(rtt.Microseconds()))
			} else if rtt < time.Second {
				rttText = fmt.Sprintf("%.1fms", float64(rtt.Microseconds())/1000.0)
			} else {
				rttText = fmt.Sprintf("%.2fs", rtt.Seconds())
			}
		}
		rttPadded := PadLeft(rttText, 8)

		// Format flap count
		flapStr := fmt.Sprintf("%d", state.FlapCount)
		flapNum := PadRight(flapStr, 5)
		if state.FlapCount > 0 {
			flapNum = color.YellowString(flapNum)
		}

		// Apply zebra striping to non-colored columns (odd rows get darker)
		if i%2 == 1 && state.Status != "offline" && !isNew {
			hostnamePadded = getZebraColorFunc().Sprint(hostnamePadded)
			// MAC only if not yellow (locally-administered)
			if !isLocallyAdministeredFunc(mac) {
				macPadded = getZebraColorFunc().Sprint(macPadded)
			}
			vendorPadded = getZebraColorFunc().Sprint(vendorPadded)
			deviceTypePadded = getZebraColorFunc().Sprint(deviceTypePadded)
			rttPadded = getZebraColorFunc().Sprint(rttPadded)
		}

		// Assemble row with UTF-8-aware padding
		rowContent := displayIPPadded + " " +
			hostnamePadded + " " +
			macPadded + " " +
			vendorPadded + " " +
			deviceTypePadded + " " +
			rttPadded + " " +
			flapNum

		PrintTableRow(rowContent, width)
	}

	// Show paging indicator if multiple pages exist
	if totalPages > 1 {
		indicator := fmt.Sprintf("  Page %d/%d (%d hosts total)", page, totalPages, totalHosts)
		PrintTableRow(color.CyanString(indicator), width)
	}
}

// RedrawWideTable - Full view for wide terminals (>= 140 cols)
func RedrawWideTable(states map[string]*DeviceState, referenceTime time.Time, termSize output.TerminalSize, currentPage *int32, scanCount int, sortState *SortState, formatIPWithBoldHostFunc func(string) string, isLocallyAdministeredFunc func(string) bool, getZebraColorFunc func() *color.Color) {
	// Calculate dynamic column widths based on terminal size
	termWidth := termSize.GetDisplayWidth()

	// Fixed columns: IP(17) + MAC(18) + RTT(8) + FirstSeen(13) + Uptime(12) + Flaps(5) = 73
	// Spaces between columns: 8 spaces = 8
	// Borders: "║ " + " ║" = 4
	// Total fixed: 73 + 8 + 4 = 85
	// Remaining for Hostname + Vendor + Type
	remainingWidth := termWidth - 85

	// Distribute remaining width: 50% hostname, 25% vendor, 25% type (with minimums)
	hostnameWidth := max(20, min(40, int(float64(remainingWidth)*0.5)))
	vendorWidth := max(15, int(float64(remainingWidth)*0.25))
	typeWidth := max(12, remainingWidth-hostnameWidth-vendorWidth)

	// Get current sort state for indicators
	sortCol, sortAsc := sortState.Get()

	// Table header with sort indicators and underlined shortcut keys
	headerContent := PadRightANSI(UnderlineChar("IP Address", 'i')+GetSortIndicator(sortCol, SortByIP, sortAsc), 17) + " " +
		PadRightANSI(UnderlineChar("Hostname", 'h')+GetSortIndicator(sortCol, SortByHostname, sortAsc), hostnameWidth) + " " +
		PadRightANSI(UnderlineChar("MAC Address", 'm')+GetSortIndicator(sortCol, SortByMAC, sortAsc), 18) + " " +
		PadRightANSI(UnderlineChar("Vendor", 'v')+GetSortIndicator(sortCol, SortByVendor, sortAsc), vendorWidth) + " " +
		PadRightANSI(UnderlineChar("Device", 'd')+GetSortIndicator(sortCol, SortByDeviceType, sortAsc), typeWidth) + " " +
		PadRightANSI(UnderlineChar("RTT", 'r')+GetSortIndicator(sortCol, SortByRTT, sortAsc), 8) + " " +
		PadRightANSI(UnderlineChar("Time", 't')+GetSortIndicator(sortCol, SortByFirstSeen, sortAsc), 13) + " " +
		PadRightANSI(UnderlineChar("Uptime", 'u')+GetSortIndicator(sortCol, SortByUptime, sortAsc), 12) + " " +
		PadRightANSI(UnderlineChar("Flaps", 'f')+GetSortIndicator(sortCol, SortByFlaps, sortAsc), 5)

	PrintTableRow(color.CyanString(headerContent), termWidth)

	// Create IPs slice and sort based on current sort state
	ips := make([]string, 0, len(states))
	for ip := range states {
		ips = append(ips, ip)
	}
	SortIPs(ips, states, sortState, referenceTime)

	// Calculate paging
	totalHosts := len(ips)
	maxVisible := CalculateMaxVisibleHosts(termSize.Height)

	// Calculate total pages
	totalPages := (totalHosts + maxVisible - 1) / maxVisible
	if totalPages < 1 {
		totalPages = 1
	}

	// Ensure currentPage is within bounds
	page := atomic.LoadInt32(currentPage)
	if page < 1 {
		atomic.StoreInt32(currentPage, 1)
		page = 1
	}
	if int(page) > totalPages {
		atomic.StoreInt32(currentPage, int32(totalPages))
		page = int32(totalPages)
	}

	// Calculate slice range for current page
	startIdx := int(page-1) * maxVisible
	endIdx := startIdx + maxVisible
	if endIdx > len(ips) {
		endIdx = len(ips)
	}

	visibleIPs := ips[startIdx:endIdx]

	// Print each device
	for i, ipStr := range visibleIPs {
		state := states[ipStr]

		// Build IP with markers (Gateway, Offline, New) - with bold host part
		displayIP := formatIPWithBoldHostFunc(ipStr)
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		// Mark as new if detected in last 2 scans (but not first scan)
		isNew := state.FirstSeenScan > 1 && (scanCount-state.FirstSeenScan) < 2
		if isNew {
			displayIP += " [+]"
		}

		// Color IP: red if offline, green if new, otherwise use zebra striping
		displayIPPadded := PadRightANSI(displayIP, 17)
		if state.Status == "offline" {
			displayIPPadded = color.RedString(displayIPPadded)
		} else if isNew {
			displayIPPadded = color.GreenString(displayIPPadded)
		} else if i%2 == 1 {
			// Zebra striping: odd rows darker
			displayIPPadded = getZebraColorFunc().Sprint(displayIPPadded)
		}

		// Hostname - use dynamic width with UTF-8 awareness
		hostname := GetHostname(state.Host)
		hostnameRunes := []rune(hostname)
		if len(hostnameRunes) > hostnameWidth {
			hostname = string(hostnameRunes[:hostnameWidth-1]) + "…"
		}
		hostnamePadded := PadRight(hostname, hostnameWidth)

		// Format MAC address - handle color after padding
		mac := state.Host.MAC
		if mac == "" || mac == "-" {
			mac = "-"
		}
		macPadded := PadRight(mac, 18)
		if isLocallyAdministeredFunc(mac) {
			macPadded = color.YellowString(macPadded)
		}

		// Vendor from MAC lookup - use dynamic width
		vendor := GetVendor(state.Host)
		if vendor == "" || vendor == "-" {
			vendor = "-"
		}
		vendorRunes := []rune(vendor)
		if len(vendorRunes) > vendorWidth {
			vendor = string(vendorRunes[:vendorWidth-1]) + "…"
		}
		vendorPadded := PadRight(vendor, vendorWidth)

		// Device type classification - use dynamic width
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
		}
		deviceTypeRunes := []rune(deviceType)
		if len(deviceTypeRunes) > typeWidth {
			deviceType = string(deviceTypeRunes[:typeWidth-1]) + "…"
		}
		deviceTypePadded := PadRight(deviceType, typeWidth)

		firstSeen := state.FirstSeen.Format("15:04:05")
		firstSeenPadded := PadRight(firstSeen, 13)

		// Calculate uptime/downtime based on status
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}
		uptimePadded := PadLeft(FormatDuration(statusDuration), 12)

		// Format RTT
		rttText := "-"
		if state.Host.RTT > 0 {
			rtt := state.Host.RTT
			if rtt < time.Millisecond {
				rttText = fmt.Sprintf("%.1fµs", float64(rtt.Microseconds()))
			} else if rtt < time.Second {
				rttText = fmt.Sprintf("%.1fms", float64(rtt.Microseconds())/1000.0)
			} else {
				rttText = fmt.Sprintf("%.2fs", rtt.Seconds())
			}
		}
		rttPadded := PadLeft(rttText, 8)

		// Format flap count - UTF-8 aware padding
		flapStr := fmt.Sprintf("%d", state.FlapCount)
		flapNum := PadRight(flapStr, 5)
		if state.FlapCount > 0 {
			flapNum = color.YellowString(flapNum)
		}

		// Apply zebra striping to non-colored columns (odd rows get darker)
		if i%2 == 1 && state.Status != "offline" && !isNew {
			hostnamePadded = getZebraColorFunc().Sprint(hostnamePadded)
			// MAC only if not yellow (locally-administered)
			if !isLocallyAdministeredFunc(mac) {
				macPadded = getZebraColorFunc().Sprint(macPadded)
			}
			vendorPadded = getZebraColorFunc().Sprint(vendorPadded)
			deviceTypePadded = getZebraColorFunc().Sprint(deviceTypePadded)
			rttPadded = getZebraColorFunc().Sprint(rttPadded)
			firstSeenPadded = getZebraColorFunc().Sprint(firstSeenPadded)
			uptimePadded = getZebraColorFunc().Sprint(uptimePadded)
		}

		// Assemble row with UTF-8-aware padding
		rowContent := displayIPPadded + " " +
			hostnamePadded + " " +
			macPadded + " " +
			vendorPadded + " " +
			deviceTypePadded + " " +
			rttPadded + " " +
			firstSeenPadded + " " +
			uptimePadded + " " +
			flapNum

		PrintTableRow(rowContent, termWidth)
	}

	// Show paging indicator if multiple pages exist
	if totalPages > 1 {
		indicator := fmt.Sprintf("  Page %d/%d (%d hosts total)", page, totalPages, totalHosts)
		PrintTableRow(color.CyanString(indicator), termWidth)
	}
}

// UpdateHeaderLineOnly updates only the header line with thread count (fast, no flicker)
func UpdateHeaderLineOnly(scanCount int, activeThreads *int32, getGitVersionFunc func() string) {
	termSize := output.GetTerminalSize()
	width := termSize.GetDisplayWidth()
	gitVersion := getGitVersionFunc()
	title := color.HiWhiteString(fmt.Sprintf("NetSpy - Network Monitor %s", gitVersion))

	// Load active thread count atomically
	threadCount := atomic.LoadInt32(activeThreads)
	scanInfo := color.HiYellowString(fmt.Sprintf("[Threads #%d / Scan #%d]", threadCount, scanCount))

	titleStripped := StripANSI(title)
	scanInfoStripped := StripANSI(scanInfo)
	spacesNeeded := width - RuneLen(titleStripped) - RuneLen(scanInfoStripped) - 4
	titleLine := title + SafeRepeat(" ", spacesNeeded) + scanInfo

	// Move cursor to line 2, column 1 (header line is 2nd line after top border)
	fmt.Print("\033[2;1H")
	// Print the updated header line
	PrintBoxLine(titleLine, width)
}

// ============================================================================
// Utility Functions
// ============================================================================

// FormatDuration formats a duration into a human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd %dh", days, hours)
}

// FormatDurationShort formats a duration into a very short string (compact)
func FormatDurationShort(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	} else {
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// Min returns the minimum of two integers
func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two integers
func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Lowercase aliases for internal use
func min(a, b int) int { return Min(a, b) }
func max(a, b int) int { return Max(a, b) }

// IsLocallyAdministered checks if a MAC address is locally administered
// (second character is 2, 6, A, or E)
func IsLocallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	// Check the second character of the MAC address
	secondChar := strings.ToUpper(string(mac[1]))
	return secondChar == "2" || secondChar == "6" || secondChar == "A" || secondChar == "E"
}

// GetGitVersion returns the current git version (short hash)
func GetGitVersion() string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "dev"
	}
	return "(" + strings.TrimSpace(string(output)) + ")"
}

// FormatIPWithBoldHost formats an IP address with bold host part based on CIDR
// PLACEHOLDER: This function is platform-specific (watch_windows.go, watch_darwin.go, etc.)
// The actual implementation will be provided by the caller as a function parameter
func FormatIPWithBoldHost(ip string, cidr *net.IPNet) string {
	// This is a placeholder - actual implementation is platform-specific
	// Callers should pass formatIPWithBoldHostFunc as a parameter
	return ip
}
