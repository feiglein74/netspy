package cmd

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"netspy/pkg/scanner"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Model repräsentiert den State der Bubbletea-Anwendung
type watchModel struct {
	// Network Info
	network       string
	mode          string
	interval      time.Duration

	// Device States
	deviceStates  map[string]*DeviceState
	sortedIPs     []string

	// UI State
	viewport      viewportState
	searchMode    bool
	searchQuery   string

	// Scan Stats
	scanCount     int
	scanDuration  time.Duration
	nextScanTime  time.Time
	lastScanTime  time.Time

	// Terminal Size
	width         int
	height        int

	// Timing
	ticker        *time.Ticker
	quitting      bool
}

// viewportState verwaltet die Scroll-Position
type viewportState struct {
	offset       int  // Aktuelle Scroll-Position (erste sichtbare Zeile)
	cursor       int  // Ausgewählte Zeile (für Navigation)
	maxVisible   int  // Maximale Anzahl sichtbarer Zeilen
}

// Init initialisiert das Model
func (m watchModel) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		performScanCmd(m.network, m.mode), // Sofort ersten Scan starten
		tickEverySecond(),                 // Countdown-Timer
	)
}

// tickEverySecond sendet jede Sekunde einen Tick für Countdown-Updates
func tickEverySecond() tea.Cmd {
	return tea.Tick(1*time.Second, func(t time.Time) tea.Msg {
		return countdownTickMsg(t)
	})
}

// Countdown Tick Message
type countdownTickMsg time.Time

// tickCmd triggert den nächsten Scan nach dem Interval
func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return scanTickMsg(t)
	})
}

// Nachrichten-Typen für Bubbletea
type scanTickMsg time.Time
type scanCompleteMsg struct {
	hosts    []scanner.Host
	duration time.Duration
}

// Update verarbeitet eingehende Events
func (m watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		return m.handleKeypress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateViewport()
		return m, nil

	case countdownTickMsg:
		// Countdown-Update jede Sekunde für UI refresh
		return m, tickEverySecond()

	case scanTickMsg:
		// Trigger Scan in Background
		return m, performScanCmd(m.network, m.mode)

	case scanCompleteMsg:
		// Update Device States mit Scan-Ergebnissen
		m.updateDeviceStates(msg.hosts)
		m.scanCount++
		m.scanDuration = msg.duration
		m.lastScanTime = time.Now()
		m.nextScanTime = m.lastScanTime.Add(m.interval)

		// Schedule nächsten Scan
		return m, tickCmd(m.interval)
	}

	return m, nil
}

// handleKeypress verarbeitet Keyboard-Input
func (m watchModel) handleKeypress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Quit
	if msg.String() == "q" || msg.String() == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}

	// Search Mode Toggle
	if msg.String() == "/" {
		m.searchMode = !m.searchMode
		if !m.searchMode {
			m.searchQuery = ""
		}
		return m, nil
	}

	// Search Input
	if m.searchMode {
		switch msg.String() {
		case "enter":
			m.searchMode = false
		case "backspace":
			if len(m.searchQuery) > 0 {
				m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
			}
		case "esc":
			m.searchMode = false
			m.searchQuery = ""
		default:
			m.searchQuery += msg.String()
		}
		return m, nil
	}

	// Scrolling (nur wenn nicht im Search Mode)
	switch msg.String() {
	case "up", "k":
		if m.viewport.offset > 0 {
			m.viewport.offset--
		}
	case "down", "j":
		maxOffset := len(m.sortedIPs) - m.viewport.maxVisible
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.viewport.offset < maxOffset {
			m.viewport.offset++
		}
	case "pgup":
		m.viewport.offset -= 10
		if m.viewport.offset < 0 {
			m.viewport.offset = 0
		}
	case "pgdown":
		maxOffset := len(m.sortedIPs) - m.viewport.maxVisible
		if maxOffset < 0 {
			maxOffset = 0
		}
		m.viewport.offset += 10
		if m.viewport.offset > maxOffset {
			m.viewport.offset = maxOffset
		}
	case "home":
		m.viewport.offset = 0
	case "end":
		maxOffset := len(m.sortedIPs) - m.viewport.maxVisible
		if maxOffset < 0 {
			maxOffset = 0
		}
		m.viewport.offset = maxOffset
	}

	return m, nil
}

// updateViewport berechnet maximal sichtbare Zeilen basierend auf Terminal-Höhe
func (m *watchModel) updateViewport() {
	// Terminal-Höhe - Header (6) - Footer (2) - Padding
	availableLines := m.height - 10
	if availableLines < 5 {
		availableLines = 5
	}
	m.viewport.maxVisible = availableLines
}

// updateDeviceStates aktualisiert Device-States mit Scan-Ergebnissen
func (m *watchModel) updateDeviceStates(hosts []scanner.Host) {
	now := time.Now()

	// Update existing devices oder erstelle neue
	for _, host := range hosts {
		ipStr := host.IP.String()

		if state, exists := m.deviceStates[ipStr]; exists {
			// Existing device
			state.Host = host
			state.LastSeen = now

			// Status change detection
			newStatus := "online"
			if !host.Online {
				newStatus = "offline"
			}

			if state.Status != newStatus {
				state.Status = newStatus
				state.StatusSince = now
				state.FlapCount++
			}
		} else {
			// New device
			m.deviceStates[ipStr] = &DeviceState{
				Host:        host,
				FirstSeen:   now,
				LastSeen:    now,
				Status:      "online",
				StatusSince: now,
			}
		}
	}

	// Update sorted IPs
	m.sortedIPs = make([]string, 0, len(m.deviceStates))
	for ip := range m.deviceStates {
		// Filter nach Search Query (falls aktiv)
		if m.searchQuery != "" {
			state := m.deviceStates[ip]
			query := strings.ToLower(m.searchQuery)
			if !strings.Contains(strings.ToLower(ip), query) &&
			   !strings.Contains(strings.ToLower(state.Host.Hostname), query) &&
			   !strings.Contains(strings.ToLower(state.Host.MAC), query) &&
			   !strings.Contains(strings.ToLower(state.Host.Vendor), query) {
				continue
			}
		}
		m.sortedIPs = append(m.sortedIPs, ip)
	}

	// Sort IPs
	sort.Slice(m.sortedIPs, func(i, j int) bool {
		return compareIPs(m.sortedIPs[i], m.sortedIPs[j])
	})
}

// View rendert die UI
func (m watchModel) View() string {
	if m.quitting {
		return "Goodbye! 👋\n"
	}

	var s strings.Builder

	// Styles
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("86")).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("86")).
		Padding(0, 1)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("214"))

	// Header
	title := titleStyle.Render(fmt.Sprintf("NetSpy - Network Monitor [Scan #%d]", m.scanCount))
	s.WriteString(headerStyle.Render(title))
	s.WriteString("\n\n")

	// Info Lines
	s.WriteString(fmt.Sprintf("Network: %s  │  Mode: %s  │  Interval: %v\n",
		m.network, m.mode, m.interval))

	onlineCount := 0
	offlineCount := 0
	for _, state := range m.deviceStates {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
	}

	s.WriteString(fmt.Sprintf("Devices: %d (↑%d ↓%d)  │  Scan: %v\n",
		len(m.deviceStates), onlineCount, offlineCount, m.scanDuration))

	// Search Bar (wenn aktiv)
	if m.searchMode || m.searchQuery != "" {
		searchStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("214")).
			Bold(true)
		s.WriteString(searchStyle.Render(fmt.Sprintf("\nSearch: %s_", m.searchQuery)))
		s.WriteString("\n")
	}

	s.WriteString("\n")

	// Table Header
	headerLine := fmt.Sprintf("%-15s %-7s %-20s %-18s %-15s %s",
		"IP Address", "Status", "Hostname", "MAC", "Vendor", "Uptime")
	s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(headerLine))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", m.width))
	s.WriteString("\n")

	// Device List (nur sichtbare Zeilen)
	visibleDevices := m.getVisibleDevices()
	for _, ipStr := range visibleDevices {
		state := m.deviceStates[ipStr]
		s.WriteString(m.renderDeviceRow(state))
		s.WriteString("\n")
	}

	// Scroll Indicator
	if len(m.sortedIPs) > m.viewport.maxVisible {
		totalDevices := len(m.sortedIPs)
		showing := m.viewport.offset + 1
		showingEnd := m.viewport.offset + len(visibleDevices)
		scrollInfo := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render(fmt.Sprintf("\nShowing %d-%d of %d devices", showing, showingEnd, totalDevices))
		s.WriteString(scrollInfo)
		s.WriteString("\n")
	}

	// Footer
	s.WriteString("\n")
	nextScanIn := time.Until(m.nextScanTime)
	if nextScanIn < 0 {
		nextScanIn = 0
	}

	footerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	s.WriteString(footerStyle.Render(fmt.Sprintf(
		"▶ Next scan in: %s │ q: quit │ /: search │ ↑↓: scroll │ PgUp/PgDn: page",
		formatDuration(nextScanIn))))

	return s.String()
}

// getVisibleDevices gibt nur die aktuell sichtbaren Devices zurück
func (m watchModel) getVisibleDevices() []string {
	start := m.viewport.offset
	end := m.viewport.offset + m.viewport.maxVisible

	if start >= len(m.sortedIPs) {
		return []string{}
	}

	if end > len(m.sortedIPs) {
		end = len(m.sortedIPs)
	}

	return m.sortedIPs[start:end]
}

// renderDeviceRow rendert eine einzelne Device-Zeile
func (m watchModel) renderDeviceRow(state *DeviceState) string {
	// Status Icon und Color
	statusIcon := "●"
	statusColor := lipgloss.Color("82") // grün
	if state.Status == "offline" {
		statusColor = lipgloss.Color("196") // rot
	}

	statusStr := lipgloss.NewStyle().
		Foreground(statusColor).
		Render(fmt.Sprintf("%s %s", statusIcon, state.Status))

	// Gateway Marker
	ipStr := state.Host.IP.String()
	if state.Host.IsGateway {
		ipStr += " [G]"
	}

	// Hostname
	hostname := state.Host.Hostname
	if hostname == "" {
		hostname = "-"
	}

	// MAC
	mac := state.Host.MAC
	if mac == "" {
		mac = "-"
	}

	// Vendor
	vendor := state.Host.Vendor
	if vendor == "" {
		vendor = "-"
	}
	if len(vendor) > 15 {
		vendor = vendor[:12] + "..."
	}

	// Uptime
	uptime := time.Since(state.StatusSince)

	return fmt.Sprintf("%-15s %-15s %-20s %-18s %-15s %s",
		ipStr,
		statusStr,
		hostname,
		mac,
		vendor,
		formatDuration(uptime))
}

// performScanCmd führt Scan aus und returned scanCompleteMsg
func performScanCmd(network, mode string) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()

		// Netzwerk parsen
		_, netCIDR, err := net.ParseCIDR(network)
		if err != nil {
			return scanCompleteMsg{
				hosts:    []scanner.Host{},
				duration: time.Since(start),
			}
		}

		// Context für Scan
		ctx := context.Background()

		// Nutze bestehende performScanQuiet Logik
		hosts := performScanQuiet(ctx, network, netCIDR, mode)

		return scanCompleteMsg{
			hosts:    hosts,
			duration: time.Since(start),
		}
	}
}

// newWatchModel erstellt ein neues Model
func newWatchModel(network, mode string, interval time.Duration) watchModel {
	m := watchModel{
		network:      network,
		mode:         mode,
		interval:     interval,
		deviceStates: make(map[string]*DeviceState),
		sortedIPs:    []string{},
		viewport: viewportState{
			offset:     0,
			cursor:     0,
			maxVisible: 20, // Default, wird von updateViewport() angepasst
		},
		width:  80,
		height: 24,
	}

	return m
}

// runWatchBubbletea startet den Watch-Modus mit Bubbletea UI
func runWatchBubbletea(network, mode string, interval time.Duration) error {
	// Model erstellen
	m := newWatchModel(network, mode, interval)

	// Bubbletea Program erstellen
	p := tea.NewProgram(
		m,
		tea.WithAltScreen(),       // Alt Screen Buffer verwenden
		tea.WithMouseCellMotion(), // Mouse Support (optional)
	)

	// Program starten (blockiert bis Quit)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running watch UI: %v", err)
	}

	return nil
}
