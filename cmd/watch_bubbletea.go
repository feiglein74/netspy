package cmd

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"netspy/pkg/discovery"
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

// DNS Lookup Result enthält Hostname und Source
type dnsLookupResult struct {
	hostname string
	source   string
}

// DNS Lookup Complete Message - enthält aufgelöste Hostnames
type dnsLookupCompleteMsg struct {
	updates map[string]dnsLookupResult // IP -> {Hostname, Source}
}

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

	case tea.MouseMsg:
		return m.handleMouse(msg)

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

		// Start Background DNS Lookups für neue Devices
		return m, tea.Batch(
			tickCmd(m.interval),
			performBackgroundDNSLookupsCmd(m.deviceStates),
		)

	case dnsLookupCompleteMsg:
		// DNS-Lookups abgeschlossen - Updates thread-safe anwenden
		for ip, update := range msg.updates {
			if state, exists := m.deviceStates[ip]; exists {
				if update.hostname != "" {
					state.Host.Hostname = update.hostname
					state.Host.HostnameSource = update.source

					// Update device type nach Hostname-Auflösung
					state.Host.DeviceType = discovery.DetectDeviceType(
						state.Host.Hostname,
						state.Host.MAC,
						state.Host.Vendor,
						state.Host.Ports,
					)
				} else {
					// Markiere als "versucht" auch wenn fehlgeschlagen
					state.Host.HostnameSource = "none"
				}
			}
		}
		return m, nil

	}

	return m, nil
}

// handleMouse verarbeitet Mouse-Events (Scroll-Wheel)
func (m watchModel) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	// Nur Scroll-Events verarbeiten
	switch msg.Type {
	case tea.MouseWheelUp:
		// Scroll up = nach oben in der Liste
		if m.viewport.offset > 0 {
			m.viewport.offset--
		}
	case tea.MouseWheelDown:
		// Scroll down = nach unten in der Liste
		maxOffset := len(m.sortedIPs) - m.viewport.maxVisible
		if maxOffset < 0 {
			maxOffset = 0
		}
		if m.viewport.offset < maxOffset {
			m.viewport.offset++
		}
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

	// Device List mit responsivem Layout
	m.renderDeviceList(&s)

	// Scroll Indicator
	if len(m.sortedIPs) > m.viewport.maxVisible {
		totalDevices := len(m.sortedIPs)
		visibleCount := len(m.getVisibleDevices())
		showing := m.viewport.offset + 1
		showingEnd := m.viewport.offset + visibleCount
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

// getScrollbarChar gibt das Scrollbar-Zeichen für die gegebene Zeile zurück
func (m watchModel) getScrollbarChar(visibleLineIndex int) string {
	totalDevices := len(m.sortedIPs)
	visibleCount := m.viewport.maxVisible

	// Berechne Scrollbar-Position und Größe
	// thumbSize = Verhältnis sichtbar/total * Anzahl sichtbare Zeilen
	thumbSize := (visibleCount * visibleCount) / totalDevices
	if thumbSize < 1 {
		thumbSize = 1
	}

	// thumbStart = Position des Thumbs basierend auf Offset
	thumbStart := (m.viewport.offset * visibleCount) / totalDevices

	// Prüfe ob aktuelle Zeile im Thumb-Bereich liegt
	if visibleLineIndex >= thumbStart && visibleLineIndex < thumbStart+thumbSize {
		// Im Thumb-Bereich
		return lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Render("█")
	}

	// Im Track-Bereich
	return lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("░")
}

// renderDeviceList rendert die Device-Liste mit responsivem Layout
func (m watchModel) renderDeviceList(s *strings.Builder) {
	totalDevices := len(m.sortedIPs)
	visibleDevices := m.getVisibleDevices()

	// Entscheide Layout basierend auf Terminal-Breite
	if m.width < 100 {
		m.renderNarrowLayout(s, visibleDevices, totalDevices)
	} else if m.width < 140 {
		m.renderMediumLayout(s, visibleDevices, totalDevices)
	} else {
		m.renderWideLayout(s, visibleDevices, totalDevices)
	}
}

// renderNarrowLayout - Kompakte Ansicht für schmale Terminals mit dynamischen Breiten (< 100 cols)
func (m watchModel) renderNarrowLayout(s *strings.Builder, visibleDevices []string, totalDevices int) {
	// Berechne dynamische Spaltenbreiten
	// Fixed: IP(15) + Status(15) + Uptime(10) = 40 + Spaces(3) = 43
	fixedWidth := 43
	if totalDevices > m.viewport.maxVisible {
		fixedWidth += 3 // Scrollbar
	}

	// Verfügbare Breite für Hostname
	hostnameWidth := m.width - fixedWidth
	if hostnameWidth < 15 {
		hostnameWidth = 15 // Minimum
	}

	// Header mit dynamischer Hostname-Breite
	headerLine := fmt.Sprintf("%-15s %-15s %-*s %s",
		"IP Address", "Status", hostnameWidth, "Hostname", "Uptime")
	if totalDevices > m.viewport.maxVisible {
		headerLine += "   "
	}
	s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(headerLine))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", m.width))
	s.WriteString("\n")

	// Rows mit dynamischer Breite
	for i, ipStr := range visibleDevices {
		state := m.deviceStates[ipStr]
		row := m.renderNarrowRowDynamic(state, hostnameWidth)
		if totalDevices > m.viewport.maxVisible {
			row += "  " + m.getScrollbarChar(i)
		}
		s.WriteString(row)
		s.WriteString("\n")
	}
}

// renderMediumLayout - Standard-Ansicht mit dynamischen Breiten (100-140 cols)
func (m watchModel) renderMediumLayout(s *strings.Builder, visibleDevices []string, totalDevices int) {
	// Berechne dynamische Spaltenbreiten
	// Fixed: IP(15) + Status(15) + MAC(18) + Uptime(10) = 58 + Spaces(5) = 63
	fixedWidth := 63
	if totalDevices > m.viewport.maxVisible {
		fixedWidth += 3 // Scrollbar
	}

	// Verfügbare Breite für Hostname und Vendor
	dynamicWidth := m.width - fixedWidth
	if dynamicWidth < 25 {
		dynamicWidth = 25 // Minimum
	}

	// Verteile dynamische Breite: 60% Hostname, 40% Vendor
	hostnameWidth := max(15, (dynamicWidth*60)/100)
	vendorWidth := max(10, dynamicWidth-hostnameWidth)

	// Header mit dynamischen Breiten
	headerLine := fmt.Sprintf("%-15s %-15s %-*s %-18s %-*s %s",
		"IP Address", "Status", hostnameWidth, "Hostname", "MAC", vendorWidth, "Vendor", "Uptime")
	if totalDevices > m.viewport.maxVisible {
		headerLine += "   "
	}
	s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(headerLine))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", m.width))
	s.WriteString("\n")

	// Rows mit dynamischen Breiten
	for i, ipStr := range visibleDevices {
		state := m.deviceStates[ipStr]
		row := m.renderMediumRowDynamic(state, hostnameWidth, vendorWidth)
		if totalDevices > m.viewport.maxVisible {
			row += "  " + m.getScrollbarChar(i)
		}
		s.WriteString(row)
		s.WriteString("\n")
	}
}

// renderWideLayout - Volle Ansicht mit allen Details und dynamischen Spaltenbreiten (>= 140 cols)
func (m watchModel) renderWideLayout(s *strings.Builder, visibleDevices []string, totalDevices int) {
	// Berechne dynamische Spaltenbreiten basierend auf Terminal-Breite
	// Fixe Spalten: IP(15) + Status(15) + MAC(18) + RTT(6) + Uptime(10) = 64
	// Spaces zwischen Spalten: 7 Spaces = 7
	// Scrollbar (optional): 3
	// Total fixed = 64 + 7 = 71 (+ 3 wenn Scrollbar)
	fixedWidth := 71
	if totalDevices > m.viewport.maxVisible {
		fixedWidth += 3 // Scrollbar-Platz
	}

	// Verfügbare Breite für dynamische Spalten (Hostname, Vendor, Type)
	dynamicWidth := m.width - fixedWidth
	if dynamicWidth < 30 {
		dynamicWidth = 30 // Minimum
	}

	// Verteile dynamische Breite: 40% Hostname, 30% Vendor, 30% Type
	hostnameWidth := max(15, (dynamicWidth*40)/100)
	vendorWidth := max(10, (dynamicWidth*30)/100)
	typeWidth := max(10, dynamicWidth-hostnameWidth-vendorWidth)

	// Header mit dynamischen Breiten
	headerLine := fmt.Sprintf("%-15s %-15s %-*s %-18s %-*s %-*s %-6s %s",
		"IP Address", "Status", hostnameWidth, "Hostname", "MAC",
		vendorWidth, "Vendor", typeWidth, "Type", "RTT", "Uptime")
	if totalDevices > m.viewport.maxVisible {
		headerLine += "   "
	}
	s.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render(headerLine))
	s.WriteString("\n")
	s.WriteString(strings.Repeat("─", m.width))
	s.WriteString("\n")

	// Rows mit dynamischen Breiten
	for i, ipStr := range visibleDevices {
		state := m.deviceStates[ipStr]
		row := m.renderWideRowDynamic(state, hostnameWidth, vendorWidth, typeWidth)
		if totalDevices > m.viewport.maxVisible {
			row += "  " + m.getScrollbarChar(i)
		}
		s.WriteString(row)
		s.WriteString("\n")
	}
}

// renderNarrowRowDynamic - Kompakte Zeile mit dynamischer Hostname-Breite
func (m watchModel) renderNarrowRowDynamic(state *DeviceState, hostnameWidth int) string {
	// Status Icon und Color
	statusIcon := "●"
	statusColor := lipgloss.Color("82") // grün
	if state.Status == "offline" {
		statusColor = lipgloss.Color("196") // rot
	}
	statusStr := lipgloss.NewStyle().Foreground(statusColor).Render(fmt.Sprintf("%s %s", statusIcon, state.Status))

	// IP mit Gateway-Marker
	ipStr := state.Host.IP.String()
	if state.Host.IsGateway {
		ipStr += " [G]"
	}

	// Hostname (dynamisch gekürzt)
	hostname := state.Host.Hostname
	if hostname == "" {
		hostname = "-"
	}
	hostnameRunes := []rune(hostname)
	if len(hostnameRunes) > hostnameWidth {
		hostname = string(hostnameRunes[:hostnameWidth-3]) + "..."
	}

	// Uptime
	uptime := time.Since(state.StatusSince)

	return fmt.Sprintf("%-15s %-15s %-*s %s",
		ipStr, statusStr, hostnameWidth, hostname, formatDuration(uptime))
}

// renderNarrowRow - Kompakte Zeile (deprecated, wird nicht mehr verwendet)
func (m watchModel) renderNarrowRow(state *DeviceState) string {
	// Status Icon
	statusIcon := "●"
	statusColor := lipgloss.Color("82") // grün
	if state.Status == "offline" {
		statusColor = lipgloss.Color("196") // rot
	}
	statusStr := lipgloss.NewStyle().Foreground(statusColor).Render(fmt.Sprintf("%s %s", statusIcon, state.Status))

	// IP mit Gateway-Marker
	ipStr := state.Host.IP.String()
	if state.Host.IsGateway {
		ipStr += " [G]"
	}

	// Hostname (gekürzt)
	hostname := state.Host.Hostname
	if hostname == "" {
		hostname = "-"
	}
	if len(hostname) > 20 {
		hostname = hostname[:17] + "..."
	}

	// Uptime
	uptime := time.Since(state.StatusSince)

	return fmt.Sprintf("%-15s %-15s %-20s %s",
		ipStr, statusStr, hostname, formatDuration(uptime))
}

// renderWideRowDynamic - Vollständige Zeile mit dynamischen Spaltenbreiten
func (m watchModel) renderWideRowDynamic(state *DeviceState, hostnameWidth, vendorWidth, typeWidth int) string {
	// Status Icon und Color
	statusIcon := "●"
	statusColor := lipgloss.Color("82") // grün
	if state.Status == "offline" {
		statusColor = lipgloss.Color("196") // rot
	}
	statusStr := lipgloss.NewStyle().Foreground(statusColor).Render(fmt.Sprintf("%s %s", statusIcon, state.Status))

	// IP mit Gateway-Marker
	ipStr := state.Host.IP.String()
	if state.Host.IsGateway {
		ipStr += " [G]"
	}

	// Hostname (dynamisch gekürzt)
	hostname := state.Host.Hostname
	if hostname == "" {
		hostname = "-"
	}
	hostnameRunes := []rune(hostname)
	if len(hostnameRunes) > hostnameWidth {
		hostname = string(hostnameRunes[:hostnameWidth-3]) + "..."
	}

	// MAC
	mac := state.Host.MAC
	if mac == "" {
		mac = "-"
	}

	// Vendor (dynamisch gekürzt)
	vendor := state.Host.Vendor
	if vendor == "" {
		vendor = "-"
	}
	vendorRunes := []rune(vendor)
	if len(vendorRunes) > vendorWidth {
		vendor = string(vendorRunes[:vendorWidth-3]) + "..."
	}

	// Device Type (dynamisch gekürzt)
	deviceType := state.Host.DeviceType
	if deviceType == "" {
		deviceType = "-"
	}
	typeRunes := []rune(deviceType)
	if len(typeRunes) > typeWidth {
		deviceType = string(typeRunes[:typeWidth-3]) + "..."
	}

	// RTT
	rttStr := "-"
	if state.Host.RTT > 0 {
		if state.Host.RTT < time.Millisecond {
			rttStr = fmt.Sprintf("%dµs", state.Host.RTT.Microseconds())
		} else {
			rttStr = fmt.Sprintf("%dms", state.Host.RTT.Milliseconds())
		}
	}

	// Uptime
	uptime := time.Since(state.StatusSince)

	return fmt.Sprintf("%-15s %-15s %-*s %-18s %-*s %-*s %-6s %s",
		ipStr, statusStr, hostnameWidth, hostname, mac,
		vendorWidth, vendor, typeWidth, deviceType, rttStr, formatDuration(uptime))
}

// renderWideRow - Vollständige Zeile mit allen Details (deprecated, wird nicht mehr verwendet)
func (m watchModel) renderWideRow(state *DeviceState) string {
	// Status Icon und Color
	statusIcon := "●"
	statusColor := lipgloss.Color("82") // grün
	if state.Status == "offline" {
		statusColor = lipgloss.Color("196") // rot
	}
	statusStr := lipgloss.NewStyle().Foreground(statusColor).Render(fmt.Sprintf("%s %s", statusIcon, state.Status))

	// IP mit Gateway-Marker
	ipStr := state.Host.IP.String()
	if state.Host.IsGateway {
		ipStr += " [G]"
	}

	// Hostname (gekürzt)
	hostname := state.Host.Hostname
	if hostname == "" {
		hostname = "-"
	}
	if len(hostname) > 20 {
		hostname = hostname[:17] + "..."
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

	// Device Type
	deviceType := state.Host.DeviceType
	if deviceType == "" {
		deviceType = "-"
	}
	if len(deviceType) > 12 {
		deviceType = deviceType[:9] + "..."
	}

	// RTT (Response Time)
	rttStr := "-"
	if state.Host.RTT > 0 {
		if state.Host.RTT < time.Millisecond {
			rttStr = fmt.Sprintf("%dµs", state.Host.RTT.Microseconds())
		} else {
			rttStr = fmt.Sprintf("%dms", state.Host.RTT.Milliseconds())
		}
	}

	// Uptime
	uptime := time.Since(state.StatusSince)

	return fmt.Sprintf("%-15s %-15s %-20s %-18s %-15s %-12s %-6s %s",
		ipStr,
		statusStr,
		hostname,
		mac,
		vendor,
		deviceType,
		rttStr,
		formatDuration(uptime))
}

// renderMediumRowDynamic - Zeile mit dynamischen Hostname- und Vendor-Breiten
func (m watchModel) renderMediumRowDynamic(state *DeviceState, hostnameWidth, vendorWidth int) string {
	// Status Icon und Color
	statusIcon := "●"
	statusColor := lipgloss.Color("82") // grün
	if state.Status == "offline" {
		statusColor = lipgloss.Color("196") // rot
	}
	statusStr := lipgloss.NewStyle().
		Foreground(statusColor).
		Render(fmt.Sprintf("%s %s", statusIcon, state.Status))

	// IP mit Gateway-Marker
	ipStr := state.Host.IP.String()
	if state.Host.IsGateway {
		ipStr += " [G]"
	}

	// Hostname (dynamisch gekürzt)
	hostname := state.Host.Hostname
	if hostname == "" {
		hostname = "-"
	}
	hostnameRunes := []rune(hostname)
	if len(hostnameRunes) > hostnameWidth {
		hostname = string(hostnameRunes[:hostnameWidth-3]) + "..."
	}

	// MAC
	mac := state.Host.MAC
	if mac == "" {
		mac = "-"
	}

	// Vendor (dynamisch gekürzt)
	vendor := state.Host.Vendor
	if vendor == "" {
		vendor = "-"
	}
	vendorRunes := []rune(vendor)
	if len(vendorRunes) > vendorWidth {
		vendor = string(vendorRunes[:vendorWidth-3]) + "..."
	}

	// Uptime
	uptime := time.Since(state.StatusSince)

	return fmt.Sprintf("%-15s %-15s %-*s %-18s %-*s %s",
		ipStr,
		statusStr,
		hostnameWidth, hostname,
		mac,
		vendorWidth, vendor,
		formatDuration(uptime))
}

// renderMediumRow - Zeile mit MAC und Vendor (deprecated, wird nicht mehr verwendet)
func (m watchModel) renderMediumRow(state *DeviceState) string {
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
	// Kürze zu lange Hostnames (max 20 Zeichen für %-20s)
	if len(hostname) > 20 {
		hostname = hostname[:17] + "..."
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

// performBackgroundDNSLookupsCmd startet DNS-Lookups und returned Updates als Message
func performBackgroundDNSLookupsCmd(deviceStates map[string]*DeviceState) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		updates := make(map[string]dnsLookupResult)
		var mu sync.Mutex
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 10) // Limit concurrent lookups

		// Sammle IPs die DNS-Lookups brauchen
		for ipStr, state := range deviceStates {
			// Nur für online hosts ohne Hostname UND ohne vorherigen Lookup-Versuch
			if state.Status != "online" || state.Host.Hostname != "" || state.Host.HostnameSource != "" {
				continue
			}

			wg.Add(1)
			go func(ip string, ipAddr net.IP) {
				defer wg.Done()

				// Check if context was cancelled
				select {
				case <-ctx.Done():
					return
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				}

				// Comprehensive hostname resolution (DNS, mDNS, NetBIOS, LLMNR)
				result := discovery.ResolveBackground(ipAddr, 1*time.Second)
				mu.Lock()
				if result.Hostname != "" {
					updates[ip] = dnsLookupResult{
						hostname: result.Hostname,
						source:   result.Source,
					}
				} else {
					// Auch fehlgeschlagene Versuche markieren
					updates[ip] = dnsLookupResult{
						hostname: "",
						source:   "none",
					}
				}
				mu.Unlock()
			}(ipStr, state.Host.IP)
		}

		wg.Wait()

		// Returne Updates als Message (thread-safe)
		return dnsLookupCompleteMsg{updates: updates}
	}
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
		tea.WithAltScreen(), // Alt Screen Buffer verwenden
	)

	// Program starten (blockiert bis Quit)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running watch UI: %v", err)
	}

	return nil
}
