package watch

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// HostDetailsModal zeigt Details zu einem Host und ermöglicht Port-Scanning
type HostDetailsModal struct {
	app         *tview.Application
	pages       *tview.Pages
	flex        *tview.Flex
	detailsView *tview.TextView
	portsInput  *tview.InputField
	portsTable  *tview.Table
	scanButton  *tview.Button
	state       *DeviceState
	ipStr       string
	onClose     func()

	// Port-Scan State
	scanning    bool
	scanResults []PortScanResult
	scanMu      sync.Mutex
}

// PortScanResult enthält das Ergebnis eines Port-Scans
type PortScanResult struct {
	Port    string
	Status  string // "open", "closed", "filtered"
	Service string
	Banner  string
	RTT     time.Duration
	Index   int // Original-Position in der Eingabe
}

// Standard-Ports für Quick-Scan
var defaultPorts = "icmp,22,80,443,445,3389,8080"

// NewHostDetailsModal erstellt ein neues Details-Modal
func NewHostDetailsModal(app *tview.Application, pages *tview.Pages, ipStr string, state *DeviceState, onClose func()) *HostDetailsModal {
	m := &HostDetailsModal{
		app:     app,
		pages:   pages,
		ipStr:   ipStr,
		state:   state,
		onClose: onClose,
	}

	m.setupUI()
	return m
}

// setupUI erstellt das Modal-Layout
func (m *HostDetailsModal) setupUI() {
	// Host-Details TextView (oberer Bereich)
	m.detailsView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	m.detailsView.SetBorder(true).
		SetBorderColor(tcell.ColorAqua).
		SetTitle(" Host Details ").
		SetTitleColor(tcell.ColorAqua).
		SetTitleAlign(tview.AlignCenter)

	// Port-Input Feld
	m.portsInput = tview.NewInputField().
		SetLabel("Ports: ").
		SetText(defaultPorts).
		SetFieldWidth(40).
		SetFieldBackgroundColor(tcell.ColorDarkBlue)

	// Scan Button
	m.scanButton = tview.NewButton("Scan").
		SetSelectedFunc(func() {
			m.startPortScan()
		})
	m.scanButton.SetBackgroundColor(tcell.ColorDarkGreen)

	// Port-Input Zeile (Input + Button)
	inputRow := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(m.portsInput, 0, 1, true).
		AddItem(m.scanButton, 8, 0, false)

	// Port-Scan Ergebnis-Tabelle (scrollbar)
	m.portsTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false). // Zeilen selektierbar = scrollbar
		SetFixed(1, 0)
	m.setupPortsTableHeader()

	// Port-Scan Bereich (Input + Tabelle)
	portsFlex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(inputRow, 1, 0, true).
		AddItem(m.portsTable, 0, 1, false)
	portsFlex.SetBorder(true).
		SetBorderColor(tcell.ColorAqua).
		SetTitle(" Port Scan ").
		SetTitleColor(tcell.ColorAqua).
		SetTitleAlign(tview.AlignCenter)

	// Footer mit Hinweisen
	footer := tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetText("[yellow]Tab[white]=Switch  [yellow]Enter[white]=Scan  [yellow]ESC[white]=Close")

	// Haupt-Layout (proportional)
	m.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(m.detailsView, 0, 2, false). // ~33% für Details
		AddItem(portsFlex, 0, 3, true).      // ~50% für Port-Scan (mehr Platz für Ergebnisse)
		AddItem(footer, 1, 0, false)         // 1 Zeile für Footer
	m.flex.SetBorder(true).
		SetBorderColor(tcell.ColorYellow).
		SetTitle(fmt.Sprintf(" %s ", m.ipStr)).
		SetTitleColor(tcell.ColorYellow).
		SetTitleAlign(tview.AlignCenter)

	// Keyboard-Handler
	m.flex.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			m.Close()
			return nil
		case tcell.KeyEnter:
			// Enter startet Scan wenn nicht im Input-Feld
			if m.app.GetFocus() != m.portsInput {
				m.startPortScan()
				return nil
			}
			// Im Input-Feld: auch Scan starten
			m.startPortScan()
			return nil
		case tcell.KeyTab:
			// Tab wechselt zwischen Input und Button
			if m.app.GetFocus() == m.portsInput {
				m.app.SetFocus(m.scanButton)
			} else {
				m.app.SetFocus(m.portsInput)
			}
			return nil
		}
		return event
	})

	// Details initial füllen
	m.updateDetails()
}

// setupPortsTableHeader erstellt die Header-Zeile der Port-Tabelle
func (m *HostDetailsModal) setupPortsTableHeader() {
	headers := []string{"Port", "Status", "Service", "Banner", "RTT"}
	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(tcell.ColorAqua).
			SetAlign(tview.AlignLeft).
			SetSelectable(false).
			SetAttributes(tcell.AttrBold)
		m.portsTable.SetCell(0, col, cell)
	}
}

// checkDNSConsistency prüft ob Forward (aus Cache) und Reverse DNS konsistent sind
// Tabelle zeigt Forward-DNS (was das System "denkt")
// Hier machen wir Reverse-DNS und vergleichen
// Gibt zurück: (reverse-resolved hostnames, isConsistent, error)
func (m *HostDetailsModal) checkDNSConsistency() ([]string, bool, error) {
	cachedHostname := m.state.Host.Hostname
	if cachedHostname == "" {
		return nil, true, nil // Kein Hostname = nichts zu prüfen
	}

	// Reverse DNS: IP → Hostnames
	names, err := net.LookupAddr(m.ipStr)
	if err != nil {
		return nil, false, err
	}

	// Hostnames normalisieren (trailing dot entfernen)
	for i, name := range names {
		names[i] = strings.TrimSuffix(name, ".")
	}
	cachedNormalized := strings.TrimSuffix(cachedHostname, ".")

	// Prüfen ob der cached Hostname in den Reverse-Ergebnissen ist
	for _, name := range names {
		if strings.EqualFold(name, cachedNormalized) {
			return names, true, nil
		}
	}

	return names, false, nil
}

// updateDetails aktualisiert die Host-Details Anzeige
func (m *HostDetailsModal) updateDetails() {
	var sb strings.Builder

	// IP
	sb.WriteString(fmt.Sprintf("[yellow]IP:[white]        %s\n", m.ipStr))

	// Hostname
	hostname := "-"
	hostnameSource := ""
	if m.state.Host.Hostname != "" {
		hostname = m.state.Host.Hostname
		if m.state.Host.HostnameSource != "" {
			hostnameSource = fmt.Sprintf(" [gray](%s)[white]", m.state.Host.HostnameSource)
		}
	}
	sb.WriteString(fmt.Sprintf("[yellow]Hostname:[white]  %s%s\n", hostname, hostnameSource))

	// DNS Konsistenz-Check NUR wenn Hostname aus Forward-Cache kam
	// Bei Reverse-DNS (Source="dns") ist kein Check nötig - das IST bereits der Reverse
	if m.state.Host.Hostname != "" && m.state.Host.HostnameSource == "dns-cache" {
		reverseNames, consistent, err := m.checkDNSConsistency()
		if err != nil {
			sb.WriteString(fmt.Sprintf("[yellow]DNS Check:[white] [gray]Reverse failed[white] (%s)\n", err.Error()))
		} else if !consistent {
			// Inkonsistenz gefunden! Forward (Cache) stimmt nicht mit Reverse überein
			reverseStr := "(keine)"
			if len(reverseNames) > 0 {
				reverseStr = strings.Join(reverseNames, ", ")
			}
			sb.WriteString(fmt.Sprintf("[yellow]DNS Check:[white] [red]⚠ MISMATCH[white] Reverse: %s\n", reverseStr))
		} else {
			sb.WriteString("[yellow]DNS Check:[white] [green]✓ OK[white] (Forward = Reverse)\n")
		}
	}

	// MAC
	mac := "-"
	if m.state.Host.MAC != "" {
		mac = m.state.Host.MAC
		if IsLocallyAdministered(mac) {
			mac += " [yellow](randomized)[white]"
		}
	}
	sb.WriteString(fmt.Sprintf("[yellow]MAC:[white]       %s\n", mac))

	// Vendor
	vendor := "-"
	if m.state.Host.Vendor != "" {
		vendor = m.state.Host.Vendor
	}
	sb.WriteString(fmt.Sprintf("[yellow]Vendor:[white]    %s\n", vendor))

	// Device Type
	deviceType := "-"
	if m.state.Host.DeviceType != "" && m.state.Host.DeviceType != "Unknown" {
		deviceType = m.state.Host.DeviceType
	}
	sb.WriteString(fmt.Sprintf("[yellow]Device:[white]    %s\n", deviceType))

	// Status
	statusColor := "[green]"
	if m.state.Status == "offline" {
		statusColor = "[red]"
	}
	duration := time.Since(m.state.StatusSince)
	sb.WriteString(fmt.Sprintf("[yellow]Status:[white]    %s%s[white] (seit %s)\n", statusColor, m.state.Status, FormatDuration(duration)))

	// RTT
	rtt := "-"
	if m.state.Host.RTT > 0 {
		rtt = fmt.Sprintf("%.2fms", float64(m.state.Host.RTT.Microseconds())/1000.0)
	}
	sb.WriteString(fmt.Sprintf("[yellow]RTT:[white]       %s\n", rtt))

	// Flaps
	sb.WriteString(fmt.Sprintf("[yellow]Flaps:[white]     %d\n", m.state.FlapCount))

	// First Seen
	sb.WriteString(fmt.Sprintf("[yellow]First:[white]     %s\n", m.state.FirstSeen.Format("15:04:05")))

	// Gateway
	if m.state.Host.IsGateway {
		sb.WriteString("[yellow]Gateway:[white]   [green]Yes[white]\n")
	}

	m.detailsView.SetText(sb.String())
}

// startPortScan startet einen Port-Scan
func (m *HostDetailsModal) startPortScan() {
	if m.scanning {
		return
	}

	m.scanning = true
	m.scanButton.SetLabel("...")

	// Ports parsen
	portsText := m.portsInput.GetText()
	ports := parsePortList(portsText)

	// Tabelle leeren
	m.portsTable.Clear()
	m.setupPortsTableHeader()

	// Scan in Goroutine
	go func() {
		results := m.scanPorts(ports)

		m.app.QueueUpdateDraw(func() {
			m.scanMu.Lock()
			m.scanResults = results
			m.scanMu.Unlock()

			m.updatePortsTable()
			m.scanning = false
			m.scanButton.SetLabel("Scan")
		})
	}()
}

// parsePortList parst eine komma-separierte Port-Liste mit Range-Support
// Unterstützt: icmp, einzelne Ports (22), Ranges (80-90)
// Beispiel: "icmp,22,80-90,443" → ["icmp", "22", "80", "81", ..., "90", "443"]
func parsePortList(text string) []string {
	parts := strings.Split(text, ",")
	var ports []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Check für Range (z.B. "80-90")
		if strings.Contains(p, "-") && strings.ToLower(p) != "icmp" {
			rangeParts := strings.SplitN(p, "-", 2)
			if len(rangeParts) == 2 {
				startStr := strings.TrimSpace(rangeParts[0])
				endStr := strings.TrimSpace(rangeParts[1])

				start, errStart := strconv.Atoi(startStr)
				end, errEnd := strconv.Atoi(endStr)

				if errStart == nil && errEnd == nil && start <= end && start > 0 && end <= 65535 {
					// Maximale Range-Größe begrenzen (verhindert DoS bei z.B. "1-65535")
					if end-start > 100 {
						end = start + 100
					}
					for port := start; port <= end; port++ {
						ports = append(ports, strconv.Itoa(port))
					}
					continue
				}
			}
		}

		// Einzelner Port oder "icmp"
		ports = append(ports, p)
	}
	return ports
}

// scanPorts führt den eigentlichen Scan durch
func (m *HostDetailsModal) scanPorts(ports []string) []PortScanResult {
	var results []PortScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	for idx, port := range ports {
		wg.Add(1)
		go func(p string, index int) {
			defer wg.Done()

			result := m.scanSinglePort(p)
			result.Index = index // Original-Position speichern

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			// UI sofort updaten
			m.app.QueueUpdateDraw(func() {
				m.scanMu.Lock()
				m.scanResults = append(m.scanResults, result)
				m.scanMu.Unlock()
				m.updatePortsTable()
			})
		}(port, idx)
	}

	wg.Wait()
	return results
}

// scanSinglePort scannt einen einzelnen Port
func (m *HostDetailsModal) scanSinglePort(port string) PortScanResult {
	result := PortScanResult{
		Port:    port,
		Status:  "closed",
		Service: getServiceName(port),
		Banner:  "-",
	}

	// ICMP Ping
	if strings.ToLower(port) == "icmp" {
		rtt, ok := m.pingICMP()
		if ok {
			result.Status = "open"
			result.RTT = rtt
			result.Banner = fmt.Sprintf("%.2fms", float64(rtt.Microseconds())/1000.0)
		}
		return result
	}

	// TCP Port Scan
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(m.ipStr, port), 2*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			result.Status = "filtered"
		}
		return result
	}
	defer conn.Close()

	result.Status = "open"
	result.RTT = time.Since(start)

	// Einfaches Banner Grabbing für bekannte Ports
	result.Banner = m.grabBanner(conn, port)

	return result
}

// pingICMP führt einen ICMP Ping durch
func (m *HostDetailsModal) pingICMP() (time.Duration, bool) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "2000", m.ipStr)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-W", "2000", m.ipStr)
	default:
		cmd = exec.Command("ping", "-c", "1", "-W", "2", m.ipStr)
	}

	start := time.Now()
	err := cmd.Run()
	rtt := time.Since(start)

	return rtt, err == nil
}

// grabBanner versucht ein Banner vom Service zu lesen
func (m *HostDetailsModal) grabBanner(conn net.Conn, port string) string {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "-"
	}

	banner := strings.TrimSpace(string(buf[:n]))
	// Nur erste Zeile, max 30 Zeichen
	if idx := strings.Index(banner, "\n"); idx > 0 {
		banner = banner[:idx]
	}
	if len(banner) > 30 {
		banner = banner[:30] + "..."
	}
	return banner
}

// getServiceName gibt den bekannten Service-Namen für einen Port zurück
func getServiceName(port string) string {
	services := map[string]string{
		"icmp": "ping",
		"21":   "ftp",
		"22":   "ssh",
		"23":   "telnet",
		"25":   "smtp",
		"53":   "dns",
		"80":   "http",
		"110":  "pop3",
		"143":  "imap",
		"443":  "https",
		"445":  "smb",
		"993":  "imaps",
		"995":  "pop3s",
		"3306": "mysql",
		"3389": "rdp",
		"5432": "postgres",
		"5900": "vnc",
		"8080": "http-alt",
		"8443": "https-alt",
	}

	if name, ok := services[strings.ToLower(port)]; ok {
		return name
	}
	return "-"
}

// updatePortsTable aktualisiert die Port-Ergebnis-Tabelle
func (m *HostDetailsModal) updatePortsTable() {
	m.scanMu.Lock()
	defer m.scanMu.Unlock()

	if m.scanning {
		// Während Scan: nach Original-Index sortieren (Eingabe-Reihenfolge)
		sort.Slice(m.scanResults, func(i, j int) bool {
			return m.scanResults[i].Index < m.scanResults[j].Index
		})
	} else {
		// Nach Scan: Status (open > filtered > closed), dann Original-Index
		sort.Slice(m.scanResults, func(i, j int) bool {
			statusPriority := func(s string) int {
				switch s {
				case "open":
					return 0
				case "filtered":
					return 1
				default:
					return 2
				}
			}
			pi, pj := statusPriority(m.scanResults[i].Status), statusPriority(m.scanResults[j].Status)
			if pi != pj {
				return pi < pj
			}
			return m.scanResults[i].Index < m.scanResults[j].Index
		})
	}

	// Tabelle neu aufbauen
	m.portsTable.Clear()
	m.setupPortsTableHeader()

	for i, result := range m.scanResults {
		row := i + 1

		// Status-Farbe
		statusColor := tcell.ColorRed
		statusSymbol := "✗"
		if result.Status == "open" {
			statusColor = tcell.ColorGreen
			statusSymbol = "✓"
		} else if result.Status == "filtered" {
			statusColor = tcell.ColorYellow
			statusSymbol = "?"
		}

		// RTT formatieren
		rttStr := "-"
		if result.RTT > 0 {
			rttStr = fmt.Sprintf("%.1fms", float64(result.RTT.Microseconds())/1000.0)
		}

		// Zellen setzen
		m.portsTable.SetCell(row, 0, tview.NewTableCell(result.Port).SetTextColor(tcell.ColorWhite))
		m.portsTable.SetCell(row, 1, tview.NewTableCell(statusSymbol).SetTextColor(statusColor))
		m.portsTable.SetCell(row, 2, tview.NewTableCell(result.Service).SetTextColor(tcell.ColorWhite))
		m.portsTable.SetCell(row, 3, tview.NewTableCell(result.Banner).SetTextColor(tcell.ColorGray))
		m.portsTable.SetCell(row, 4, tview.NewTableCell(rttStr).SetTextColor(tcell.ColorWhite))
	}
}

// Show zeigt das Modal an
func (m *HostDetailsModal) Show() {
	// Modal als Overlay hinzufügen (zentriert, ~80% der Fenstergröße)
	// Proportionen: 1 (Rand) : 8 (Inhalt) : 1 (Rand) = 10% : 80% : 10%
	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false). // 10% links
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).    // 10% oben
			AddItem(m.flex, 0, 8, true).  // 80% Inhalt (flexibel!)
			AddItem(nil, 0, 1, false),    // 10% unten
			0, 8, true).                  // 80% Breite (flexibel!)
		AddItem(nil, 0, 1, false) // 10% rechts

	m.pages.AddPage("hostdetails", modal, true, true)
	m.app.SetFocus(m.portsInput)
}

// Close schließt das Modal
func (m *HostDetailsModal) Close() {
	m.pages.RemovePage("hostdetails")
	if m.onClose != nil {
		m.onClose()
	}
}
