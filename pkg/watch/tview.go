package watch

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"netspy/pkg/scanner"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// TviewApp ist die tview-basierte Watch-Anwendung
type TviewApp struct {
	app        *tview.Application
	flex       *tview.Flex
	headerView *tview.TextView
	infoView   *tview.TextView
	table      *tview.Table
	footerView *tview.TextView
	helpModal  *tview.Modal
	pages      *tview.Pages

	// State
	deviceStates map[string]*DeviceState
	statesMu     sync.RWMutex
	sortState    *SortState
	network      string
	netCIDR      *net.IPNet
	interval     time.Duration
	mode         string
	scanCount    int
	scanDuration time.Duration
	nextScanIn   time.Duration
	isLocal      bool

	// Thread tracking
	activeThreads int32
	threadConfig  ThreadConfig

	// Channels
	ctx    context.Context
	cancel context.CancelFunc
}

// Farb-Konstanten
var (
	colorOnline     = tcell.ColorGreen
	colorOffline    = tcell.ColorRed
	colorNew        = tcell.ColorLime
	colorFlapping   = tcell.ColorYellow
	colorLocalMAC   = tcell.ColorYellow
	colorHeader     = tcell.ColorAqua
	colorBorder     = tcell.ColorAqua
	colorZebraLight = tcell.ColorWhite
	colorZebraDark  = tcell.Color240
)

// NewTviewApp erstellt eine neue tview Watch-Anwendung
func NewTviewApp(network string, netCIDR *net.IPNet, mode string, interval time.Duration, maxThreads int) *TviewApp {
	ctx, cancel := context.WithCancel(context.Background())

	// Calculate thread config
	threadConfig := CalculateThreads(netCIDR, maxThreads)

	// Check if local subnet
	isLocal, _ := IsLocalSubnet(netCIDR)

	w := &TviewApp{
		app:          tview.NewApplication(),
		deviceStates: make(map[string]*DeviceState),
		sortState:    &SortState{Column: SortByIP, Ascending: true},
		network:      network,
		netCIDR:      netCIDR,
		interval:     interval,
		mode:         mode,
		isLocal:      isLocal,
		threadConfig: threadConfig,
		ctx:          ctx,
		cancel:       cancel,
	}

	w.setupUI()
	w.setupKeyBindings()

	return w
}

// setupUI erstellt das UI-Layout
func (w *TviewApp) setupUI() {
	// Statistics Box (links oben) - wie im Netflow-Tool
	w.headerView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	w.headerView.SetBorder(true).
		SetBorderColor(colorBorder).
		SetTitle(" Statistics ").
		SetTitleColor(colorHeader).
		SetTitleAlign(tview.AlignCenter)
	w.updateHeader()

	// Scan & Sort Box (rechts oben)
	w.infoView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)
	w.infoView.SetBorder(true).
		SetBorderColor(colorBorder).
		SetTitle(" Scan & Sort ").
		SetTitleColor(colorHeader).
		SetTitleAlign(tview.AlignCenter)
	w.updateInfo()

	// Devices-Tabelle (Hauptbereich)
	w.table = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false). // Zeilen selektierbar, Spalten nicht
		SetFixed(1, 0).             // Header-Zeile fixiert
		SetSeparator(' ')
	w.table.SetBorder(true).
		SetBorderColor(colorBorder).
		SetTitle(" Devices ").
		SetTitleColor(colorHeader).
		SetTitleAlign(tview.AlignCenter)
	w.table.SetBorderPadding(0, 0, 1, 1)
	w.setupTableHeader()

	// Footer/Controls
	w.footerView = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)
	w.footerView.SetBorder(true).
		SetBorderColor(colorBorder).
		SetTitle(" Controls ").
		SetTitleColor(colorHeader).
		SetTitleAlign(tview.AlignCenter)
	w.updateFooter()

	// Help Modal
	w.helpModal = tview.NewModal().
		SetText(w.getHelpText()).
		AddButtons([]string{"Schließen"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			w.pages.SwitchToPage("main")
		})

	// Oberer Bereich: Statistics (breit) + Scan & Sort (schmaler) nebeneinander
	topRow := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(w.headerView, 0, 2, false).  // Statistics breit
		AddItem(w.infoView, 0, 1, false)     // Scan & Sort schmaler

	// Haupt-Layout
	w.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(topRow, 5, 0, false).           // Header+Info oben (5 Zeilen: 3 Text + 2 Border)
		AddItem(w.table, 0, 1, true).           // Tabelle bekommt restlichen Platz
		AddItem(w.footerView, 3, 0, false)      // Footer unten (3 Zeilen: 1 Text + 2 Border)

	// Pages für Modal-Handling
	w.pages = tview.NewPages().
		AddPage("main", w.flex, true, true).
		AddPage("help", w.helpModal, true, false)

	w.app.SetRoot(w.pages, true)
}

// setupTableHeader erstellt die Tabellen-Kopfzeile
func (w *TviewApp) setupTableHeader() {
	headers := []string{"IP Address", "Hostname", "MAC Address", "Vendor", "Device", "RTT", "Uptime", "Flaps"}

	for col, header := range headers {
		cell := tview.NewTableCell(header).
			SetTextColor(colorHeader).
			SetAlign(tview.AlignLeft).
			SetSelectable(false).
			SetAttributes(tcell.AttrBold)

		// Spaltenbreiten setzen
		switch col {
		case 0: // IP
			cell.SetExpansion(1)
		case 1: // Hostname
			cell.SetExpansion(2)
		case 2: // MAC
			cell.SetExpansion(1)
		case 3: // Vendor
			cell.SetExpansion(1)
		case 4: // Device
			cell.SetExpansion(1)
		case 5: // RTT
			cell.SetExpansion(0)
		case 6: // Uptime
			cell.SetExpansion(0)
		case 7: // Flaps
			cell.SetExpansion(0)
		}

		w.table.SetCell(0, col, cell)
	}
}

// setupKeyBindings richtet die Tastatur-Shortcuts ein
func (w *TviewApp) setupKeyBindings() {
	w.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Help Modal ist offen - nur ESC/Enter durchlassen
		if w.pages.HasPage("help") {
			name, _ := w.pages.GetFrontPage()
			if name == "help" {
				if event.Key() == tcell.KeyEscape || event.Key() == tcell.KeyEnter {
					w.pages.SwitchToPage("main")
					return nil
				}
				return event
			}
		}

		switch event.Key() {
		case tcell.KeyEscape:
			w.Stop()
			return nil
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q', 'Q':
				w.Stop()
				return nil
			case '?':
				w.pages.SwitchToPage("help")
				return nil
			case 'i', 'I':
				w.sortState.Toggle(SortByIP)
				w.updateTable()
				return nil
			case 'h', 'H':
				w.sortState.Toggle(SortByHostname)
				w.updateTable()
				return nil
			case 'm', 'M':
				w.sortState.Toggle(SortByMAC)
				w.updateTable()
				return nil
			case 'v', 'V':
				w.sortState.Toggle(SortByVendor)
				w.updateTable()
				return nil
			case 'd', 'D':
				w.sortState.Toggle(SortByDeviceType)
				w.updateTable()
				return nil
			case 'r', 'R':
				w.sortState.Toggle(SortByRTT)
				w.updateTable()
				return nil
			case 'u', 'U':
				w.sortState.Toggle(SortByUptime)
				w.updateTable()
				return nil
			case 'f', 'F':
				w.sortState.Toggle(SortByFlaps)
				w.updateTable()
				return nil
			}
		}
		return event
	})
}

// updateHeader aktualisiert die Statistics-Box
func (w *TviewApp) updateHeader() {
	w.statesMu.RLock()
	onlineCount := 0
	offlineCount := 0
	totalFlaps := 0
	for _, state := range w.deviceStates {
		if state.Status == "online" {
			onlineCount++
		} else {
			offlineCount++
		}
		totalFlaps += state.FlapCount
	}
	totalDevices := len(w.deviceStates)
	w.statesMu.RUnlock()

	networkDisplay := w.network
	if !w.isLocal {
		networkDisplay += " [gray](remote)[aqua]"
	}

	// Mehrzeilige Statistics wie im Netflow-Tool
	text := fmt.Sprintf("[yellow]Network:[white] %s  [yellow]Mode:[white] %s  [yellow]Interval:[white] %v\n"+
		"[yellow]Devices:[white] %d ([green]↑%d[white] [red]↓%d[white])  [yellow]Flaps:[white] %d  [yellow]Scan:[white] %s\n"+
		"[yellow]Threads:[white] %d  [yellow]Scan #[white]%d  [yellow]Next:[white] %s",
		networkDisplay, w.mode, w.interval,
		totalDevices, onlineCount, offlineCount, totalFlaps, FormatDuration(w.scanDuration),
		w.activeThreads, w.scanCount, FormatDuration(w.nextScanIn))
	w.headerView.SetText(text)
}

// updateInfo aktualisiert die Scan & Sort Box
func (w *TviewApp) updateInfo() {
	sortCol, sortAsc := w.sortState.Get()

	// Sort-Richtung
	sortDir := "DESC"
	if sortAsc {
		sortDir = "ASC"
	}

	// Aktueller Sort-Spaltenname
	sortName := "IP"
	switch sortCol {
	case SortByHostname:
		sortName = "Hostname"
	case SortByMAC:
		sortName = "MAC"
	case SortByVendor:
		sortName = "Vendor"
	case SortByDeviceType:
		sortName = "Device"
	case SortByRTT:
		sortName = "RTT"
	case SortByUptime:
		sortName = "Uptime"
	case SortByFlaps:
		sortName = "Flaps"
	}

	// Sortierung und Shortcuts wie im Netflow-Tool
	text := fmt.Sprintf("[yellow]Sort:[white] %s %s\n"+
		"[gray]i[white]=IP [gray]h[white]=host [gray]m[white]=MAC [gray]v[white]=vendor\n"+
		"[gray]d[white]=device [gray]r[white]=RTT [gray]u[white]=up [gray]f[white]=flaps",
		sortName, sortDir)
	w.infoView.SetText(text)
}

// updateFooter aktualisiert die Footer-Zeile
func (w *TviewApp) updateFooter() {
	text := "[yellow]?[white]=Help  [yellow]q[white]/[yellow]ESC[white]=Quit  [yellow]↑↓[white]=Scroll  [yellow]PgUp/PgDn[white]=Page"
	w.footerView.SetText(text)
}

// updateTable aktualisiert die Host-Tabelle
func (w *TviewApp) updateTable() {
	w.statesMu.RLock()
	defer w.statesMu.RUnlock()

	// Sortierte IP-Liste erstellen
	ips := make([]string, 0, len(w.deviceStates))
	for ip := range w.deviceStates {
		ips = append(ips, ip)
	}

	referenceTime := time.Now()
	SortIPs(ips, w.deviceStates, w.sortState, referenceTime)

	// Tabelle komplett leeren und Header neu erstellen
	w.table.Clear()
	w.setupTableHeader()

	// Zeilen hinzufügen
	for i, ipStr := range ips {
		row := i + 1 // +1 wegen Header
		state := w.deviceStates[ipStr]

		// Bestimme Zeilenfarbe
		rowColor := colorZebraLight
		if i%2 == 1 {
			rowColor = colorZebraDark
		}

		// Status-spezifische Farben
		ipColor := rowColor
		if state.Status == "offline" {
			ipColor = colorOffline
		} else if state.FirstSeenScan > 1 && (w.scanCount-state.FirstSeenScan) < 2 {
			ipColor = colorNew
		}

		// IP mit Markern
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}

		// Hostname
		hostname := GetHostname(state.Host)
		if len(hostname) > 20 {
			hostname = hostname[:19] + "…"
		}

		// MAC
		mac := state.Host.MAC
		if mac == "" {
			mac = "-"
		}
		macColor := rowColor
		if IsLocallyAdministered(mac) {
			macColor = colorLocalMAC
		}

		// Vendor
		vendor := GetVendor(state.Host)
		if len(vendor) > 15 {
			vendor = vendor[:14] + "…"
		}

		// Device Type
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
		}
		if len(deviceType) > 12 {
			deviceType = deviceType[:11] + "…"
		}

		// RTT
		rttText := "-"
		if state.Host.RTT > 0 {
			if state.Host.RTT < time.Millisecond {
				rttText = fmt.Sprintf("%.0fµs", float64(state.Host.RTT.Microseconds()))
			} else {
				rttText = fmt.Sprintf("%.1fms", float64(state.Host.RTT.Microseconds())/1000.0)
			}
		}

		// Uptime/Downtime
		var statusDuration time.Duration
		if state.Status == "online" {
			totalTime := referenceTime.Sub(state.FirstSeen)
			statusDuration = totalTime - state.TotalOfflineTime
		} else {
			statusDuration = referenceTime.Sub(state.StatusSince)
		}
		uptimeText := FormatDuration(statusDuration)

		// Flaps
		flapText := fmt.Sprintf("%d", state.FlapCount)
		flapColor := rowColor
		if state.FlapCount > 0 {
			flapColor = colorFlapping
		}

		// Zellen setzen
		w.table.SetCell(row, 0, tview.NewTableCell(displayIP).SetTextColor(ipColor))
		w.table.SetCell(row, 1, tview.NewTableCell(hostname).SetTextColor(rowColor))
		w.table.SetCell(row, 2, tview.NewTableCell(mac).SetTextColor(macColor))
		w.table.SetCell(row, 3, tview.NewTableCell(vendor).SetTextColor(rowColor))
		w.table.SetCell(row, 4, tview.NewTableCell(deviceType).SetTextColor(rowColor))
		w.table.SetCell(row, 5, tview.NewTableCell(rttText).SetTextColor(rowColor).SetAlign(tview.AlignRight))
		w.table.SetCell(row, 6, tview.NewTableCell(uptimeText).SetTextColor(rowColor).SetAlign(tview.AlignRight))
		w.table.SetCell(row, 7, tview.NewTableCell(flapText).SetTextColor(flapColor).SetAlign(tview.AlignRight))
	}

	// Sort-Indikator im Header aktualisieren
	w.updateTableHeaderWithSort()
}

// updateTableHeaderWithSort aktualisiert Header mit Sort-Indikator
func (w *TviewApp) updateTableHeaderWithSort() {
	headers := []struct {
		name string
		col  SortColumn
	}{
		{"IP Address", SortByIP},
		{"Hostname", SortByHostname},
		{"MAC Address", SortByMAC},
		{"Vendor", SortByVendor},
		{"Device", SortByDeviceType},
		{"RTT", SortByRTT},
		{"Uptime", SortByUptime},
		{"Flaps", SortByFlaps},
	}

	sortCol, sortAsc := w.sortState.Get()

	for i, h := range headers {
		text := h.name
		if sortCol == h.col {
			if sortAsc {
				text += " ↑"
			} else {
				text += " ↓"
			}
		}
		w.table.GetCell(0, i).SetText(text)
	}
}

// getHelpText gibt den Help-Text zurück
func (w *TviewApp) getHelpText() string {
	return `NetSpy Hilfe

SORTIERUNG:
  i = Sort by IP
  h = Sort by Hostname
  m = Sort by MAC
  v = Sort by Vendor
  d = Sort by Device Type
  r = Sort by RTT
  u = Sort by Uptime
  f = Sort by Flaps

NAVIGATION:
  ↑/↓ = Scroll
  PgUp/PgDn = Page
  q/ESC = Quit
  ? = This help

SYMBOLE:
  [G] = Gateway
  [!] = Offline
  Grün = Neu entdeckt
  Rot = Offline
  Gelb = Lokal-MAC / Flapping`
}

// Run startet die Anwendung
func (w *TviewApp) Run() error {
	// Alternate Screen Buffer aktivieren (verhindert Überlappung mit Terminal-History)
	w.app.EnableMouse(false) // Mouse deaktivieren (optional, aber cleaner)

	// Scan-Loop in Goroutine starten
	go w.scanLoop()

	// Countdown-Timer in Goroutine
	go w.countdownLoop()

	// UI starten (blockiert)
	return w.app.Run()
}

// Stop beendet die Anwendung
func (w *TviewApp) Stop() {
	w.cancel()
	w.app.Stop()
}

// scanLoop führt periodische Scans durch
func (w *TviewApp) scanLoop() {
	// Erster Scan sofort
	w.performScan()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.performScan()
		}
	}
}

// performScan führt einen Scan durch und aktualisiert die UI
func (w *TviewApp) performScan() {
	scanStart := time.Now()

	// Scan durchführen
	hosts := PerformScanQuiet(w.ctx, w.network, w.netCIDR, w.mode, &w.activeThreads, w.threadConfig)

	// Check if cancelled
	if w.ctx.Err() != nil {
		return
	}

	w.scanCount++
	w.scanDuration = time.Since(scanStart)
	w.nextScanIn = w.interval

	// Device States aktualisieren
	w.updateDeviceStates(hosts, scanStart)

	// DNS-Cache vorab laden
	w.statesMu.Lock()
	PopulateFromDNSCache(w.deviceStates)
	w.statesMu.Unlock()

	// UI aktualisieren (thread-safe)
	w.app.QueueUpdateDraw(func() {
		w.updateHeader()
		w.updateInfo()
		w.updateTable()
		w.updateFooter()
	})

	// Background DNS Lookups starten
	go func() {
		w.statesMu.Lock()
		PerformInitialDNSLookups(w.ctx, w.deviceStates)
		w.statesMu.Unlock()

		// UI nach DNS-Updates aktualisieren
		w.app.QueueUpdateDraw(func() {
			w.updateTable()
		})
	}()
}

// updateDeviceStates aktualisiert die Device-States basierend auf Scan-Ergebnissen
func (w *TviewApp) updateDeviceStates(hosts []scanner.Host, scanStart time.Time) {
	w.statesMu.Lock()
	defer w.statesMu.Unlock()

	currentIPs := make(map[string]bool)

	for _, host := range hosts {
		ipStr := host.IP.String()

		if host.Online {
			currentIPs[ipStr] = true
		} else {
			continue
		}

		state, exists := w.deviceStates[ipStr]

		if exists {
			state.LastSeen = scanStart

			// Preserve hostname if already resolved
			oldHostname := state.Host.Hostname
			oldSource := state.Host.HostnameSource
			oldRTT := state.Host.RTT

			state.Host = host

			if oldSource != "" {
				state.Host.Hostname = oldHostname
				state.Host.HostnameSource = oldSource
			}

			if state.Host.RTT == 0 && oldRTT > 0 {
				state.Host.RTT = oldRTT
			}

			if state.Status == "offline" {
				offlineDuration := scanStart.Sub(state.StatusSince)
				state.TotalOfflineTime += offlineDuration
				state.Status = "online"
				state.StatusSince = scanStart
				state.FlapCount++
			}
		} else {
			w.deviceStates[ipStr] = &DeviceState{
				Host:          host,
				FirstSeen:     scanStart,
				FirstSeenScan: w.scanCount,
				LastSeen:      scanStart,
				Status:        "online",
				StatusSince:   scanStart,
			}
		}
	}

	// Check for offline devices
	for ipStr, state := range w.deviceStates {
		if !currentIPs[ipStr] && state.Status == "online" {
			state.Status = "offline"
			state.StatusSince = scanStart
			state.FlapCount++
		}
	}
}

// countdownLoop aktualisiert den Countdown-Timer
func (w *TviewApp) countdownLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if w.nextScanIn > 0 {
				w.nextScanIn -= time.Second
			}

			w.app.QueueUpdateDraw(func() {
				w.updateFooter()
				w.updateHeader() // Thread-Count aktualisieren
			})
		}
	}
}

// IsLocalSubnet prüft ob das Subnet lokal ist (Wrapper für discovery.IsLocalSubnet)
func IsLocalSubnet(netCIDR *net.IPNet) (bool, error) {
	// Einfache Implementierung - prüft ob es ein privates Netzwerk ist
	ip := netCIDR.IP

	// Private IPv4 ranges
	private10 := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}
	private172 := net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}
	private192 := net.IPNet{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}

	if private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip) {
		return true, nil
	}

	return false, nil
}

// GetSortedIPs gibt sortierte IP-Liste zurück (für externe Nutzung)
func (w *TviewApp) GetSortedIPs() []string {
	w.statesMu.RLock()
	defer w.statesMu.RUnlock()

	ips := make([]string, 0, len(w.deviceStates))
	for ip := range w.deviceStates {
		ips = append(ips, ip)
	}

	sort.Slice(ips, func(i, j int) bool {
		return CompareIPs(ips[i], ips[j])
	})

	return ips
}
