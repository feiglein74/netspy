package watch

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netspy/pkg/crash"
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
	helpModal  *tview.Modal
	pages      *tview.Pages

	// Filter UI
	filterInput       *tview.InputField
	dropdown          *tview.List
	dropdownFlex      *tview.Flex // Container für Dropdown-Positionierung
	dropdownVisible   bool
	dropdownDisabled  bool // Verhindert sofortiges Wieder-Öffnen nach ESC
	filterInputActive bool   // TRUE wenn Filter-Eingabe aktiv ist (für Keyboard-Routing)
	suggestions       []string
	filterText        string // Aktiver Filter-Text
	filterError       string // Fehler bei Filter-Validierung
	filterHistory     []string
	historyIndex      int // -1 = neue Eingabe, 0+ = Historie durchblättern

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
	colorOffline  = tcell.ColorRed
	colorNew      = tcell.ColorLime
	colorFlapping = tcell.ColorYellow
	colorLocalMAC = tcell.ColorYellow
	colorHeader   = tcell.ColorAqua
	colorBorder   = tcell.ColorAqua
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
	// Filter Input (ganz oben)
	w.filterInput = tview.NewInputField().
		SetLabel("Filter: ").
		SetFieldWidth(0).
		SetFieldBackgroundColor(tcell.ColorDarkBlue)
	w.filterInput.SetBorder(true).
		SetBorderColor(colorBorder).
		SetTitle(" Filter (↑↓ History, Tab Select, Enter Apply, Esc Close) ").
		SetTitleColor(colorHeader).
		SetTitleAlign(tview.AlignCenter)

	// Focus/Blur Handler für Maus-Support
	w.filterInput.SetFocusFunc(func() {
		w.filterInputActive = true
	})
	w.filterInput.SetBlurFunc(func() {
		w.filterInputActive = false
	})

	w.setupFilterInput()

	// Dropdown Overlay für Vorschläge
	w.dropdown = tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true).
		SetSelectedBackgroundColor(tcell.ColorDarkCyan).
		SetSelectedTextColor(tcell.ColorWhite).
		SetMainTextColor(tcell.ColorYellow)
	w.dropdown.SetBorder(true).
		SetTitle(" ↑↓ Navigate, Tab/Enter Select, Esc Close ").
		SetBackgroundColor(tcell.ColorBlack)

	// ESC-Handler für Dropdown (falls Fokus dort landet)
	w.dropdown.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape:
			w.dropdownDisabled = true
			w.hideDropdown()
			w.app.SetFocus(w.filterInput)
			return nil
		case tcell.KeyTab, tcell.KeyEnter:
			// Auswahl übernehmen
			idx := w.dropdown.GetCurrentItem()
			if idx >= 0 && idx < len(w.suggestions) {
				w.filterInput.SetText(w.suggestions[idx])
			}
			w.hideDropdown()
			w.app.SetFocus(w.filterInput)
			return nil
		}
		return event
	})

	// Container für Dropdown-Positionierung (oben links, begrenzte Größe)
	w.dropdownFlex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(nil, 3, 0, false). // Platz für Filter-Input
		AddItem(tview.NewFlex().
			AddItem(w.dropdown, 40, 0, true). // Dropdown links, 40 Zeichen breit
			AddItem(nil, 0, 1, false),        // Rest leer
			10, 0, true). // Max 10 Zeilen hoch
		AddItem(nil, 0, 1, false) // Rest des Bildschirms leer

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
		SetSeparator(' ').          // Ein Leerzeichen zwischen Spalten
		SetEvaluateAllRows(true)    // Alle Zeilen für Spaltenbreite berücksichtigen
	w.table.SetBorder(true).
		SetBorderColor(colorBorder).
		SetTitle(" Devices ").
		SetTitleColor(colorHeader).
		SetTitleAlign(tview.AlignCenter)
	// Kein BorderPadding - verursacht Rendering-Probleme bei vielen Einträgen
	w.setupTableHeader()

	// Focus-Handler für Tabelle: filterInputActive zurücksetzen
	w.table.SetFocusFunc(func() {
		w.filterInputActive = false
	})

	// Enter-Handler für Tabelle: Host-Details Modal öffnen
	w.table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter {
			row, _ := w.table.GetSelection()
			if row > 0 { // Nicht auf Header-Zeile
				// IP aus erster Spalte extrahieren
				cell := w.table.GetCell(row, 0)
				if cell != nil {
					ipText := cell.Text
					// Marker entfernen ([G], [!], etc.)
					fields := strings.Fields(ipText)
					if len(fields) > 0 {
						ipStr := fields[0]
						w.showHostDetails(ipStr)
					}
				}
			}
			return nil
		}
		return event
	})

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

	// Haupt-Layout (ohne Footer - Controls sind in "Scan & Sort")
	w.flex = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(w.filterInput, 3, 0, false).    // Filter oben (3 Zeilen: 1 Text + 2 Border)
		AddItem(topRow, 5, 0, false).           // Header+Info (5 Zeilen: 3 Text + 2 Border)
		AddItem(w.table, 0, 1, true)            // Tabelle bekommt restlichen Platz

	// Pages für Modal-Handling
	w.pages = tview.NewPages().
		AddPage("main", w.flex, true, true).
		AddPage("help", w.helpModal, true, false)

	w.app.SetRoot(w.pages, true)
}

// setupTableHeader erstellt die Tabellen-Kopfzeile
func (w *TviewApp) setupTableHeader() {
	// Header mit festen Max-Breiten für Stabilität
	type colDef struct {
		name      string
		maxWidth  int // 0 = unbegrenzt
		expansion int // 0 = nur Inhalt, >0 = Gewichtung für Extra-Platz
	}

	columns := []colDef{
		{"IP Address", 16, 0},  // IP + evtl. [G] [!]
		{"Hostname", 20, 1},    // flexibel aber begrenzt
		{"MAC", 17, 0},         // 17 Zeichen
		{"Vendor", 15, 1},      // flexibel aber begrenzt
		{"Device", 12, 1},      // flexibel aber begrenzt
		{"RTT", 7, 0},          // z.B. "99.9ms"
		{"Up", 7, 0},           // z.B. "00m00s" (6 + 1 Padding)
		{"Fl", 3, 0},           // z.B. "99"
	}

	for col, def := range columns {
		cell := tview.NewTableCell(def.name).
			SetTextColor(colorHeader).
			SetAlign(tview.AlignLeft).
			SetSelectable(false).
			SetAttributes(tcell.AttrBold).
			SetExpansion(def.expansion)

		if def.maxWidth > 0 {
			cell.SetMaxWidth(def.maxWidth)
		}

		w.table.SetCell(0, col, cell)
	}
}

// setupKeyBindings richtet die Tastatur-Shortcuts ein
func (w *TviewApp) setupKeyBindings() {
	w.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		// Host-Details Modal ist offen - ESC schließt das Modal
		if w.pages.HasPage("hostdetails") {
			name, _ := w.pages.GetFrontPage()
			if name == "hostdetails" {
				// Alle Eingaben ans Modal weiterleiten
				return event
			}
		}

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

		// Wenn Filter aktiv ist, die meisten Tasten durchlassen
		// Double-check: filterInputActive UND tatsächlicher Fokus
		if w.filterInputActive && w.app.GetFocus() == w.filterInput {
			switch event.Key() {
			case tcell.KeyEscape:
				return event // An FilterInput weitergeben
			case tcell.KeyEnter, tcell.KeyTab, tcell.KeyUp, tcell.KeyDown:
				return event // Navigation im Filter
			case tcell.KeyCtrlC, tcell.KeyCtrlV, tcell.KeyCtrlX, tcell.KeyCtrlA:
				return event // Clipboard-Operationen
			case tcell.KeyBackspace, tcell.KeyBackspace2, tcell.KeyDelete:
				return event // Löschen
			case tcell.KeyLeft, tcell.KeyRight, tcell.KeyHome, tcell.KeyEnd:
				return event // Cursor-Navigation
			case tcell.KeyRune:
				return event // Normale Texteingabe
			default:
				return event // Alles andere auch durchlassen
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
			case '/':
				// / öffnet Filter-Eingabe (wie vim)
				w.filterInputActive = true
				w.app.SetFocus(w.filterInput)
				return nil
			case 'c', 'C':
				// c löscht Filter
				w.clearFilter()
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
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			// Backspace löscht letztes Zeichen des Filters (ohne in Filter-Modus zu wechseln)
			if w.filterText != "" {
				// Letztes Zeichen entfernen
				runes := []rune(w.filterText)
				w.filterText = string(runes[:len(runes)-1])
				w.filterInput.SetText(w.filterText)
				w.filterError = validateFilter(w.filterText)
				w.updateTable()
				w.updateInfo()
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

	// Sortierung und Shortcuts (Filter ist oben im Input-Feld sichtbar)
	var text string
	if w.filterError != "" {
		// Fehler anzeigen statt Shortcuts
		text = fmt.Sprintf("[yellow]Sort:[white] %s %s\n"+
			"[red]Filter Error:[white] %s\n"+
			"[gray]/[white]=filter [gray]c[white]=clear",
			sortName, sortDir, w.filterError)
	} else {
		text = fmt.Sprintf("[yellow]Sort:[white] %s %s\n"+
			"[gray]/[white]=filter [gray]c[white]=clear [gray]i[white]=IP [gray]h[white]=host\n"+
			"[gray]m[white]=MAC [gray]v[white]=vendor [gray]d[white]=dev [gray]r[white]=RTT [gray]u[white]=up [gray]f[white]=fl",
			sortName, sortDir)
	}
	w.infoView.SetText(text)
}

// updateTable aktualisiert die Host-Tabelle
func (w *TviewApp) updateTable() {
	w.statesMu.RLock()
	defer w.statesMu.RUnlock()

	// Sortierte IP-Liste erstellen (mit Filter)
	ips := make([]string, 0, len(w.deviceStates))
	for ip := range w.deviceStates {
		// Filter anwenden
		if w.matchesFilter(ip, w.deviceStates[ip]) {
			ips = append(ips, ip)
		}
	}

	referenceTime := time.Now()
	SortIPs(ips, w.deviceStates, w.sortState, referenceTime)

	// Tabelle komplett leeren und Header neu erstellen
	w.table.Clear()
	w.setupTableHeader()

	// Spalten-Definitionen für konsistente Breiten (muss mit setupTableHeader übereinstimmen)
	type colDef struct {
		maxWidth  int
		expansion int
		align     int // tview.AlignLeft = 0, tview.AlignRight = 2
	}
	columns := []colDef{
		{16, 0, tview.AlignLeft},  // IP Address
		{20, 1, tview.AlignLeft},  // Hostname
		{17, 0, tview.AlignLeft},  // MAC
		{15, 1, tview.AlignLeft},  // Vendor
		{12, 1, tview.AlignLeft},  // Device
		{7, 0, tview.AlignRight},  // RTT
		{7, 0, tview.AlignRight},  // Up
		{3, 0, tview.AlignRight},  // Fl
	}

	// Zeilen hinzufügen
	for i, ipStr := range ips {
		row := i + 1 // +1 wegen Header
		state := w.deviceStates[ipStr]

		// Standard-Farbe (weiß)
		rowColor := tcell.ColorWhite

		// Status-spezifische Farben
		ipColor := rowColor
		if state.Status == "offline" {
			ipColor = colorOffline
		} else if state.FirstSeenScan > 1 && (w.scanCount-state.FirstSeenScan) < 2 {
			ipColor = colorNew
		}

		// IP mit Markern + extra Leerzeichen für visuelle Trennung
		displayIP := ipStr
		if state.Host.IsGateway {
			displayIP += " [G]"
		}
		if state.Status == "offline" {
			displayIP += " [!]"
		}
		displayIP += " " // Extra Abstand vor Hostname

		// Hostname - tview schneidet automatisch ab wenn nötig
		hostname := GetHostname(state.Host)

		// MAC + extra Leerzeichen für visuelle Trennung
		mac := state.Host.MAC
		if mac == "" {
			mac = "-"
		}
		macColor := rowColor
		if IsLocallyAdministered(mac) {
			macColor = colorLocalMAC
		}
		mac += " " // Extra Abstand vor Vendor

		// Vendor - tview schneidet automatisch ab wenn nötig
		vendor := GetVendor(state.Host)

		// Device Type - nicht abschneiden
		deviceType := state.Host.DeviceType
		if deviceType == "" || deviceType == "Unknown" {
			deviceType = "-"
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

		// Daten für jede Spalte
		cellData := []struct {
			text  string
			color tcell.Color
		}{
			{displayIP, ipColor},
			{hostname, rowColor},
			{mac, macColor},
			{vendor, rowColor},
			{deviceType, rowColor},
			{rttText, rowColor},
			{uptimeText, rowColor},
			{flapText, flapColor},
		}

		// Zellen setzen mit gleichen MaxWidth/Expansion wie Header
		for col, def := range columns {
			cell := tview.NewTableCell(cellData[col].text).
				SetTextColor(cellData[col].color).
				SetAlign(def.align).
				SetExpansion(def.expansion)
			if def.maxWidth > 0 {
				cell.SetMaxWidth(def.maxWidth)
			}
			w.table.SetCell(row, col, cell)
		}
	}

	// Sort-Indikator im Header aktualisieren
	w.updateTableHeaderWithSort()

	// Scroll-Indikator im Tabellen-Titel aktualisieren
	w.updateScrollIndicators(len(ips))
}

// updateTableHeaderWithSort aktualisiert Header mit Sort-Indikator
func (w *TviewApp) updateTableHeaderWithSort() {
	// Kurze Header-Namen (müssen mit setupTableHeader übereinstimmen)
	headers := []struct {
		name string
		col  SortColumn
	}{
		{"IP Address", SortByIP},
		{"Hostname", SortByHostname},
		{"MAC", SortByMAC},
		{"Vendor", SortByVendor},
		{"Device", SortByDeviceType},
		{"RTT", SortByRTT},
		{"Up", SortByUptime},
		{"Fl", SortByFlaps},
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

// updateScrollIndicators fügt Scroll-Hinweise oben und unten in die Tabelle ein
func (w *TviewApp) updateScrollIndicators(totalDevices int) {
	_, _, _, height := w.table.GetInnerRect()
	visibleRows := height - 1 // -1 für Header

	if visibleRows <= 0 || totalDevices <= visibleRows {
		// Alle sichtbar oder kein Platz - Titel zurücksetzen
		w.table.SetTitle(" Devices ")
		return
	}

	// Scroll-Position ermitteln
	rowOffset, _ := w.table.GetOffset()

	// Berechne wie viele Einträge oben/unten versteckt sind
	hiddenAbove := rowOffset
	hiddenBelow := totalDevices - (rowOffset + visibleRows)
	if hiddenBelow < 0 {
		hiddenBelow = 0
	}

	// Titel mit Scroll-Info
	if hiddenAbove > 0 || hiddenBelow > 0 {
		titleParts := []string{}
		if hiddenAbove > 0 {
			titleParts = append(titleParts, fmt.Sprintf("↑%d", hiddenAbove))
		}
		if hiddenBelow > 0 {
			titleParts = append(titleParts, fmt.Sprintf("↓%d", hiddenBelow))
		}
		w.table.SetTitle(fmt.Sprintf(" Devices (%d) %s ", totalDevices, strings.Join(titleParts, " ")))
	} else {
		w.table.SetTitle(fmt.Sprintf(" Devices (%d) ", totalDevices))
	}
}

// getHelpText gibt den Help-Text zurück
func (w *TviewApp) getHelpText() string {
	return `NetSpy Hilfe

FILTER:
  / = Filter öffnen
  c = Filter löschen
  ↑/↓ = History durchblättern
  Tab = Vorschlag übernehmen
  Enter = Filter anwenden
  Esc = Filter schließen

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
  Enter = Host Details + Port Scan
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
	// Terminal-Reset-Funktion registrieren für sauberen Crash-Exit
	crash.SetTerminalResetFunc(func() {
		w.app.Stop()
	})

	// Screen vor Start clearen (Windows Terminal Fix)
	fmt.Print("\033[2J\033[H")

	// Maus-Unterstützung aktivieren
	w.app.EnableMouse(true)

	// Bei JEDEM Draw den Screen vollständig synchronisieren (Windows Terminal Fix)
	w.app.SetAfterDrawFunc(func(screen tcell.Screen) {
		screen.Sync()
	})

	// Scan-Loop in Goroutine starten (mit Crash-Recovery)
	crash.SafeGo("scanLoop", w.scanLoop)

	// Countdown-Timer in Goroutine (mit Crash-Recovery)
	crash.SafeGo("countdownLoop", w.countdownLoop)

	// UI starten (blockiert)
	return w.app.Run()
}

// Stop beendet die Anwendung
func (w *TviewApp) Stop() {
	// Debug: Stack trace ausgeben um zu sehen woher der Stop kommt
	fmt.Println("\n[DEBUG] Stop() aufgerufen von:")
	debug.PrintStack()
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
	})

	// Background DNS Lookups starten
	go func() {
		w.statesMu.Lock()
		PerformInitialDNSLookups(w.ctx, w.deviceStates)
		w.statesMu.Unlock()

		// UI nach DNS-Updates aktualisieren (alle Komponenten für Konsistenz)
		w.app.QueueUpdateDraw(func() {
			w.updateHeader()
			w.updateInfo()
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
				w.updateHeader()
				w.updateInfo()
				w.updateTable()
			})
		}
	}
}

// setupFilterInput richtet die Tastatur-Behandlung für das Filter-Feld ein
func (w *TviewApp) setupFilterInput() {
	w.historyIndex = -1

	w.filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyUp:
			// Dropdown navigieren oder History durchblättern
			if w.dropdownVisible && w.dropdown.GetItemCount() > 0 {
				idx := w.dropdown.GetCurrentItem()
				if idx > 0 {
					w.dropdown.SetCurrentItem(idx - 1)
				} else {
					w.dropdown.SetCurrentItem(w.dropdown.GetItemCount() - 1)
				}
				return nil
			}
			// History nach oben
			if len(w.filterHistory) > 0 {
				if w.historyIndex < len(w.filterHistory)-1 {
					w.historyIndex++
					w.filterInput.SetText(w.filterHistory[len(w.filterHistory)-1-w.historyIndex])
				}
			}
			return nil
		case tcell.KeyDown:
			// Dropdown navigieren oder History durchblättern
			if w.dropdownVisible && w.dropdown.GetItemCount() > 0 {
				idx := w.dropdown.GetCurrentItem()
				if idx < w.dropdown.GetItemCount()-1 {
					w.dropdown.SetCurrentItem(idx + 1)
				} else {
					w.dropdown.SetCurrentItem(0)
				}
				return nil
			}
			// History nach unten
			if w.historyIndex > 0 {
				w.historyIndex--
				w.filterInput.SetText(w.filterHistory[len(w.filterHistory)-1-w.historyIndex])
			} else if w.historyIndex == 0 {
				w.historyIndex = -1
				w.filterInput.SetText("")
			}
			return nil
		case tcell.KeyTab:
			// Tab wählt aus Dropdown
			if w.dropdownVisible && w.dropdown.GetItemCount() > 0 {
				idx := w.dropdown.GetCurrentItem()
				if idx >= 0 && idx < len(w.suggestions) {
					w.applySuggestion(w.suggestions[idx])
				}
				w.hideDropdown()
				return nil
			}
		case tcell.KeyEnter:
			// Wenn Dropdown sichtbar, erst ausgewählten Eintrag übernehmen
			if w.dropdownVisible && w.dropdown.GetItemCount() > 0 {
				idx := w.dropdown.GetCurrentItem()
				if idx >= 0 && idx < len(w.suggestions) {
					w.applySuggestion(w.suggestions[idx])
				}
			}
			w.hideDropdown()
			w.filterInputActive = false // Filter-Modus beenden
			w.applyFilter()
			return nil
		case tcell.KeyEscape:
			// Esc schließt Dropdown oder Filter-Feld
			if w.dropdownVisible {
				w.dropdownDisabled = true // Verhindert sofortiges Wieder-Öffnen
				w.hideDropdown()
				return nil
			}
			w.filterInputActive = false // Filter-Modus beenden
			w.app.SetFocus(w.table)
			return nil
		}
		return event
	})

	// Dropdown aktualisieren bei Texteingabe
	w.filterInput.SetChangedFunc(func(text string) {
		// Bei neuer Eingabe das Dropdown wieder erlauben
		w.dropdownDisabled = false
		w.updateDropdown(text)
	})
}

// applySuggestion fügt eine Suggestion in den Filter-Text ein
// Bei && / || / AND / OR wird nur der Teil nach dem letzten Operator ersetzt
// NOT ist ein Präfix und wird NICHT als Trennstelle verwendet
func (w *TviewApp) applySuggestion(suggestion string) {
	currentText := w.filterInput.GetText()

	// Finde den letzten Infix-Operator (AND/OR, NICHT: NOT)
	type opMatch struct {
		pos int
		len int
	}
	operators := []struct {
		pattern string
		length  int
	}{
		{"&&", 2},
		{"||", 2},
		{" AND ", 5},
		{" and ", 5},
		{" And ", 5},
		{" OR ", 4},
		{" or ", 4},
		{" Or ", 4},
		// NOT ist Präfix, nicht hier!
	}

	var lastMatch *opMatch
	for _, op := range operators {
		pos := strings.LastIndex(currentText, op.pattern)
		if pos >= 0 && (lastMatch == nil || pos > lastMatch.pos) {
			lastMatch = &opMatch{pos: pos, len: op.length}
		}
	}

	if lastMatch != nil {
		// Alles bis zum letzten Operator behalten
		prefix := currentText[:lastMatch.pos+lastMatch.len]
		// Prüfen ob nach dem Operator ein NOT/! steht - das behalten
		suffix := strings.TrimSpace(currentText[lastMatch.pos+lastMatch.len:])
		notPrefix := ""
		for _, notOp := range []string{"NOT ", "not ", "Not ", "!"} {
			if strings.HasPrefix(suffix, notOp) {
				notPrefix = notOp
				break
			}
		}
		// Zusammenbauen
		if strings.HasSuffix(prefix, " ") {
			w.filterInput.SetText(prefix + notPrefix + suggestion)
		} else {
			w.filterInput.SetText(prefix + " " + notPrefix + suggestion)
		}
	} else {
		// Kein Infix-Operator - prüfen ob NOT am Anfang steht
		trimmed := strings.TrimSpace(currentText)
		for _, notOp := range []string{"NOT ", "not ", "Not ", "!"} {
			if strings.HasPrefix(trimmed, notOp) {
				w.filterInput.SetText(notOp + suggestion)
				return
			}
		}
		// Kein Operator - einfach ersetzen
		w.filterInput.SetText(suggestion)
	}
}

// updateDropdown aktualisiert die Vorschlagsliste basierend auf Eingabe
func (w *TviewApp) updateDropdown(text string) {
	if text == "" {
		w.hideDropdown()
		return
	}

	w.statesMu.RLock()
	defer w.statesMu.RUnlock()

	// Normalisiere Operatoren für Suche
	normalizedText := normalizeFilterText(text)

	// Teil nach dem letzten Operator für Suggestions verwenden
	searchText := normalizedText
	lastAnd := strings.LastIndex(normalizedText, "&&")
	lastOr := strings.LastIndex(normalizedText, "||")
	lastOp := lastAnd
	if lastOr > lastOp {
		lastOp = lastOr
	}
	if lastOp >= 0 {
		searchText = strings.TrimSpace(normalizedText[lastOp+2:])
		if searchText == "" {
			w.hideDropdown()
			return
		}
	}

	// NOT-Prefix entfernen für Suche
	if strings.HasPrefix(searchText, "!") {
		searchText = strings.TrimSpace(searchText[1:])
		if searchText == "" {
			w.hideDropdown()
			return
		}
	}

	// Sammle alle matchenden Werte
	matches := make(map[string]bool)
	textLower := strings.ToLower(searchText)

	for ipStr, state := range w.deviceStates {
		// IP prüfen
		if strings.Contains(strings.ToLower(ipStr), textLower) {
			matches[ipStr] = true
		}
		// Hostname prüfen
		if state.Host.Hostname != "" && strings.Contains(strings.ToLower(state.Host.Hostname), textLower) {
			matches[state.Host.Hostname] = true
		}
		// MAC prüfen
		if state.Host.MAC != "" && strings.Contains(strings.ToLower(state.Host.MAC), textLower) {
			matches[state.Host.MAC] = true
		}
		// Vendor prüfen
		if state.Host.Vendor != "" && strings.Contains(strings.ToLower(state.Host.Vendor), textLower) {
			matches[state.Host.Vendor] = true
		}
		// DeviceType prüfen
		if state.Host.DeviceType != "" && strings.Contains(strings.ToLower(state.Host.DeviceType), textLower) {
			matches[state.Host.DeviceType] = true
		}
	}

	// In Liste umwandeln und sortieren
	w.suggestions = make([]string, 0, len(matches))
	for match := range matches {
		w.suggestions = append(w.suggestions, match)
	}
	sort.Strings(w.suggestions)

	// Maximal 8 Vorschläge
	if len(w.suggestions) > 8 {
		w.suggestions = w.suggestions[:8]
	}

	if len(w.suggestions) == 0 {
		w.hideDropdown()
		return
	}

	// Dropdown befüllen
	w.dropdown.Clear()
	for _, suggestion := range w.suggestions {
		w.dropdown.AddItem(suggestion, "", 0, nil)
	}
	// Ersten Eintrag auswählen
	w.dropdown.SetCurrentItem(0)

	w.showDropdown()
}

// showDropdown zeigt das Dropdown-Overlay
func (w *TviewApp) showDropdown() {
	if w.dropdownVisible {
		return
	}
	w.dropdownVisible = true
	// Dropdown in Container hinzufügen (resize=true damit es sich anpasst, aber Container begrenzt Größe)
	w.pages.AddPage("dropdown", w.dropdownFlex, true, true)
	// Fokus bleibt auf FilterInput
	w.app.SetFocus(w.filterInput)
}

// hideDropdown versteckt das Dropdown-Overlay
func (w *TviewApp) hideDropdown() {
	if !w.dropdownVisible {
		return
	}
	w.dropdownVisible = false
	// Merken ob Filter aktiv war (RemovePage kann Blur auslösen)
	wasFilterActive := w.filterInputActive
	w.pages.RemovePage("dropdown")
	// Fokus und State wiederherstellen falls Filter aktiv war
	if wasFilterActive {
		w.filterInputActive = true
		w.app.SetFocus(w.filterInput)
	}
}

// validateFilter prüft ob ein Filter gültig ist und gibt ggf. einen Fehler zurück
func validateFilter(filter string) string {
	if filter == "" {
		return ""
	}

	// Normalisiere Operatoren
	normalized := normalizeFilterText(filter)

	// Prüfe alle Teile (OR-Split, dann AND-Split)
	orParts := strings.Split(normalized, "||")
	for _, orPart := range orParts {
		andParts := strings.Split(orPart, "&&")
		for _, part := range andParts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			// NOT-Prefix entfernen
			if strings.HasPrefix(part, "!") {
				part = strings.TrimSpace(part[1:])
			}
			if part == "" {
				continue
			}

			// CIDR validieren (z.B. 10.0.113.0/28)
			if strings.Contains(part, "/") {
				_, _, err := net.ParseCIDR(part)
				if err != nil {
					return fmt.Sprintf("Invalid CIDR: %s", part)
				}
				continue
			}

			// IP-Bereich validieren (z.B. 10.0.113.11-13)
			if isIPRangeFilter(part) {
				// Zusätzliche Validierung: Bereich prüfen
				lastDot := strings.LastIndex(part, ".")
				rangePart := part[lastDot+1:]
				rangeParts := strings.Split(rangePart, "-")
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				if start < 0 || start > 255 || end < 0 || end > 255 {
					return fmt.Sprintf("Invalid IP range: %s (0-255)", part)
				}
				continue
			}

			// Wildcard-Pattern validieren
			if strings.Contains(part, "*") {
				regexPattern := wildcardToRegex(part)
				_, err := regexp.Compile(regexPattern)
				if err != nil {
					return fmt.Sprintf("Invalid pattern: %s", part)
				}
			}
		}
	}
	return ""
}

// applyFilter wendet den aktuellen Filter an
// WICHTIG: Diese Funktion wird aus InputCapture aufgerufen, also bereits im UI-Thread!
// Daher KEIN QueueUpdateDraw verwenden - das würde einen Deadlock verursachen.
func (w *TviewApp) applyFilter() {
	text := strings.TrimSpace(w.filterInput.GetText())
	w.filterText = text

	// Filter validieren
	w.filterError = validateFilter(text)

	// Zur History hinzufügen (wenn nicht leer und nicht bereits vorhanden, und kein Fehler)
	if text != "" {
		// Duplikate entfernen
		newHistory := make([]string, 0, len(w.filterHistory)+1)
		for _, h := range w.filterHistory {
			if h != text {
				newHistory = append(newHistory, h)
			}
		}
		newHistory = append(newHistory, text)
		// Max 20 Einträge behalten
		if len(newHistory) > 20 {
			newHistory = newHistory[len(newHistory)-20:]
		}
		w.filterHistory = newHistory
	}

	w.historyIndex = -1

	// Direkt updaten (wir sind bereits im UI-Thread aus InputCapture)
	w.updateTable()
	w.updateInfo()

	// Fokus zurück zur Tabelle
	w.app.SetFocus(w.table)
}

// clearFilter löscht den aktuellen Filter
// WICHTIG: Wird aus InputCapture aufgerufen - kein QueueUpdateDraw!
func (w *TviewApp) clearFilter() {
	w.filterText = ""
	w.filterError = ""
	w.filterInput.SetText("")
	w.historyIndex = -1

	// Direkt updaten (bereits im UI-Thread)
	w.updateTable()
	w.updateInfo()
}

// normalizeFilterText ersetzt Wort-Operatoren durch Symbole
// AND/and → &&, OR/or → ||, NOT/not → !
func normalizeFilterText(text string) string {
	// Groß/Kleinschreibung beachten für Wort-Grenzen
	// Ersetze " AND " oder " and " durch " && "
	result := text
	for _, word := range []string{" AND ", " and ", " And "} {
		result = strings.ReplaceAll(result, word, " && ")
	}
	for _, word := range []string{" OR ", " or ", " Or "} {
		result = strings.ReplaceAll(result, word, " || ")
	}
	// NOT am Anfang oder nach Operator
	for _, word := range []string{"NOT ", "not ", "Not "} {
		result = strings.ReplaceAll(result, word, "!")
	}
	return result
}

// matchesFilter prüft ob ein Device zum aktuellen Filter passt
// Unterstützt:
// - Wildcards: * für beliebige Zeichen (z.B. "192.168.*" oder "*router*")
// - AND-Verknüpfung: && oder AND (z.B. "apple && online" oder "apple AND online")
// - OR-Verknüpfung: || oder OR (z.B. "apple || samsung" oder "apple OR samsung")
// - NOT: ! oder NOT am Anfang (z.B. "!offline" oder "NOT offline")
// Priorität: || wird zuerst gesplittet (niedrigste Priorität), dann &&
func (w *TviewApp) matchesFilter(ipStr string, state *DeviceState) bool {
	if w.filterText == "" {
		return true
	}

	// Wort-Operatoren zu Symbolen normalisieren
	filterText := normalizeFilterText(w.filterText)

	// Alle durchsuchbaren Felder sammeln
	searchFields := []string{
		strings.ToLower(ipStr),
		strings.ToLower(state.Host.Hostname),
		strings.ToLower(state.Host.MAC),
		strings.ToLower(state.Host.Vendor),
		strings.ToLower(state.Host.DeviceType),
		strings.ToLower(state.Status), // "online" oder "offline"
	}

	// OR hat niedrigste Priorität - mindestens ein Teil muss matchen
	if strings.Contains(filterText, "||") {
		orParts := strings.Split(filterText, "||")
		for _, orPart := range orParts {
			orPart = strings.TrimSpace(orPart)
			if orPart == "" {
				continue
			}
			if matchesAndExpression(orPart, searchFields) {
				return true
			}
		}
		return false
	}

	// Kein OR - als AND-Expression behandeln
	return matchesAndExpression(filterText, searchFields)
}

// matchesAndExpression prüft einen AND-Ausdruck (kann mehrere && enthalten)
func matchesAndExpression(expr string, fields []string) bool {
	// Bei && müssen ALLE Teile matchen
	if strings.Contains(expr, "&&") {
		parts := strings.Split(expr, "&&")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !matchesSingleFilter(part, fields) {
				return false
			}
		}
		return true
	}

	// Einzelner Filter
	return matchesSingleFilter(expr, fields)
}

// matchesSingleFilter prüft einen einzelnen Filter-Term gegen alle Felder
// Ohne Wildcard: Exakter Match auf ein Feld
// Mit Wildcard (*): Pattern-Matching
// Mit ! am Anfang: Negation (NOT)
// IP-Bereich: 10.0.113.11-13 matcht .11, .12, .13
// CIDR: 10.0.113.0/28 matcht alle IPs im Subnet
func matchesSingleFilter(filter string, fields []string) bool {
	filterLower := strings.ToLower(strings.TrimSpace(filter))
	if filterLower == "" {
		return true
	}

	// NOT-Operator: ! am Anfang
	negated := false
	if strings.HasPrefix(filterLower, "!") {
		negated = true
		filterLower = strings.TrimSpace(filterLower[1:])
		if filterLower == "" {
			return true
		}
	}

	var matches bool

	// IP-Feld extrahieren (erstes Feld ist immer die IP)
	ipField := ""
	if len(fields) > 0 {
		ipField = fields[0]
	}

	// CIDR-Filter: z.B. 10.0.113.0/28
	if strings.Contains(filterLower, "/") {
		matches = matchesCIDR(filterLower, ipField)
	} else if isIPRangeFilter(filterLower) {
		// IP-Bereich-Filter: z.B. 10.0.113.11-13
		matches = matchesIPRange(filterLower, ipField)
	} else if strings.Contains(filterLower, "*") {
		// Wildcard-Support: * wird zu Regex-Pattern
		matches = matchesWildcard(filterLower, fields)
	} else {
		// Ohne Wildcard: Exakter Match auf ein Feld
		matches = false
		for _, field := range fields {
			if field != "" && field == filterLower {
				matches = true
				break
			}
		}
	}

	// Bei Negation umkehren
	if negated {
		return !matches
	}
	return matches
}

// isIPRangeFilter prüft ob der Filter ein IP-Bereich ist (z.B. 10.0.113.11-13)
func isIPRangeFilter(filter string) bool {
	// Muss mindestens einen Punkt und einen Bindestrich enthalten
	// Format: x.x.x.start-end
	if !strings.Contains(filter, ".") || !strings.Contains(filter, "-") {
		return false
	}

	// Letztes Oktett muss den Bereich enthalten
	lastDot := strings.LastIndex(filter, ".")
	if lastDot == -1 || lastDot >= len(filter)-1 {
		return false
	}

	lastOctet := filter[lastDot+1:]
	parts := strings.Split(lastOctet, "-")
	if len(parts) != 2 {
		return false
	}

	// Beide Teile müssen Zahlen sein
	_, err1 := strconv.Atoi(parts[0])
	_, err2 := strconv.Atoi(parts[1])
	return err1 == nil && err2 == nil
}

// matchesIPRange prüft ob eine IP in einem Bereich liegt (z.B. 10.0.113.11-13)
func matchesIPRange(filter string, ipField string) bool {
	if ipField == "" {
		return false
	}

	// Filter parsen: 10.0.113.11-13
	lastDot := strings.LastIndex(filter, ".")
	if lastDot == -1 {
		return false
	}

	prefix := filter[:lastDot+1] // "10.0.113."
	rangePart := filter[lastDot+1:]
	parts := strings.Split(rangePart, "-")
	if len(parts) != 2 {
		return false
	}

	start, err1 := strconv.Atoi(parts[0])
	end, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}

	// IP-Feld parsen
	ipLastDot := strings.LastIndex(ipField, ".")
	if ipLastDot == -1 {
		return false
	}

	ipPrefix := ipField[:ipLastDot+1]
	ipLastOctet := ipField[ipLastDot+1:]

	// Prefix muss übereinstimmen
	if ipPrefix != prefix {
		return false
	}

	// Letztes Oktett der IP parsen
	ipNum, err := strconv.Atoi(ipLastOctet)
	if err != nil {
		return false
	}

	// Prüfen ob im Bereich (start und end können vertauscht sein)
	if start > end {
		start, end = end, start
	}

	return ipNum >= start && ipNum <= end
}

// matchesCIDR prüft ob eine IP in einem CIDR-Bereich liegt (z.B. 10.0.113.0/28)
func matchesCIDR(filter string, ipField string) bool {
	if ipField == "" {
		return false
	}

	// CIDR parsen
	_, network, err := net.ParseCIDR(filter)
	if err != nil {
		return false
	}

	// IP parsen
	ip := net.ParseIP(ipField)
	if ip == nil {
		return false
	}

	return network.Contains(ip)
}

// matchesWildcard prüft Wildcard-Pattern gegen Felder
// * = beliebige Zeichen (auch keine)
func matchesWildcard(pattern string, fields []string) bool {
	// Pattern in Regex konvertieren:
	// - * wird zu .*
	// - Andere Regex-Sonderzeichen escapen
	regexPattern := wildcardToRegex(pattern)

	for _, field := range fields {
		if field == "" {
			continue
		}
		matched, _ := regexp.MatchString(regexPattern, field)
		if matched {
			return true
		}
	}
	return false
}

// wildcardToRegex konvertiert ein Wildcard-Pattern zu Regex
func wildcardToRegex(pattern string) string {
	// Regex-Sonderzeichen escapen (außer *)
	escaped := regexp.QuoteMeta(pattern)
	// \* (escaped asterisk) zurück zu .* (regex any)
	result := strings.ReplaceAll(escaped, `\*`, `.*`)
	// Vollständiger Match (Anfang und Ende)
	return "^" + result + "$"
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

// showHostDetails zeigt das Host-Details Modal für eine IP
func (w *TviewApp) showHostDetails(ipStr string) {
	w.statesMu.RLock()
	state, exists := w.deviceStates[ipStr]
	w.statesMu.RUnlock()

	if !exists {
		return
	}

	// Modal erstellen mit Callback zum Schließen
	modal := NewHostDetailsModal(w.app, w.pages, ipStr, state, func() {
		// Fokus zurück zur Tabelle
		w.app.SetFocus(w.table)
	})

	modal.Show()
}
