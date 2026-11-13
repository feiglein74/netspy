package watch

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"netspy/pkg/crash"
)

// Dienste, die per Enter über den Standard-Handler des Systems geöffnet werden
var connectSchemes = map[string]string{
	"http":  "http",
	"https": "https",
	"ssh":   "ssh",
}

// serviceURL liefert die URL zum Verbinden mit einem Port-Ergebnis.
// Nur per Sonde erkannte Dienste (Service ohne "?") sind verbindbar.
func serviceURL(ip string, result PortScanResult) (string, bool) {
	if result.Status != "open" || result.Probing {
		return "", false
	}
	scheme, ok := connectSchemes[result.Service]
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(ip, result.Port)), true
}

// openURL öffnet eine URL mit dem Standard-Programm des Systems (Browser, Terminal für ssh://)
func openURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Prozess im Hintergrund abwarten, damit kein Zombie-Prozess bleibt
	go func() {
		defer crash.RecoverAndLog("watch.openURL")
		_ = cmd.Wait()
	}()
	return nil
}

// focusTable setzt den Fokus in die Ergebnis-Tabelle (erste Zeile, falls nichts gewählt)
func (m *HostDetailsModal) focusTable() {
	if m.portsTable.GetRowCount() <= 1 {
		return
	}
	if row, _ := m.portsTable.GetSelection(); row < 1 {
		m.portsTable.Select(1, 0)
	}
	m.app.SetFocus(m.portsTable)
}

// connectSelected verbindet mit dem in der Tabelle gewählten Port
func (m *HostDetailsModal) connectSelected() {
	row, _ := m.portsTable.GetSelection()

	m.scanMu.Lock()
	var result PortScanResult
	found := row >= 1 && row <= len(m.scanResults)
	if found {
		result = m.scanResults[row-1]
	}
	m.scanMu.Unlock()
	if !found {
		return
	}

	url, ok := serviceURL(m.ipStr, result)
	if !ok {
		service := strings.TrimSuffix(result.Service, "?")
		switch {
		case result.Status != "open":
			m.showFooterMessage(fmt.Sprintf("Port %s ist nicht offen", result.Port))
		case result.Probing:
			m.showFooterMessage("Diensterkennung läuft noch …")
		default:
			m.showFooterMessage(fmt.Sprintf("Keine Verbindungsaktion für '%s' (Port %s)", service, result.Port))
		}
		return
	}

	if err := openURL(url); err != nil {
		m.showFooterMessage(fmt.Sprintf("[red]Öffnen fehlgeschlagen:[white] %v", err))
		return
	}
	m.showFooterMessage("Geöffnet: " + url)
}

// showFooterHelp zeigt die Tastenhinweise im Footer
func (m *HostDetailsModal) showFooterHelp() {
	m.footer.SetText("[yellow]Tab[white]=Switch  [yellow]↓↑[white]=Select port  [yellow]Enter[white]=Scan / Open  [yellow]ESC[white]=Close")
}

// showFooterMessage zeigt eine Meldung im Footer (bis zum nächsten Tastendruck)
func (m *HostDetailsModal) showFooterMessage(msg string) {
	m.footer.SetText(msg + "  [gray](ESC=Close)")
}
