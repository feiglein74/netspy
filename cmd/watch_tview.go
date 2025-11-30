package cmd

import (
	"net"
	"time"

	"netspy/pkg/watch"
)

// runWatchTview startet den Watch-Modus mit tview UI
func runWatchTview(network string, netCIDR *net.IPNet, interval time.Duration, mode string, maxThreadsOverride int) error {
	// tview App erstellen
	app := watch.NewTviewApp(network, netCIDR, mode, interval, maxThreadsOverride)

	// App starten (blockiert bis Beenden)
	return app.Run()
}
