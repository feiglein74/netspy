// Package crash bietet globales Panic-Recovery und Crash-Logging für NetSpy.
package crash

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// CrashInfo enthält Informationen über einen Crash
type CrashInfo struct {
	Time         time.Time
	Error        interface{}
	StackTrace   string
	GoVersion    string
	OS           string
	Arch         string
	NumGoroutine int
	NumCPU       int
	MemStats     runtime.MemStats
}

// crashLogFile ist der Pfad zur Crash-Log-Datei
var crashLogFile string

// sentinelFile ist der Pfad zur Sentinel-Datei (zeigt laufenden Prozess an)
var sentinelFile string

// terminalResetFunc ist eine optionale Funktion zum Zurücksetzen des Terminals
var terminalResetFunc func()

func init() {
	// Standard Crash-Log im aktuellen Verzeichnis
	crashLogFile = "netspy_crash.log"
	sentinelFile = ".netspy.running"
}

// SetCrashLogFile setzt den Pfad zur Crash-Log-Datei
func SetCrashLogFile(path string) {
	crashLogFile = path
}

// SetTerminalResetFunc setzt eine Funktion zum Zurücksetzen des Terminals bei Crash
func SetTerminalResetFunc(f func()) {
	terminalResetFunc = f
}

// Handler ist der globale Crash-Handler, der als defer in main() verwendet wird
func Handler() {
	if r := recover(); r != nil {
		handleCrash(r)
	}
}

// handleCrash verarbeitet einen abgefangenen Panic
func handleCrash(r interface{}) {
	// Terminal zuerst zurücksetzen falls möglich
	resetTerminal()

	// Memory-Stats sammeln
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Crash-Info sammeln
	info := CrashInfo{
		Time:         time.Now(),
		Error:        r,
		StackTrace:   string(debug.Stack()),
		GoVersion:    runtime.Version(),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
		MemStats:     memStats,
	}

	// In Datei loggen
	logCrash(info)

	// Benutzerfreundliche Ausgabe
	printCrashMessage(info)

	// Mit Fehlercode beenden
	os.Exit(1)
}

// resetTerminal setzt das Terminal in einen sauberen Zustand zurück
func resetTerminal() {
	// Benutzerdefinierte Reset-Funktion aufrufen falls vorhanden
	if terminalResetFunc != nil {
		// Sicher ausführen - könnte selbst paniken
		func() {
			defer func() { _ = recover() }()
			terminalResetFunc()
		}()
	}

	// ANSI Reset-Sequenzen senden
	fmt.Print("\033[?25h")   // Cursor anzeigen
	fmt.Print("\033[0m")     // Alle Attribute zurücksetzen
	fmt.Print("\033[?1049l") // Alternate Screen Buffer verlassen (falls aktiv)
	fmt.Println()            // Neue Zeile für saubere Ausgabe
}

// logCrash schreibt Crash-Informationen in die Log-Datei
func logCrash(info CrashInfo) {
	// Versuche Log-Datei zu öffnen/erstellen
	f, err := os.OpenFile(crashLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		// Kann nicht loggen, ignorieren
		return
	}
	defer func() { _ = f.Close() }()

	// Log-Eintrag formatieren
	entry := formatCrashLog(info)
	_, _ = f.WriteString(entry)
}

// formatCrashLog formatiert einen Crash-Eintrag für die Log-Datei
func formatCrashLog(info CrashInfo) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("================================================================================\n")
	fmt.Fprintf(&sb, "CRASH REPORT - %s\n", info.Time.Format("2006-01-02 15:04:05"))
	sb.WriteString("================================================================================\n")
	fmt.Fprintf(&sb, "Error: %v\n", info.Error)
	fmt.Fprintf(&sb, "Go Version: %s\n", info.GoVersion)
	fmt.Fprintf(&sb, "OS/Arch: %s/%s\n", info.OS, info.Arch)
	fmt.Fprintf(&sb, "CPUs: %d\n", info.NumCPU)
	fmt.Fprintf(&sb, "Goroutines: %d\n", info.NumGoroutine)
	sb.WriteString("\n--- Memory Stats ---\n")
	fmt.Fprintf(&sb, "Alloc: %s\n", formatBytes(info.MemStats.Alloc))
	fmt.Fprintf(&sb, "TotalAlloc: %s\n", formatBytes(info.MemStats.TotalAlloc))
	fmt.Fprintf(&sb, "Sys: %s\n", formatBytes(info.MemStats.Sys))
	fmt.Fprintf(&sb, "HeapAlloc: %s\n", formatBytes(info.MemStats.HeapAlloc))
	fmt.Fprintf(&sb, "HeapInuse: %s\n", formatBytes(info.MemStats.HeapInuse))
	fmt.Fprintf(&sb, "HeapObjects: %d\n", info.MemStats.HeapObjects)
	fmt.Fprintf(&sb, "NumGC: %d\n", info.MemStats.NumGC)
	sb.WriteString("\n--- Stack Trace ---\n")
	sb.WriteString(info.StackTrace)
	sb.WriteString("================================================================================\n")

	return sb.String()
}

// formatBytes formatiert Bytes in lesbare Form
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// printCrashMessage gibt eine benutzerfreundliche Crash-Meldung aus
func printCrashMessage(info CrashInfo) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                         NetSpy ist unerwartet beendet                        ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Fehler: %v\n", info.Error)
	fmt.Println()

	// Crash-Log-Pfad anzeigen
	absPath, err := filepath.Abs(crashLogFile)
	if err != nil {
		absPath = crashLogFile
	}
	fmt.Printf("  Ein detaillierter Crash-Report wurde gespeichert:\n")
	fmt.Printf("  → %s\n", absPath)
	fmt.Println()
	fmt.Println("  Bitte melden Sie diesen Fehler unter:")
	fmt.Println("  → https://github.com/feiglein74/netspy/issues")
	fmt.Println()
}

// WrapGoroutine wickelt eine Goroutine-Funktion mit Panic-Recovery ein
// Verwendung: go crash.WrapGoroutine("taskName", func() { ... })()
func WrapGoroutine(name string, f func()) func() {
	return func() {
		defer func() {
			if r := recover(); r != nil {
				// Terminal zurücksetzen
				resetTerminal()

				// Crash-Info sammeln
				info := CrashInfo{
					Time:       time.Now(),
					Error:      fmt.Sprintf("goroutine '%s': %v", name, r),
					StackTrace: string(debug.Stack()),
					GoVersion:  runtime.Version(),
					OS:         runtime.GOOS,
					Arch:       runtime.GOARCH,
				}

				// In Datei loggen
				logCrash(info)

				// Benutzerfreundliche Ausgabe
				printCrashMessage(info)

				// Beenden
				os.Exit(1)
			}
		}()
		f()
	}
}

// SafeGo startet eine Goroutine mit automatischem Panic-Recovery
// Verwendung: crash.SafeGo("taskName", func() { ... })
func SafeGo(name string, f func()) {
	go WrapGoroutine(name, f)()
}

// RecoverAndLog fängt Panics ab und loggt sie, ohne das Programm zu beenden
// Nützlich für nicht-kritische Goroutines
// Verwendung: defer crash.RecoverAndLog("taskName")
func RecoverAndLog(name string) {
	if r := recover(); r != nil {
		// Crash-Info sammeln
		info := CrashInfo{
			Time:       time.Now(),
			Error:      fmt.Sprintf("recovered in '%s': %v", name, r),
			StackTrace: string(debug.Stack()),
			GoVersion:  runtime.Version(),
			OS:         runtime.GOOS,
			Arch:       runtime.GOARCH,
		}

		// Nur loggen, nicht beenden
		logCrash(info)

		// Optional: Warnung ausgeben (falls nicht im quiet mode)
		fmt.Fprintf(os.Stderr, "\n[WARNUNG] Fehler in %s wurde abgefangen: %v\n", name, r)
	}
}

// ============================================================================
// Sentinel-File Mechanismus - Erkennt unsaubere Beendigungen
// ============================================================================

// StartSentinel prüft auf vorherige unsaubere Beendigung und startet neuen Sentinel
// Gibt true zurück wenn der letzte Lauf unsauber beendet wurde
func StartSentinel() bool {
	wasUnclean := false

	// Prüfen ob Sentinel-Datei existiert (= letzter Lauf war unsauber)
	if _, err := os.Stat(sentinelFile); err == nil {
		wasUnclean = true

		// Lese Inhalt für Details
		content, _ := os.ReadFile(sentinelFile)

		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  ⚠️  WARNUNG: Letzter Lauf wurde nicht sauber beendet!                        ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
		if len(content) > 0 {
			fmt.Printf("  Gestartet: %s\n", string(content))
		}

		// Prüfe ob es auch einen Crash-Report gibt
		if _, err := os.Stat(crashLogFile); err == nil {
			absPath, _ := filepath.Abs(crashLogFile)
			fmt.Printf("  Crash-Report gefunden: %s\n", absPath)
		} else {
			fmt.Println("  Kein Crash-Report → Prozess wurde wahrscheinlich von außen beendet (taskkill/kill)")
		}
		fmt.Println()
	}

	// Neue Sentinel-Datei erstellen
	content := fmt.Sprintf("%s (PID: %d)", time.Now().Format("2006-01-02 15:04:05"), os.Getpid())
	_ = os.WriteFile(sentinelFile, []byte(content), 0600)

	return wasUnclean
}

// StopSentinel entfernt die Sentinel-Datei bei sauberem Exit
// Sollte mit defer in main() oder im Signal-Handler aufgerufen werden
func StopSentinel() {
	_ = os.Remove(sentinelFile)
}

// CleanupOnSignal richtet Signal-Handler ein für sauberes Beenden
// Gibt einen Channel zurück der bei Signal geschlossen wird
func CleanupOnSignal() chan struct{} {
	done := make(chan struct{})

	sigChan := make(chan os.Signal, 1)
	// Hinweis: signal.Notify ist in os/signal, muss importiert werden
	// Dies wird in main.go gemacht

	go func() {
		<-sigChan
		StopSentinel()
		close(done)
	}()

	return done
}
