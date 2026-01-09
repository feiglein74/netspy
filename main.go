package main

import (
	"netspy/cmd"
	"netspy/pkg/crash"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Globaler Crash-Handler - fängt alle unbehandelten Panics ab
	// und schreibt einen detaillierten Report in netspy_crash.log
	defer crash.Handler()

	// Sentinel starten - prüft auf unsaubere vorherige Beendigung
	// und erstellt Marker-Datei für diesen Lauf
	crash.StartSentinel()

	// Sentinel bei sauberem Exit entfernen
	defer crash.StopSentinel()

	// Signal-Handler für sauberes Beenden (Ctrl+C, kill)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		crash.StopSentinel()
		os.Exit(0)
	}()

	cmd.Execute()
}
