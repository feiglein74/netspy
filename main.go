package main

import (
	"netspy/cmd"
	"netspy/pkg/crash"
)

func main() {
	// Globaler Crash-Handler - fängt alle unbehandelten Panics ab
	// und schreibt einen detaillierten Report in netspy_crash.log
	defer crash.Handler()

	cmd.Execute()
}
