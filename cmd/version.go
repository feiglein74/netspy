package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version enthält die aktuelle Version von NetSpy
// Wird beim Kompilieren via ldflags gesetzt
var Version = "0.1.0"

// BuildDate wird beim Kompilieren gesetzt (optional, via ldflags)
var BuildDate string = "unbekannt"

// GitCommit wird beim Kompilieren gesetzt (optional, via ldflags)
var GitCommit string = "unbekannt"

// versionCmd repräsentiert den version-Befehl
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Zeigt die Version von NetSpy an",
	Long:  `Gibt Versionsinformationen über NetSpy aus, einschließlich Version, Build-Datum und Git-Commit.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("NetSpy v%s\n", Version)
		if BuildDate != "unbekannt" {
			fmt.Printf("Build-Datum: %s\n", BuildDate)
		}
		if GitCommit != "unbekannt" {
			fmt.Printf("Git-Commit: %s\n", GitCommit)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
