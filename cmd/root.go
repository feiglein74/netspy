package cmd

import (
	"fmt"
	"netspy/pkg/crash"
	"netspy/pkg/discovery"
	"netspy/pkg/output"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var showVersion bool

// FullOutput steuert ob Ausgaben vollständig (true) oder gekürzt (false) angezeigt werden
// Default ist false (responsive Kürzung für Terminal-Breite)
// Mit --full-output wird alles ungekürzt ausgegeben
var FullOutput bool

// rootCmd repräsentiert den Basis-Befehl wenn ohne Unterbefehle aufgerufen
var rootCmd = &cobra.Command{
	Use:   "netspy",
	Short: "Modern network discovery tool",
	Long: `NetSpy is a modern, elegant network discovery tool that helps you
monitor your network infrastructure with style and efficiency.

Features:
- Real-time subnet scanning
- Change detection and alerting
- Multiple discovery methods (ICMP, ARP)
- Beautiful CLI output
- Non-intrusive scanning`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// FullOutput-Flag an Output-Package weitergeben
		output.SetFullOutput(FullOutput)
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Wenn --version Flag gesetzt ist, Version anzeigen
		if showVersion {
			fmt.Printf("NetSpy v%s\n", getVersion())
			// return statt os.Exit, damit deferred Cleanup (Sentinel) in main läuft
			return
		}
		// Sonst Standard-Hilfe anzeigen
		_ = cmd.Help() // Ignore error - just displaying help
	},
}

// Execute fügt alle Unterbefehle zum Root-Befehl hinzu und setzt Flags entsprechend
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		// os.Exit überspringt deferred Cleanup in main - Sentinel daher hier entfernen
		crash.StopSentinel()
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig, initLearnedVendors)

	// Globale Flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.netspy.yaml)")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("quiet", false, "quiet output")
	rootCmd.PersistentFlags().BoolVar(&FullOutput, "full-output", false, "show full output without truncation (hostnames, banners, etc.)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "show version information")

	// Flags an Viper binden
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
}

// getVersion gibt die aktuelle Version ohne führendes "v" zurück
// (Release-Builds setzen Version per ldflags auf den Git-Tag, z.B. "v0.2.0")
func getVersion() string {
	return strings.TrimPrefix(Version, "v")
}

// initConfig liest Konfig-Datei und ENV-Variablen ein falls gesetzt
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".netspy")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// initLearnedVendors initialisiert die Learned-Vendors-Datenbank
func initLearnedVendors() {
	// Versuche die Learned-Vendors-Datei zu laden
	// Fehler werden ignoriert, da die Datei beim ersten Start nicht existiert
	_ = discovery.InitLearnedVendors()

	// IEEE-Registry aus dem lokalen Cache laden, Aktualisierung läuft
	// im Hintergrund und blockiert den Start nicht
	discovery.InitVendorRegistry()
}
