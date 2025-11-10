package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

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
}

// Execute fügt alle Unterbefehle zum Root-Befehl hinzu und setzt Flags entsprechend
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Globale Flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.netspy.yaml)")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("quiet", false, "quiet output")

	// Flags an Viper binden
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
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
