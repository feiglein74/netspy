package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Shell-Completion generieren",
	Long: `Generiert Shell-Completion-Scripts für netspy.

Bash:
  $ source <(netspy completion bash)
  # Oder permanent in ~/.bashrc:
  $ netspy completion bash >> ~/.bashrc

Zsh:
  $ source <(netspy completion zsh)
  # Oder permanent:
  $ netspy completion zsh > "${fpath[1]}/_netspy"

Fish:
  $ netspy completion fish | source
  # Oder permanent:
  $ netspy completion fish > ~/.config/fish/completions/netspy.fish

PowerShell:
  PS> netspy completion powershell | Out-String | Invoke-Expression
  # Oder permanent in $PROFILE:
  PS> netspy completion powershell >> $PROFILE
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
