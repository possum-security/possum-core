package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/spf13/cobra"
)

var (
	noColor    bool
	debug      bool
	configFile string
)

var rootCmd = &cobra.Command{
	Use:   "possum",
	Short: "Possum: Developer-First Cloud Security & FinOps Waste Scanner",
	Long: `Possum is a fast, zero-dependency FinSecOps scanner that correlates
security misconfigurations and cloud waste into an actionable developer workflow.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable ANSI colored terminal output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable verbose debug logging")
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Path to Possum configuration file (default: ./.possum.yaml or ~/.config/possum/config.yaml)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(cloudCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		if errors.Is(err, model.ErrThresholdExceeded) {
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
