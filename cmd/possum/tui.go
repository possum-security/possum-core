package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui [findings.json]",
	Short: "Launch interactive terminal UI to browse and inspect findings",
	Long: `Interactive keyboard-driven console inspector for scan findings.
Allows rapid severity filtering, scrolling, and deep-dive inspection of remediation steps.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTUI,
}

func runTUI(cmd *cobra.Command, args []string) error {
	var results []model.ScanResult

	if len(args) > 0 {
		f, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open findings file: %w", err)
		}
		defer f.Close()

		if err := json.NewDecoder(f).Decode(&results); err != nil {
			return fmt.Errorf("failed to decode findings JSON: %w", err)
		}
	} else {
		// Read from stdin if piped
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			if err := json.NewDecoder(os.Stdin).Decode(&results); err != nil {
				return fmt.Errorf("failed to decode findings from stdin: %w", err)
			}
		} else {
			return fmt.Errorf("please provide a findings JSON file or pipe JSON via stdin (e.g. 'possum tui results.json')")
		}
	}

	model := tui.NewModel(results)
	return model.RunInteractive(os.Stdin, os.Stdout)
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
