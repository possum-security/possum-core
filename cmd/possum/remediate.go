package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/output"
	"github.com/possum-security/possum-core/pkg/remediation"
	"github.com/spf13/cobra"
)

var (
	remediateDryRun     bool
	remediateConfirm    bool
	remediateExportFile string
)

var remediateCmd = &cobra.Command{
	Use:   "remediate [findings.json]",
	Short: "Generate an automated, safe bash script to patch detected vulnerabilities",
	Long: `Generate executable shell remediation scripts from Possum scan findings.
Includes safe dry-run modes, confirmation prompts, and explicit command review.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRemediate,
}

func runRemediate(cmd *cobra.Command, args []string) error {
	var results []model.ScanResult
	var err error

	if len(args) > 0 {
		results, err = output.LoadResultsFromFile(args[0])
		if err != nil {
			return fmt.Errorf("failed to load findings file: %w", err)
		}
	} else {
		// Read from stdin if piped
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			results, err = output.LoadResults(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to parse findings from stdin: %w", err)
			}
		} else {
			return fmt.Errorf("please provide a findings JSON file or pipe JSON via stdin (e.g. 'possum scan aws -f json | possum remediate')")
		}
	}

	gen := remediation.NewGenerator()
	actions := gen.ExtractActions(results)

	if len(actions) == 0 {
		fmt.Fprintln(os.Stderr, "ℹ️ No remediable findings detected in input.")
		return nil
	}

	outWriter := os.Stdout
	if remediateExportFile != "" {
		f, err := os.OpenFile(filepath.Clean(remediateExportFile), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to create script file %s: %w", remediateExportFile, err)
		}
		defer f.Close()
		outWriter = f
	}

	opts := remediation.ScriptOptions{
		DryRun:      remediateDryRun,
		ConfirmEach: remediateConfirm,
	}

	if err := gen.GenerateScript(outWriter, actions, opts); err != nil {
		return fmt.Errorf("failed to generate remediation script: %w", err)
	}

	if remediateExportFile != "" {
		fmt.Fprintf(os.Stderr, "✅ Remediation script with %d action(s) exported to %s\n", len(actions), remediateExportFile)
	}

	return nil
}

func init() {
	remediateCmd.Flags().BoolVar(&remediateDryRun, "dry-run", true, "Generate script with DRY_RUN=true to simulate execution safely")
	remediateCmd.Flags().BoolVar(&remediateConfirm, "confirm", true, "Include interactive confirmation prompts before executing each command")
	remediateCmd.Flags().StringVarP(&remediateExportFile, "export", "e", "", "Write executable script to specified file path (e.g. fix.sh)")
	rootCmd.AddCommand(remediateCmd)
}
