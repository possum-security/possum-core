package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/diff"
	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/spf13/cobra"
)

var (
	diffFormat     string
	diffOutputFile string
)

var diffCmd = &cobra.Command{
	Use:   "diff <baseline.json> <head.json>",
	Short: "Compare two scan result files to identify regressions and delta waste",
	Long: `Compare two JSON scan reports (such as a PR branch vs main branch) to detect
new security issues, resolved findings, and net cloud waste changes.`,
	Args: cobra.ExactArgs(2),
	RunE: runDiff,
}

func runDiff(cmd *cobra.Command, args []string) error {
	baselinePath := args[0]
	headPath := args[1]

	baseline, err := diff.LoadResultsFromFile(baselinePath)
	if err != nil {
		return fmt.Errorf("failed to read baseline: %w", err)
	}

	head, err := diff.LoadResultsFromFile(headPath)
	if err != nil {
		return fmt.Errorf("failed to read head: %w", err)
	}

	report := diff.Compare(baseline, head)

	outWriter := os.Stdout
	if diffOutputFile != "" {
		f, err := os.Create(diffOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", diffOutputFile, err)
		}
		defer f.Close()
		outWriter = f
	}

	switch strings.ToLower(diffFormat) {
	case "markdown-pr", "markdown", "md":
		return report.FormatMarkdownPR(outWriter)
	case "json":
		enc := json.NewEncoder(outWriter)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	default:
		// Terminal summary table
		fmt.Fprintf(outWriter, "=== Possum Scan Diff Summary ===\n")
		fmt.Fprintf(outWriter, "Baseline: %d findings ($%.2f/mo waste)\n", report.BaselineCount, report.BaselineWaste)
		fmt.Fprintf(outWriter, "Head:     %d findings ($%.2f/mo waste)\n", report.HeadCount, report.HeadWaste)
		fmt.Fprintf(outWriter, "New Findings:      %d\n", len(report.NewFindings))
		fmt.Fprintf(outWriter, "Resolved Findings: %d\n", len(report.ResolvedFindings))
		fmt.Fprintf(outWriter, "Net Waste Delta:   $%.2f/mo\n\n", report.NetWasteDelta)

		if len(report.NewFindings) > 0 {
			fmt.Fprintln(outWriter, "🚨 NEW FINDINGS:")
			for _, r := range report.NewFindings {
				fmt.Fprintf(outWriter, "  [%s] %s (%s) - %s\n", r.Severity, r.RuleID, r.ResourceID, r.Title)
			}
			fmt.Fprintln(outWriter)
		}

		if len(report.ResolvedFindings) > 0 {
			fmt.Fprintln(outWriter, "✅ RESOLVED FINDINGS:")
			for _, r := range report.ResolvedFindings {
				fmt.Fprintf(outWriter, "  [%s] %s (%s)\n", r.Severity, r.RuleID, r.ResourceID)
			}
			fmt.Fprintln(outWriter)
		}

		if len(report.NewFindings) > 0 {
			return model.ErrThresholdExceeded
		}
		return nil
	}
}

func init() {
	diffCmd.Flags().StringVarP(&diffFormat, "format", "f", "markdown-pr", "Output format: markdown-pr, table, json")
	diffCmd.Flags().StringVarP(&diffOutputFile, "output", "o", "", "Write output to file path")
	rootCmd.AddCommand(diffCmd)
}
