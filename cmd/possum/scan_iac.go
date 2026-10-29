package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/output"
	"github.com/amirmahdy/possum-core/pkg/scanner/iac"
	"github.com/spf13/cobra"
)

var (
	iacFormat     string
	iacOutputFile string
	iacFailOn     string
)

var scanIaCCmd = &cobra.Command{
	Use:   "iac <directory-or-tfplan.json>",
	Short: "Scan Infrastructure-as-Code (Terraform files or JSON plan) before deployment",
	Long: `Shift-left cloud security and FinOps scanning: evaluates Terraform files (.tf)
or compiled Terraform execution plan files (generated via 'terraform show -json tfplan')
for security misconfigurations, open attack surfaces, and projected cost waste.`,
	Args: cobra.ExactArgs(1),
	RunE: runScanIaC,
}

func runScanIaC(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	scanner := iac.NewScanner()
	results, err := scanner.ScanPath(targetPath)
	if err != nil {
		return fmt.Errorf("failed to scan IaC path %s: %w", targetPath, err)
	}

	var outWriter io.Writer = os.Stdout
	if iacOutputFile != "" {
		f, err := os.Create(iacOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", iacOutputFile, err)
		}
		defer f.Close()
		outWriter = f
	}

	var formatter output.Formatter
	switch strings.ToLower(iacFormat) {
	case "json":
		formatter = output.NewJSONFormatter(true)
	case "sarif":
		formatter = output.NewSARIFFormatter()
	case "junit":
		formatter = output.NewJUnitFormatter()
	case "mermaid":
		formatter = output.NewMermaidFormatter()
	case "html":
		formatter = output.NewHTMLFormatter()
	default:
		formatter = output.NewTableFormatter("iac", noColor)
	}

	if err := formatter.Format(outWriter, results); err != nil {
		return fmt.Errorf("failed to format IaC scan results: %w", err)
	}

	if iacFailOn != "" {
		failThreshold := model.Severity(strings.ToUpper(iacFailOn))
		for _, r := range results {
			if r.Status == model.StatusFail && r.MeetsThreshold(failThreshold) {
				return model.ErrThresholdExceeded
			}
		}
	}

	return nil
}

func init() {
	scanIaCCmd.Flags().StringVarP(&iacFormat, "format", "f", "table", "Output format (table, json, sarif, junit, mermaid, html)")
	scanIaCCmd.Flags().StringVarP(&iacOutputFile, "output", "o", "", "Write output to specified file path")
	scanIaCCmd.Flags().StringVar(&iacFailOn, "fail-on", "", "Fail with exit code 1 if findings meet or exceed severity (CRITICAL, HIGH, MEDIUM, LOW)")

	scanCmd.AddCommand(scanIaCCmd)
}
