package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/possum-security/possum-core/pkg/rules"
	"github.com/spf13/cobra"
)

var (
	rulesFilterService  string
	rulesFilterSeverity string
	rulesFilterSearch   string
	rulesOutputFormat   string
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Explore the embedded cloud security rules catalog",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available security checks and misconfiguration rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		catalog := rules.GetDefaultCatalog()
		checks := catalog.ListChecks(rules.CheckFilter{
			ServiceName: rulesFilterService,
			Severity:    rulesFilterSeverity,
			Search:      rulesFilterSearch,
		})

		if rulesOutputFormat == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(checks)
		}

		fmt.Printf("Displaying %d rules from embedded catalog:\n", len(checks))
		fmt.Printf("%-38s %-12s %-10s %s\n", "CHECK ID", "SERVICE", "SEVERITY", "TITLE")
		fmt.Println(strings.Repeat("─", 90))

		for _, chk := range checks {
			title := chk.CheckTitle
			if len(title) > 38 {
				title = title[:35] + "..."
			}
			fmt.Printf("%-38s %-12s %-10s %s\n",
				chk.CheckID, chk.ServiceName, chk.Severity, title)
		}

		return nil
	},
}

var rulesGetCmd = &cobra.Command{
	Use:   "get <rule_id>",
	Short: "Get comprehensive metadata and remediation for a specific check",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ruleID := args[0]
		catalog := rules.GetDefaultCatalog()
		chk, ok := catalog.GetCheck(ruleID)
		if !ok {
			return fmt.Errorf("rule %q not found in embedded catalog", ruleID)
		}

		if rulesOutputFormat == "json" {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(chk)
		}

		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Printf("Rule ID:      %s\n", chk.CheckID)
		fmt.Printf("Title:        %s\n", chk.CheckTitle)
		fmt.Printf("Service:      %s\n", chk.ServiceName)
		fmt.Printf("Severity:     %s\n", chk.Severity)
		fmt.Printf("Resource:     %s\n", chk.ResourceType)
		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Printf("Description:\n%s\n\n", chk.Description)
		if chk.Risk != "" {
			fmt.Printf("Risk:\n%s\n\n", chk.Risk)
		}
		if chk.Remediation.Recommendation.Text != "" {
			fmt.Printf("Recommendation:\n%s\n", chk.Remediation.Recommendation.Text)
			if chk.Remediation.Recommendation.Url != "" {
				fmt.Printf("URL: %s\n", chk.Remediation.Recommendation.Url)
			}
			fmt.Println()
		}
		if chk.Remediation.Code.Terraform != "" {
			fmt.Println("Terraform Remediation:")
			fmt.Println(chk.Remediation.Code.Terraform)
			fmt.Println()
		}
		if chk.Remediation.Code.CLI != "" {
			fmt.Println("AWS CLI Remediation:")
			fmt.Println(chk.Remediation.Code.CLI)
		}
		fmt.Println("─────────────────────────────────────────────────────────────────")
		return nil
	},
}

func init() {
	rulesListCmd.Flags().StringVar(&rulesFilterService, "service", "", "Filter checks by AWS service name (e.g. s3, iam, ec2)")
	rulesListCmd.Flags().StringVar(&rulesFilterSeverity, "severity", "", "Filter checks by severity (CRITICAL, HIGH, MEDIUM, LOW)")
	rulesListCmd.Flags().StringVar(&rulesFilterSearch, "search", "", "Text search in check titles and descriptions")
	rulesListCmd.Flags().StringVarP(&rulesOutputFormat, "format", "f", "table", "Output format (table, json)")

	rulesGetCmd.Flags().StringVarP(&rulesOutputFormat, "format", "f", "table", "Output format (table, json)")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesGetCmd)
}
