package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/possum-security/possum-core/pkg/config"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/output"
	"github.com/possum-security/possum-core/pkg/rules/custom"
	"github.com/possum-security/possum-core/pkg/scanner/iac"
	"github.com/possum-security/possum-core/pkg/suppression"
	"github.com/spf13/cobra"
)

var (
	iacFormat         string
	iacOutputFile     string
	iacFailOn         string
	iacIgnoreFile     string
	iacCustomRulesDir string
	iacMode           string
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
	// 1. Discover and merge configuration file (.possum.yaml)
	fileCfg, cfgPath, err := config.Discover(configFile)
	if err != nil {
		return fmt.Errorf("invalid config file: %w", err)
	}
	if fileCfg != nil && debug {
		fmt.Fprintf(os.Stderr, "ℹ️ Loaded configuration from %s\n", cfgPath)
	}
	applyIaCConfigFileDefaults(fileCfg, cmd)

	// 2. Validate CLI/config flags
	var failThreshold model.Severity
	if iacFailOn != "" {
		sev, err := model.ParseSeverity(iacFailOn)
		if err != nil {
			return err
		}
		failThreshold = sev
	}
	if _, err := model.ValidateScanMode(iacMode); err != nil {
		return err
	}
	if err := validateScanFormat(iacFormat); err != nil {
		return err
	}

	targetPath := args[0]

	// 3. Scan IaC target
	scanner := iac.NewScanner()
	results, err := scanner.ScanPath(targetPath)
	if err != nil {
		return fmt.Errorf("failed to scan IaC path %s: %w", targetPath, err)
	}

	// 4. Load and evaluate custom policy rules (.possum/rules or --custom-rules)
	customFindings, err := evaluateCustomRulesForIaC(targetPath, iacCustomRulesDir)
	if err != nil {
		return err
	}
	results = append(results, customFindings...)

	// 5. Apply .possumignore suppressions
	suppLoader := suppression.NewLoader()
	var suppressions []suppression.Suppression
	if iacIgnoreFile != "" {
		if loaded, err := suppLoader.LoadFile(iacIgnoreFile); err == nil {
			suppressions = loaded
		} else {
			fmt.Fprintf(os.Stderr, "⚠️ Warning: Could not read ignore file %s: %v\n", iacIgnoreFile, err)
		}
	} else {
		if loaded, _, err := suppLoader.DiscoverAndLoad("."); err == nil && len(loaded) > 0 {
			suppressions = loaded
		}
	}
	if len(suppressions) > 0 {
		results = suppression.ApplySuppressions(results, suppressions)
	}

	// 6. Format & Export Results
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
	switch strings.ToLower(strings.TrimSpace(iacFormat)) {
	case "json":
		formatter = output.NewJSONFormatter(true)
	case "sarif":
		formatter = output.NewSARIFFormatter()
	case "junit":
		formatter = output.NewJUnitFormatter()
	case "csv":
		formatter = output.NewCSVFormatter()
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

	if failThreshold != "" {
		for _, r := range results {
			if r.Status == model.StatusFail && r.MeetsThreshold(failThreshold) {
				return model.ErrThresholdExceeded
			}
		}
	}

	return nil
}

func applyIaCConfigFileDefaults(fileCfg *config.Config, cmd *cobra.Command) {
	if fileCfg == nil {
		return
	}
	s := fileCfg.Scan
	if !cmd.Flags().Changed("fail-on") && s.FailOn != "" {
		iacFailOn = s.FailOn
	}
	if !cmd.Flags().Changed("mode") && s.Mode != "" {
		iacMode = s.Mode
	}
	if !cmd.Flags().Changed("ignore-file") && s.IgnoreFile != "" {
		iacIgnoreFile = s.IgnoreFile
	}
	if !cmd.Flags().Changed("format") && !cmd.Flags().Changed("output-format") && fileCfg.Output.Format != "" {
		iacFormat = fileCfg.Output.Format
	}
	if !cmd.Flags().Changed("output") && fileCfg.Output.OutputFile != "" {
		iacOutputFile = fileCfg.Output.OutputFile
	}
	if !cmd.Flags().Changed("no-color") && !rootCmd.PersistentFlags().Changed("no-color") && fileCfg.Output.NoColor {
		noColor = fileCfg.Output.NoColor
	}
}

func evaluateCustomRulesForIaC(targetPath, explicitRulesDir string) ([]model.ScanResult, error) {
	engine := custom.NewEngine()

	if explicitRulesDir != "" {
		fi, err := os.Stat(explicitRulesDir)
		if err != nil {
			return nil, fmt.Errorf("custom rules path %s not found: %w", explicitRulesDir, err)
		}
		if fi.IsDir() {
			if _, err := engine.LoadDirectory(explicitRulesDir); err != nil {
				return nil, fmt.Errorf("failed to load custom rules from %s: %w", explicitRulesDir, err)
			}
		} else {
			f, err := os.Open(explicitRulesDir)
			if err != nil {
				return nil, fmt.Errorf("failed to open custom rule file %s: %w", explicitRulesDir, err)
			}
			defer f.Close()
			rule, err := custom.LoadRule(f)
			if err != nil {
				return nil, err
			}
			engine.AddRule(*rule)
		}
	} else {
		candidateDirs := []string{filepath.Join(".", ".possum", "rules")}
		if targetFi, err := os.Stat(targetPath); err == nil && targetFi.IsDir() {
			targetRules := filepath.Join(targetPath, ".possum", "rules")
			if targetRules != candidateDirs[0] {
				candidateDirs = append(candidateDirs, targetRules)
			}
		}
		for _, d := range candidateDirs {
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				_, _ = engine.LoadDirectory(d)
			}
		}
	}

	if len(engine.Rules()) == 0 {
		return nil, nil
	}

	contexts := extractIaCResourceContexts(targetPath)
	var findings []model.ScanResult
	for _, rctx := range contexts {
		findings = append(findings, engine.EvaluateContext(rctx)...)
	}
	return findings, nil
}

func extractIaCResourceContexts(targetPath string) []custom.ResourceContext {
	fi, err := os.Stat(targetPath)
	if err != nil {
		return nil
	}

	if !fi.IsDir() {
		if strings.EqualFold(filepath.Ext(targetPath), ".json") {
			return extractPlanContexts(targetPath)
		}
		return extractTFFileContexts(targetPath)
	}

	var contexts []custom.ResourceContext
	_ = filepath.Walk(targetPath, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(p), ".tf") {
			contexts = append(contexts, extractTFFileContexts(p)...)
		}
		return nil
	})
	return contexts
}

func extractPlanContexts(path string) []custom.ResourceContext {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var plan iac.TerraformPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil
	}

	var contexts []custom.ResourceContext
	for _, rc := range plan.ResourceChanges {
		if len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == "delete" {
			continue
		}
		props := rc.Change.After
		if props == nil {
			props = rc.Change.Before
		}
		if props == nil {
			props = map[string]interface{}{}
		}
		tags := make(map[string]string)
		if rawTags, ok := props["tags"].(map[string]interface{}); ok {
			for k, v := range rawTags {
				tags[k] = fmt.Sprintf("%v", v)
			}
		}
		contexts = append(contexts, custom.ResourceContext{
			ResourceID:   rc.Address,
			ResourceType: rc.Type,
			Region:       "iac",
			Tags:         tags,
			Properties:   props,
		})
	}
	return contexts
}

func extractTFFileContexts(path string) []custom.ResourceContext {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var contexts []custom.ResourceContext
	lines := strings.Split(string(content), "\n")
	currType := ""
	currName := ""
	var blockLines []string
	inBlock := false
	braceCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "resource ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				currType = strings.Trim(parts[1], "\"")
				currName = strings.Trim(parts[2], "\"")
				inBlock = true
				braceCount = 0
				blockLines = nil
			}
		}

		if inBlock {
			blockLines = append(blockLines, line)
			braceCount += strings.Count(line, "{")
			braceCount -= strings.Count(line, "}")
			if braceCount <= 0 && len(blockLines) > 1 {
				address := fmt.Sprintf("%s.%s", currType, currName)
				props, tags := parseTFBlockPropsAndTags(blockLines)
				contexts = append(contexts, custom.ResourceContext{
					ResourceID:   address,
					ResourceType: currType,
					Region:       "iac",
					Tags:         tags,
					Properties:   props,
				})
				inBlock = false
				currType = ""
				currName = ""
			}
		}
	}

	return contexts
}

func parseTFBlockPropsAndTags(lines []string) (map[string]interface{}, map[string]string) {
	props := make(map[string]interface{})
	tags := make(map[string]string)
	inTags := false

	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if strings.HasPrefix(trimmed, "tags") && strings.Contains(trimmed, "{") {
			inTags = true
			continue
		}
		if inTags {
			if strings.HasPrefix(trimmed, "}") {
				inTags = false
				continue
			}
			if idx := strings.Index(trimmed, "="); idx != -1 {
				k := strings.Trim(strings.TrimSpace(trimmed[:idx]), "\"'")
				v := strings.Trim(strings.TrimSpace(trimmed[idx+1:]), "\"'")
				tags[k] = v
			}
			continue
		}
		if idx := strings.Index(trimmed, "="); idx != -1 && !strings.Contains(trimmed, "{") {
			k := strings.Trim(strings.TrimSpace(trimmed[:idx]), "\"'")
			v := strings.Trim(strings.TrimSpace(trimmed[idx+1:]), "\"'")
			props[k] = v
		}
	}

	return props, tags
}

func init() {
	scanIaCCmd.Flags().StringVarP(&iacFormat, "format", "f", "table", "Output format (table, json, sarif, junit, csv, mermaid, html)")
	scanIaCCmd.Flags().StringVar(&iacFormat, "output-format", "table", "Output format (alias for --format)")
	scanIaCCmd.Flags().StringVarP(&iacOutputFile, "output", "o", "", "Write output to specified file path")
	scanIaCCmd.Flags().StringVar(&iacFailOn, "fail-on", "", "Fail with exit code 1 if findings meet or exceed severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	scanIaCCmd.Flags().StringVar(&iacIgnoreFile, "ignore-file", "", "Custom path to .possumignore rule suppression file")
	scanIaCCmd.Flags().StringVar(&iacCustomRulesDir, "custom-rules", "", "Path to custom YAML policy rules directory or file (default: .possum/rules)")
	scanIaCCmd.Flags().StringVar(&iacMode, "mode", "standard", "Scan mode: quick, standard, deep")

	scanCmd.AddCommand(scanIaCCmd)
}
