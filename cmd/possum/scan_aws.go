package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/possum-security/possum-core/pkg/cloudclient"
	"github.com/possum-security/possum-core/pkg/config"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/output"
	"github.com/possum-security/possum-core/pkg/rules"
	"github.com/possum-security/possum-core/pkg/scanner"
	scanneraws "github.com/possum-security/possum-core/pkg/scanner/aws"
	"github.com/possum-security/possum-core/pkg/suppression"
	"github.com/spf13/cobra"
)

var (
	awsRegion       string
	awsRegions      string
	awsAllRegions   bool
	awsProfile      string
	awsRoleARN      string
	awsServices     string
	awsChecks       string
	awsCompliance   string
	awsFailOn       string
	awsFailOnError  bool
	awsFormat       string
	awsOutputFile   string
	awsCloudSync    bool
	awsAPIKey       string
	awsAPIURL       string
	awsAccountID    string
	awsMaxWorkers   int
	awsScanTimeout  time.Duration
	awsMode         string
	awsOrganization bool
	awsIgnoreFile   string
)

var scanAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Scan AWS cloud infrastructure for misconfigurations and FinOps waste",
	Long: `Possum AWS Scanner: Fast, agentless inspection of AWS infrastructure
for security misconfigurations, compliance benchmarks, and cloud cost waste.`,
	RunE: runScanAWS,
}

func validateScanFormat(format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "table", "json", "sarif", "junit", "csv", "mermaid", "html":
		return nil
	default:
		return fmt.Errorf("invalid output format %q (must be one of: table, json, sarif, junit, csv, mermaid, html)", format)
	}
}

func runScanAWS(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	// 1. Discover and merge configuration file (.possum.yaml)
	fileCfg, cfgPath, err := config.Discover(configFile)
	if err != nil {
		return fmt.Errorf("invalid config file: %w", err)
	}
	if fileCfg != nil && debug {
		fmt.Fprintf(os.Stderr, "ℹ️ Loaded configuration from %s\n", cfgPath)
	}
	applyConfigFileDefaults(fileCfg, cmd)

	// 1b. Validate CLI/config options before making network/AWS calls
	var failThreshold model.Severity
	if awsFailOn != "" {
		sev, err := model.ParseSeverity(awsFailOn)
		if err != nil {
			return err
		}
		failThreshold = sev
	}
	if _, err := model.ValidateScanMode(awsMode); err != nil {
		return err
	}
	if err := validateScanFormat(awsFormat); err != nil {
		return err
	}

	ecrRetentionDays := 180
	flagUntaggedECR := true
	if fileCfg != nil {
		if fileCfg.FinOps.ECRRetentionDays > 0 {
			ecrRetentionDays = fileCfg.FinOps.ECRRetentionDays
		}
		flagUntaggedECR = fileCfg.FinOps.FlagUntaggedECR
	}

	// 2. Resolve primary AWS region
	primaryRegion := awsRegion
	if primaryRegion == "" {
		primaryRegion = os.Getenv("AWS_DEFAULT_REGION")
		if primaryRegion == "" {
			primaryRegion = os.Getenv("AWS_REGION")
		}
		if primaryRegion == "" {
			primaryRegion = "us-east-1"
		}
	}

	// 3. Initialize base AWS SDK config
	baseCfg, err := scanneraws.NewClientConfig(ctx, scanneraws.ClientOptions{
		Region:    primaryRegion,
		Profile:   awsProfile,
		RoleARN:   awsRoleARN,
		AccountID: awsAccountID,
	})
	if err != nil {
		return fmt.Errorf("failed to configure AWS client: %w", err)
	}

	// 4. Resolve Target AWS Accounts (Single Account vs AWS Organizations)
	type AccountTarget struct {
		ID   string
		Name string
		Cfg  aws.Config
	}
	var targetAccounts []AccountTarget

	if awsOrganization {
		accounts, err := scanneraws.DiscoverOrganizationAccounts(ctx, baseCfg)
		if err != nil {
			return fmt.Errorf("AWS Organizations auto-discovery failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "🏢 Discovered %d active AWS organization accounts\n", len(accounts))
		roleToAssume := awsRoleARN
		if roleToAssume == "" {
			roleToAssume = "OrganizationAccountAccessRole"
		}
		for _, acct := range accounts {
			acctCfg, err := scanneraws.CreateCrossAccountConfig(ctx, baseCfg, acct.ID, roleToAssume, "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Failed to assume role in account %s (%s): %v\n", acct.Name, acct.ID, err)
				continue
			}
			targetAccounts = append(targetAccounts, AccountTarget{
				ID:   acct.ID,
				Name: acct.Name,
				Cfg:  acctCfg,
			})
		}
		if len(targetAccounts) == 0 {
			return fmt.Errorf("no organization accounts could be accessed")
		}
	} else {
		if awsAccountID == "" {
			if ident, err := sts.NewFromConfig(baseCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil && ident != nil && ident.Account != nil {
				awsAccountID = aws.ToString(ident.Account)
				if updatedCfg, cfgErr := scanneraws.NewClientConfig(ctx, scanneraws.ClientOptions{
					Region:    primaryRegion,
					Profile:   awsProfile,
					RoleARN:   awsRoleARN,
					AccountID: awsAccountID,
				}); cfgErr == nil {
					baseCfg = updatedCfg
				}
			}
		}
		targetAccounts = append(targetAccounts, AccountTarget{
			ID:   awsAccountID,
			Name: "Primary",
			Cfg:  baseCfg,
		})
	}

	// 5. Resolve Target Scanning Regions
	var targetRegions []string
	if awsAllRegions {
		discovered, err := scanneraws.DiscoverEnabledRegions(ctx, baseCfg)
		if err != nil {
			return fmt.Errorf("failed to discover enabled regions: %w", err)
		}
		targetRegions = discovered
		if debug {
			fmt.Fprintf(os.Stderr, "🌐 Auto-discovered %d active regions: %s\n", len(targetRegions), strings.Join(targetRegions, ", "))
		}
	} else if awsRegions != "" {
		targetRegions = scanneraws.ParseRegionsList(awsRegions)
	} else {
		targetRegions = []string{primaryRegion}
	}

	// 6. Resolve Check Filters (Compliance + Explicit Checks)
	var filterChecks []string
	if awsCompliance != "" {
		if catalog, err := rules.NewRuleCatalog(); err == nil && catalog != nil {
			complianceChecks := catalog.GetChecksByFramework(awsCompliance)
			if len(complianceChecks) > 0 {
				filterChecks = append(filterChecks, complianceChecks...)
				if debug {
					fmt.Fprintf(os.Stderr, "📋 Applied compliance framework '%s' (%d checks)\n", awsCompliance, len(complianceChecks))
				}
			} else {
				fmt.Fprintf(os.Stderr, "⚠️ Warning: Compliance framework '%s' not found in catalog\n", awsCompliance)
			}
		}
	}
	if awsChecks != "" {
		for _, chk := range strings.Split(awsChecks, ",") {
			filterChecks = append(filterChecks, strings.TrimSpace(chk))
		}
	}

	var filterServices []string
	if awsServices != "" {
		for _, s := range strings.Split(awsServices, ",") {
			filterServices = append(filterServices, strings.TrimSpace(strings.ToLower(s)))
		}
	}

	// 7. Load Suppressions (.possumignore)
	suppLoader := suppression.NewLoader()
	var suppressions []suppression.Suppression
	if awsIgnoreFile != "" {
		if loaded, err := suppLoader.LoadFile(awsIgnoreFile); err == nil {
			suppressions = loaded
		} else {
			fmt.Fprintf(os.Stderr, "⚠️ Warning: Could not read ignore file %s: %v\n", awsIgnoreFile, err)
		}
	} else {
		if loaded, _, err := suppLoader.DiscoverAndLoad("."); err == nil && len(loaded) > 0 {
			suppressions = loaded
			if debug {
				fmt.Fprintf(os.Stderr, "🛡️ Loaded %d active rule suppressions\n", len(suppressions))
			}
		}
	}

	// 8. Execute Scans across Accounts and Regions
	var allResults []model.ScanResult
	var allErrors []error
	var reportMu sync.Mutex

	scanEngine := scanner.NewEngine(scanner.EngineConfig{
		MaxWorkers: awsMaxWorkers,
		Timeout:    awsScanTimeout,
	})

	for _, acct := range targetAccounts {
		// Global Scanners run once per account
		globalScanners := scanneraws.GetGlobalScanners(acct.Cfg)
		filteredGlobals := preFilterScanners(globalScanners, filterServices, filterChecks, awsMode)

		if len(filteredGlobals) > 0 {
			filterOpts := model.FilterOptions{Checks: filterChecks}
			rep, _ := scanEngine.ExecuteWithReport(ctx, filteredGlobals, filterOpts)
			for i := range rep.Results {
				if rep.Results[i].AccountID == "" {
					rep.Results[i].AccountID = acct.ID
				}
				rep.Results[i].Region = scanneraws.NormalizeRegion(rep.Results[i].Region, "global")
			}
			reportMu.Lock()
			allResults = append(allResults, rep.Results...)
			allErrors = append(allErrors, rep.Errors...)
			reportMu.Unlock()
		}

		// Regional Scanners run per target region
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4) // max 4 concurrent regional scans

		for _, reg := range targetRegions {
			wg.Add(1)
			go func(regionName string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				regCfg := acct.Cfg
				regCfg.Region = regionName

				regScanners := scanneraws.GetRegionalScanners(regCfg, ecrRetentionDays, flagUntaggedECR)
				filteredRegional := preFilterScanners(regScanners, filterServices, filterChecks, awsMode)

				if len(filteredRegional) == 0 {
					return
				}

				filterOpts := model.FilterOptions{Checks: filterChecks}
				rep, _ := scanEngine.ExecuteWithReport(ctx, filteredRegional, filterOpts)
				for i := range rep.Results {
					if rep.Results[i].AccountID == "" {
						rep.Results[i].AccountID = acct.ID
					}
					if rep.Results[i].Region == "" || strings.EqualFold(rep.Results[i].Region, "regional") || strings.EqualFold(rep.Results[i].Region, "global") {
						rep.Results[i].Region = regionName
					} else {
						rep.Results[i].Region = scanneraws.NormalizeRegion(rep.Results[i].Region, regionName)
					}
				}
				reportMu.Lock()
				allResults = append(allResults, rep.Results...)
				allErrors = append(allErrors, rep.Errors...)
				reportMu.Unlock()
			}(reg)
		}
		wg.Wait()
	}

	// 9. Standardize ARNs & Apply Suppressions
	allResults = scanneraws.StandardizeResultsARN(allResults, awsAccountID, primaryRegion)
	allResults = suppression.ApplySuppressions(allResults, suppressions)

	// 10. Surface Scanner Errors
	if len(allErrors) > 0 {
		fmt.Fprintf(os.Stderr, "⚠️ Warning: %d scanner execution error(s) occurred:\n", len(allErrors))
		for _, err := range allErrors {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
	}

	// 11. Format & Export Results
	var outWriter io.Writer = os.Stdout
	if awsOutputFile != "" {
		f, err := os.Create(awsOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", awsOutputFile, err)
		}
		defer f.Close()
		outWriter = f
	}

	var formatter output.Formatter
	switch strings.ToLower(strings.TrimSpace(awsFormat)) {
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
		formatter = output.NewTableFormatter(primaryRegion, noColor)
	}

	if err := formatter.Format(outWriter, allResults); err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

	// 12. Cloud Sync if requested
	if awsCloudSync {
		apiKey := awsAPIKey
		apiURL := awsAPIURL
		accountID := awsAccountID

		if storedCfg, err := cloudclient.LoadConfig(); err == nil && storedCfg != nil {
			if apiKey == "" {
				apiKey = storedCfg.APIKey
			}
			if apiURL == "" && storedCfg.APIURL != "" {
				apiURL = storedCfg.APIURL
			}
			if accountID == "" && storedCfg.AccountID != "" {
				accountID = storedCfg.AccountID
			}
		}

		if apiKey == "" {
			apiKey = os.Getenv("POSSUM_API_KEY")
		}
		if apiURL == "" {
			apiURL = os.Getenv("POSSUM_API_URL")
		}
		if apiURL == "" {
			apiURL = "https://app.possum.io"
		}

		if apiKey == "" {
			fmt.Fprintln(os.Stderr, "⚠️ Warning: --cloud specified but POSSUM_API_KEY is not set.")
		} else {
			client := cloudclient.NewClient(apiURL, apiKey)
			bundle := cloudclient.BuildBundle(accountID, "", allResults)
			if err := client.UploadBundle(context.Background(), bundle); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Cloud synchronization error: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "☁️ Scan results successfully synchronized with Possum Cloud (%s).\n", apiURL)
			}
		}
	}

	// 12b. Return scanner execution error after report export and cloud sync if --fail-on-error is enabled
	if len(allErrors) > 0 && awsFailOnError {
		return fmt.Errorf("%w: %d scanners failed", model.ErrScannerExecution, len(allErrors))
	}

	// 13. Check --fail-on Threshold (Clean exit code flow: return model.ErrThresholdExceeded)
	if failThreshold != "" {
		for _, r := range allResults {
			// Suppressed findings do not count toward failure threshold
			if r.Status == model.StatusFail && r.MeetsThreshold(failThreshold) {
				return model.ErrThresholdExceeded
			}
		}
	}

	return nil
}

// preFilterScanners eliminates unnecessary scanners prior to execution (TSK-06).
func preFilterScanners(scanners []scanner.Scanner, services, checks []string, modeStr string) []scanner.Scanner {
	if len(services) == 0 && len(checks) == 0 && modeStr == "" {
		return scanners
	}

	mode := model.ParseScanMode(modeStr)
	checkSet := make(map[string]bool, len(checks))
	for _, c := range checks {
		checkSet[strings.ToLower(c)] = true
	}

	var filtered []scanner.Scanner
	for _, sc := range scanners {
		metaSc, isMeta := sc.(scanner.MetaScanner)
		if !isMeta {
			filtered = append(filtered, sc)
			continue
		}

		meta := metaSc.Meta()

		// Filter by service
		if len(services) > 0 {
			matchedSvc := false
			scSvc := strings.ToLower(meta.Service)
			scName := strings.ToLower(sc.Name())
			for _, s := range services {
				if scSvc == s || strings.Contains(scName, s) {
					matchedSvc = true
					break
				}
			}
			if !matchedSvc {
				continue
			}
		}

		// Filter by checks
		if len(checks) > 0 {
			matchedCheck := false
			for _, cid := range meta.CheckIDs {
				if checkSet[strings.ToLower(cid)] {
					matchedCheck = true
					break
				}
			}
			if !matchedCheck {
				continue
			}
		}

		// Filter by mode
		if mode == model.ScanModeQuick && meta.ExecutionCost == scanner.CostHeavy {
			continue
		}

		filtered = append(filtered, sc)
	}

	return filtered
}

func applyConfigFileDefaults(fileCfg *config.Config, cmd *cobra.Command) {
	if fileCfg == nil {
		return
	}
	s := fileCfg.Scan
	if !cmd.Flags().Changed("fail-on") && s.FailOn != "" {
		awsFailOn = s.FailOn
	}
	if !cmd.Flags().Changed("fail-on-error") && s.FailOnError {
		awsFailOnError = s.FailOnError
	}
	if !cmd.Flags().Changed("all-regions") && s.AllRegions {
		awsAllRegions = s.AllRegions
	}
	if !cmd.Flags().Changed("regions") && len(s.Regions) > 0 {
		awsRegions = strings.Join(s.Regions, ",")
	}
	if !cmd.Flags().Changed("services") && len(s.Services) > 0 {
		awsServices = strings.Join(s.Services, ",")
	}
	if !cmd.Flags().Changed("checks") && len(s.Checks) > 0 {
		awsChecks = strings.Join(s.Checks, ",")
	}
	if !cmd.Flags().Changed("compliance") && s.Compliance != "" {
		awsCompliance = s.Compliance
	}
	if !cmd.Flags().Changed("workers") && s.Workers > 0 {
		awsMaxWorkers = s.Workers
	}
	if !cmd.Flags().Changed("timeout") && s.Timeout != "" {
		awsScanTimeout = s.TimeoutDuration(awsScanTimeout)
	}
	if !cmd.Flags().Changed("mode") && s.Mode != "" {
		awsMode = s.Mode
	}
	if !cmd.Flags().Changed("ignore-file") && s.IgnoreFile != "" {
		awsIgnoreFile = s.IgnoreFile
	}
	if !cmd.Flags().Changed("format") && !cmd.Flags().Changed("output-format") && fileCfg.Output.Format != "" {
		awsFormat = fileCfg.Output.Format
	}
	if !cmd.Flags().Changed("output") && fileCfg.Output.OutputFile != "" {
		awsOutputFile = fileCfg.Output.OutputFile
	}
	if !cmd.Flags().Changed("no-color") && !rootCmd.PersistentFlags().Changed("no-color") && fileCfg.Output.NoColor {
		noColor = fileCfg.Output.NoColor
	}
}

func init() {
	scanAWSCmd.Flags().StringVar(&awsRegion, "region", "", "AWS primary region to scan (default: AWS_DEFAULT_REGION or us-east-1)")
	scanAWSCmd.Flags().StringVar(&awsRegions, "regions", "", "Comma-separated list of target AWS regions (e.g. us-east-1,us-west-2,eu-west-1)")
	scanAWSCmd.Flags().BoolVar(&awsAllRegions, "all-regions", false, "Auto-discover and concurrently scan all enabled AWS regions")
	scanAWSCmd.Flags().StringVar(&awsProfile, "profile", "", "AWS named credentials profile")
	scanAWSCmd.Flags().StringVar(&awsRoleARN, "role-arn", "", "Optional IAM Role ARN to assume for scanning")
	scanAWSCmd.Flags().StringVar(&awsServices, "services", "", "Comma-separated AWS services to scan (e.g. s3,iam,ec2)")
	scanAWSCmd.Flags().StringVar(&awsChecks, "checks", "", "Comma-separated check IDs to evaluate")
	scanAWSCmd.Flags().StringVar(&awsCompliance, "compliance", "", "Compliance framework benchmark filter (e.g. cis-1.4, cis-3.0, pci-dss, soc2)")
	scanAWSCmd.Flags().StringVar(&awsFailOn, "fail-on", "", "Fail with exit code 1 if findings meet or exceed severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	scanAWSCmd.Flags().BoolVar(&awsFailOnError, "fail-on-error", false, "Fail with exit code 2 if any scanner encounters AWS execution errors")
	scanAWSCmd.Flags().StringVarP(&awsFormat, "format", "f", "table", "Output format (table, json, sarif, junit, csv, mermaid, html)")
	scanAWSCmd.Flags().StringVar(&awsFormat, "output-format", "table", "Output format (alias for --format)")
	scanAWSCmd.Flags().StringVarP(&awsOutputFile, "output", "o", "", "Write scan output to specified file path")
	scanAWSCmd.Flags().BoolVar(&awsCloudSync, "cloud", false, "Synchronize scan bundle to Possum SecaaS Platform")
	scanAWSCmd.Flags().StringVar(&awsAPIKey, "api-key", "", "Possum SecaaS API key (or POSSUM_API_KEY env)")
	scanAWSCmd.Flags().StringVar(&awsAPIURL, "api-url", "", "Possum SecaaS API URL (default: https://app.possum.io)")
	scanAWSCmd.Flags().StringVar(&awsAccountID, "account-id", "", "Cloud account identifier")
	scanAWSCmd.Flags().IntVar(&awsMaxWorkers, "workers", 10, "Maximum concurrent scanner goroutines")
	scanAWSCmd.Flags().DurationVar(&awsScanTimeout, "timeout", 10*time.Minute, "Maximum scan execution timeout")
	scanAWSCmd.Flags().StringVar(&awsMode, "mode", "standard", "Scan mode: quick (lightweight only), standard (all), deep")
	scanAWSCmd.Flags().BoolVar(&awsOrganization, "organization", false, "Discover and scan all active member accounts across AWS Organization")
	scanAWSCmd.Flags().BoolVar(&awsOrganization, "org", false, "Discover and scan all active member accounts across AWS Organization (alias for --organization)")
	scanAWSCmd.Flags().StringVar(&awsIgnoreFile, "ignore-file", "", "Custom path to .possumignore rule suppression file")
}
