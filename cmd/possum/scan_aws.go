package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/amirmahdy/possum-core/pkg/cloudclient"
	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/output"
	"github.com/amirmahdy/possum-core/pkg/scanner"
	scanneraws "github.com/amirmahdy/possum-core/pkg/scanner/aws"
	"github.com/spf13/cobra"
)

var (
	awsRegion       string
	awsProfile      string
	awsRoleARN      string
	awsServices     string
	awsChecks       string
	awsFailOn       string
	awsFormat       string
	awsOutputFile   string
	awsCloudSync    bool
	awsAPIKey       string
	awsAPIURL       string
	awsAccountID    string
	awsMaxWorkers   int
	awsScanTimeout  time.Duration
)

var scanAWSCmd = &cobra.Command{
	Use:   "aws",
	Short: "Scan AWS cloud infrastructure for misconfigurations and FinOps waste",
	RunE:  runScanAWS,
}

func runScanAWS(cmd *cobra.Command, args []string) error {
	region := awsRegion
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
		if region == "" {
			region = os.Getenv("AWS_REGION")
		}
		if region == "" {
			region = "us-east-1"
		}
	}

	cfg, err := scanneraws.NewClientConfig(cmd.Context(), scanneraws.ClientOptions{
		Region:    region,
		Profile:   awsProfile,
		RoleARN:   awsRoleARN,
		AccountID: awsAccountID,
	})
	if err != nil {
		return fmt.Errorf("failed to configure AWS client: %w", err)
	}

	allScanners := scanneraws.GetAllScanners(cfg)

	// Filter by service if specified
	var targetScanners []scanner.Scanner
	var filterServices []string
	if awsServices != "" {
		for _, s := range strings.Split(awsServices, ",") {
			filterServices = append(filterServices, strings.TrimSpace(strings.ToLower(s)))
		}
	}

	if len(filterServices) > 0 {
		for _, sc := range allScanners {
			scName := strings.ToLower(sc.Name())
			matched := false
			for _, svc := range filterServices {
				if strings.Contains(scName, svc) {
					matched = true
					break
				}
			}
			if matched {
				targetScanners = append(targetScanners, sc)
			}
		}
	} else {
		targetScanners = allScanners
	}

	// Prepare check filters
	var filterChecks []string
	if awsChecks != "" {
		for _, chk := range strings.Split(awsChecks, ",") {
			filterChecks = append(filterChecks, strings.TrimSpace(chk))
		}
	}

	engine := scanner.NewEngine(scanner.EngineConfig{
		MaxWorkers: awsMaxWorkers,
		Timeout:    awsScanTimeout,
	})

	filterOpts := model.FilterOptions{
		Checks: filterChecks,
	}

	results, err := engine.Execute(cmd.Context(), targetScanners, filterOpts)
	if err != nil {
		return fmt.Errorf("scan execution encountered error: %w", err)
	}

	// Determine output writer
	var outWriter io.Writer = os.Stdout
	if awsOutputFile != "" {
		f, err := os.Create(awsOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", awsOutputFile, err)
		}
		defer f.Close()
		outWriter = f
	}

	// Format results
	var formatter output.Formatter
	switch strings.ToLower(awsFormat) {
	case "json":
		formatter = output.NewJSONFormatter(true)
	case "sarif":
		formatter = output.NewSARIFFormatter()
	case "junit":
		formatter = output.NewJUnitFormatter()
	default:
		formatter = output.NewTableFormatter(region, noColor)
	}

	if err := formatter.Format(outWriter, results); err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

	// Upload to SecaaS platform if --cloud requested
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
			fmt.Fprintln(os.Stderr, "⚠️ Warning: --cloud specified but POSSUM_API_KEY is not set. Run 'possum cloud login' or provide --api-key.")
		} else {
			client := cloudclient.NewClient(apiURL, apiKey)
			bundle := cloudclient.BuildBundle(accountID, "", results)
			if err := client.UploadBundle(context.Background(), bundle); err != nil {
				fmt.Fprintf(os.Stderr, "⚠️ Cloud synchronization error: %v\n", err)
			} else {
				fmt.Printf("☁️ Scan results successfully synchronized with Possum Cloud (%s).\n", apiURL)
			}
		}
	}

	// Check --fail-on threshold for CI/CD exit code
	if awsFailOn != "" {
		failThreshold := model.Severity(strings.ToUpper(awsFailOn))
		for _, r := range results {
			if r.Status == model.StatusFail && r.MeetsThreshold(failThreshold) {
				// Findings meet or exceed threshold: exit code 1
				os.Exit(1)
			}
		}
	}

	return nil
}

func init() {
	scanAWSCmd.Flags().StringVar(&awsRegion, "region", "", "AWS region to scan (default: AWS_DEFAULT_REGION or us-east-1)")
	scanAWSCmd.Flags().StringVar(&awsProfile, "profile", "", "AWS named credentials profile")
	scanAWSCmd.Flags().StringVar(&awsRoleARN, "role-arn", "", "Optional IAM Role ARN to assume for scanning")
	scanAWSCmd.Flags().StringVar(&awsServices, "services", "", "Comma-separated AWS services to scan (e.g. s3,iam,ec2)")
	scanAWSCmd.Flags().StringVar(&awsChecks, "checks", "", "Comma-separated check IDs to evaluate")
	scanAWSCmd.Flags().StringVar(&awsFailOn, "fail-on", "", "Fail with exit code 1 if findings meet or exceed severity (CRITICAL, HIGH, MEDIUM, LOW)")
	scanAWSCmd.Flags().StringVarP(&awsFormat, "format", "f", "table", "Output format (table, json, sarif, junit)")
	scanAWSCmd.Flags().StringVarP(&awsOutputFile, "output", "o", "", "Write scan output to specified file path")
	scanAWSCmd.Flags().BoolVar(&awsCloudSync, "cloud", false, "Synchronize scan bundle to Possum SecaaS Platform")
	scanAWSCmd.Flags().StringVar(&awsAPIKey, "api-key", "", "Possum SecaaS API key (or POSSUM_API_KEY env)")
	scanAWSCmd.Flags().StringVar(&awsAPIURL, "api-url", "", "Possum SecaaS API URL (default: https://app.possum.io)")
	scanAWSCmd.Flags().StringVar(&awsAccountID, "account-id", "", "Cloud account identifier")
	scanAWSCmd.Flags().IntVar(&awsMaxWorkers, "workers", 10, "Maximum concurrent scanner goroutines")
	scanAWSCmd.Flags().DurationVar(&awsScanTimeout, "timeout", 10*time.Minute, "Maximum scan execution timeout")
}
