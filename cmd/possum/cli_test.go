package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/possum-security/possum-core/pkg/config"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/output"
	"github.com/possum-security/possum-core/pkg/rules"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetCmdFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		f.Changed = false
	})
	for _, sub := range cmd.Commands() {
		resetCmdFlags(sub)
	}
}

func resetFlagsForTest() {
	resetCmdFlags(rootCmd)
	configFile = ""
	noColor = false
	debug = false

	awsRegion = ""
	awsRegions = ""
	awsAllRegions = false
	awsProfile = ""
	awsRoleARN = ""
	awsServices = ""
	awsChecks = ""
	awsCompliance = ""
	awsFailOn = ""
	awsFailOnError = false
	awsFormat = "table"
	awsOutputFile = ""
	awsCloudSync = false
	awsAPIKey = ""
	awsAPIURL = ""
	awsAccountID = ""
	awsMaxWorkers = 10
	awsScanTimeout = 10 * time.Minute
	awsMode = "standard"
	awsOrganization = false
	awsIgnoreFile = ""

	iacFailOn = ""
	iacFormat = "table"
	iacMode = "standard"
	iacOutputFile = ""
	iacIgnoreFile = ""
	iacCustomRulesDir = ""

	diffFormat = "markdown-pr"
	diffOutputFile = ""
	diffFailOn = ""

	rulesFilterService = ""
	rulesFilterSeverity = ""
	rulesFilterSearch = ""
	rulesOutputFormat = "table"

	remediateDryRun = true
	remediateConfirm = true
	remediateExportFile = ""

	cloudLoginKey = ""
	cloudLoginURL = ""
	cloudLoginAccount = ""
}

// ---------------------------------------------------------------------------
// 1. Exit Codes
// ---------------------------------------------------------------------------

func TestCLI_ExitCodes(t *testing.T) {
	tmpDir := t.TempDir()

	// Clean Terraform file (no violations)
	cleanTfPath := filepath.Join(tmpDir, "clean.tf")
	require.NoError(t, os.WriteFile(cleanTfPath, []byte(`
resource "aws_s3_bucket" "secure" {
  bucket = "clean-test-bucket"
  tags = {
    Environment = "prod"
  }
}
`), 0644))

	// Vulnerable Terraform file (violates default checks, e.g. unencrypted ebs)
	vulnTfPath := filepath.Join(tmpDir, "vuln.tf")
	require.NoError(t, os.WriteFile(vulnTfPath, []byte(`
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}
`), 0644))

	t.Run("Exit 0 on clean runs", func(t *testing.T) {
		// Version command
		resetFlagsForTest()
		assert.Equal(t, 0, runMain([]string{"version"}))

		// Rules list
		resetFlagsForTest()
		assert.Equal(t, 0, runMain([]string{"rules", "list"}))

		// Rules info
		resetFlagsForTest()
		assert.Equal(t, 0, runMain([]string{"rules", "info", "s3_bucket_level_public_access_block"}))

		// Rules get
		resetFlagsForTest()
		assert.Equal(t, 0, runMain([]string{"rules", "get", "s3_bucket_level_public_access_block"}))

		// Clean IaC scan with high fail threshold
		resetFlagsForTest()
		assert.Equal(t, 0, runMain([]string{"scan", "iac", cleanTfPath, "--fail-on", "CRITICAL"}))
	})

	t.Run("Exit 1 when findings exceed fail-on threshold", func(t *testing.T) {
		resetFlagsForTest()
		// ebs unencrypted triggers HIGH severity violation; threshold is HIGH
		code := runMain([]string{"scan", "iac", vulnTfPath, "--fail-on", "HIGH"})
		assert.Equal(t, 1, code, "expected exit 1 when findings meet or exceed --fail-on threshold")

		// Also verify model.ErrThresholdExceeded maps directly to exit 1
		resetFlagsForTest()
		baseJSON := filepath.Join(tmpDir, "base.json")
		headJSON := filepath.Join(tmpDir, "head.json")
		require.NoError(t, os.WriteFile(baseJSON, []byte(`[]`), 0644))
		headResults := []model.ScanResult{
			{
				RuleID:     "ebs_encryption",
				ResourceID: "vol-12345",
				Severity:   model.SeverityCritical,
				Status:     model.StatusFail,
			},
		}
		var headBuf bytes.Buffer
		require.NoError(t, output.NewJSONFormatter(true).Format(&headBuf, headResults))
		require.NoError(t, os.WriteFile(headJSON, headBuf.Bytes(), 0644))

		code = runMain([]string{"diff", baseJSON, headJSON, "--fail-on", "CRITICAL"})
		assert.Equal(t, 1, code, "diff with new critical findings should exit 1")
	})

	t.Run("Exit 2 on invalid flags or runtime errors", func(t *testing.T) {
		// Invalid mode
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"scan", "iac", cleanTfPath, "--mode", "unknown_mode"}))

		// Invalid format
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"scan", "iac", cleanTfPath, "-f", "invalid_format"}))

		// Invalid fail-on severity
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"scan", "iac", cleanTfPath, "--fail-on", "BOGUS_SEVERITY"}))

		// Nonexistent baseline file in diff
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"diff", "nonexistent_base.json", "nonexistent_head.json"}))

		// Nonexistent findings file in remediate
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"remediate", "nonexistent_findings.json"}))

		// Nonexistent findings file in tui
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"tui", "nonexistent_findings.json"}))

		// Rule not found in embedded catalog
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"rules", "info", "nonexistent_rule_xyz"}))

		// Invalid format in rules list
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"rules", "list", "-f", "yaml"}))
	})
}

// ---------------------------------------------------------------------------
// 2. Flag-Over-Config Precedence
// ---------------------------------------------------------------------------

func TestCLI_FlagOverConfigPrecedence(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".possum.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
scan:
  fail_on: "LOW"
  mode: "quick"
  workers: 5
  regions:
    - "eu-west-1"
  services:
    - "s3"
  checks:
    - "s3_bucket_level_public_access_block"
  compliance: "cis-1.4"
  ignore_file: ".customignore"
  fail_on_error: true
  all_regions: true
  timeout: "2m"
output:
  format: "json"
  output_file: "config_out.json"
  no_color: true
`), 0644))

	fileCfg, _, err := config.Discover(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, fileCfg)

	t.Run("Config values applied when flags are unset", func(t *testing.T) {
		resetFlagsForTest()
		cmd := &cobra.Command{}
		scanAWSCmd.Flags().VisitAll(func(f *pflag.Flag) {
			cmd.Flags().AddFlag(f)
		})

		applyConfigFileDefaults(fileCfg, cmd)

		assert.Equal(t, "LOW", awsFailOn)
		assert.Equal(t, "json", awsFormat)
		assert.Equal(t, 5, awsMaxWorkers)
		assert.Equal(t, "eu-west-1", awsRegions)
		assert.Equal(t, "s3", awsServices)
		assert.Equal(t, "s3_bucket_level_public_access_block", awsChecks)
		assert.Equal(t, "cis-1.4", awsCompliance)
		assert.Equal(t, true, awsFailOnError)
		assert.Equal(t, true, awsAllRegions)
		assert.Equal(t, "quick", awsMode)
		assert.Equal(t, ".customignore", awsIgnoreFile)
		assert.Equal(t, "config_out.json", awsOutputFile)
		assert.True(t, noColor)

		// Test IaC defaults applied
		resetFlagsForTest()
		iacCmd := &cobra.Command{}
		scanIaCCmd.Flags().VisitAll(func(f *pflag.Flag) {
			iacCmd.Flags().AddFlag(f)
		})
		applyIaCConfigFileDefaults(fileCfg, iacCmd)
		assert.Equal(t, "LOW", iacFailOn)
		assert.Equal(t, "json", iacFormat)
		assert.Equal(t, "quick", iacMode)
		assert.Equal(t, ".customignore", iacIgnoreFile)
		assert.Equal(t, "config_out.json", iacOutputFile)
		assert.True(t, noColor)
	})

	t.Run("CLI flags override config values", func(t *testing.T) {
		resetFlagsForTest()

		// Simulate CLI flags explicitly set by user
		cmd := &cobra.Command{}
		scanAWSCmd.Flags().VisitAll(func(f *pflag.Flag) {
			cmd.Flags().AddFlag(f)
		})

		require.NoError(t, cmd.Flags().Set("fail-on", "HIGH"))
		require.NoError(t, cmd.Flags().Set("format", "table"))
		require.NoError(t, cmd.Flags().Set("workers", "20"))
		require.NoError(t, cmd.Flags().Set("regions", "us-east-1,us-west-2"))
		require.NoError(t, cmd.Flags().Set("services", "iam,ec2"))
		require.NoError(t, cmd.Flags().Set("checks", "ec2_sg_open"))
		require.NoError(t, cmd.Flags().Set("compliance", "pci-dss"))
		require.NoError(t, cmd.Flags().Set("mode", "standard"))
		require.NoError(t, cmd.Flags().Set("output", "cli_out.txt"))
		require.NoError(t, cmd.Flags().Set("ignore-file", ".cliignore"))

		applyConfigFileDefaults(fileCfg, cmd)

		// Flags must override config
		assert.Equal(t, "HIGH", awsFailOn, "CLI flag --fail-on must override config")
		assert.Equal(t, "table", awsFormat, "CLI flag -f must override config")
		assert.Equal(t, 20, awsMaxWorkers, "CLI flag --workers must override config")
		assert.Equal(t, "us-east-1,us-west-2", awsRegions, "CLI flag --regions must override config")
		assert.Equal(t, "iam,ec2", awsServices, "CLI flag --services must override config")
		assert.Equal(t, "ec2_sg_open", awsChecks, "CLI flag --checks must override config")
		assert.Equal(t, "pci-dss", awsCompliance, "CLI flag --compliance must override config")
		assert.Equal(t, "standard", awsMode, "CLI flag --mode must override config")
		assert.Equal(t, "cli_out.txt", awsOutputFile, "CLI flag -o must override config")
		assert.Equal(t, ".cliignore", awsIgnoreFile, "CLI flag --ignore-file must override config")
	})

	t.Run("End-to-end CLI execution respects flag overrides", func(t *testing.T) {
		tfPath := filepath.Join(tmpDir, "main.tf")
		require.NoError(t, os.WriteFile(tfPath, []byte(`
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}
`), 0644))

		outFile := filepath.Join(tmpDir, "out_override.json")

		// Config specifies fail_on: "LOW" (which would trigger exit 1 on HIGH finding),
		// but CLI explicitly specifies --fail-on CRITICAL (which shouldn't fail because finding is HIGH).
		resetFlagsForTest()
		code := runMain([]string{
			"scan", "iac", tfPath,
			"--config", cfgPath,
			"--fail-on", "CRITICAL",
			"-f", "json",
			"-o", outFile,
		})
		assert.Equal(t, 0, code, "overriding flag --fail-on CRITICAL should take precedence over config's fail_on: LOW")

		content, err := os.ReadFile(outFile)
		require.NoError(t, err)
		assert.NotEmpty(t, content)
	})
}

// ---------------------------------------------------------------------------
// 3. Scanner Pre-Filtering
// ---------------------------------------------------------------------------

type mockScanner struct {
	name string
	meta scanner.ScannerMeta
}

func (m *mockScanner) Name() string                                           { return m.name }
func (m *mockScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) { return nil, nil }
func (m *mockScanner) Meta() scanner.ScannerMeta                              { return m.meta }

type basicScanner struct {
	name string
}

func (b *basicScanner) Name() string                                           { return b.name }
func (b *basicScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) { return nil, nil }

func TestCLI_ScannerPreFiltering(t *testing.T) {
	s3Scanner := &mockScanner{
		name: "s3_public_access_scanner",
		meta: scanner.ScannerMeta{
			ID:            "s3_scanner",
			Service:       "s3",
			CheckIDs:      []string{"s3_bucket_level_public_access_block", "s3_bucket_server_side_encryption"},
			ExecutionCost: scanner.CostMedium,
		},
	}

	iamScanner := &mockScanner{
		name: "iam_mfa_scanner",
		meta: scanner.ScannerMeta{
			ID:            "iam_scanner",
			Service:       "iam",
			CheckIDs:      []string{"iam_root_mfa_enabled", "iam_password_policy"},
			ExecutionCost: scanner.CostMedium,
		},
	}

	ec2HeavyScanner := &mockScanner{
		name: "ec2_deep_sg_scanner",
		meta: scanner.ScannerMeta{
			ID:            "ec2_heavy_scanner",
			Service:       "ec2",
			CheckIDs:      []string{"ec2_securitygroup_allow_ingress_from_internet_to_any_port"},
			ExecutionCost: scanner.CostHeavy,
		},
	}

	legacyScanner := &basicScanner{name: "legacy_untyped_scanner"}

	allScanners := []scanner.Scanner{s3Scanner, iamScanner, ec2HeavyScanner, legacyScanner}

	t.Run("Empty filters return all scanners", func(t *testing.T) {
		filtered := preFilterScanners(allScanners, nil, nil, "")
		assert.Equal(t, len(allScanners), len(filtered))
	})

	t.Run("Filter by --services s3: only S3 checks run", func(t *testing.T) {
		filtered := preFilterScanners(allScanners, []string{"s3"}, nil, "")
		require.Len(t, filtered, 2) // s3Scanner + legacyScanner (non-MetaScanner kept)
		assert.Equal(t, s3Scanner.Name(), filtered[0].Name())
		assert.Equal(t, legacyScanner.Name(), filtered[1].Name())
	})

	t.Run("Filter by --checks s3_bucket_level_public_access_block", func(t *testing.T) {
		filtered := preFilterScanners(allScanners, nil, []string{"s3_bucket_level_public_access_block"}, "")
		require.Len(t, filtered, 2)
		assert.Equal(t, s3Scanner.Name(), filtered[0].Name())
		assert.Equal(t, legacyScanner.Name(), filtered[1].Name())
	})

	t.Run("Filter by --compliance cis-1.4 check resolution", func(t *testing.T) {
		catalog, err := rules.NewRuleCatalog()
		require.NoError(t, err)
		require.NotNil(t, catalog)

		checks := catalog.GetChecksByFramework("cis-1.4")
		require.NotEmpty(t, checks, "expected CIS 1.4 checks to be present in catalog")

		// Create a mock scanner for one of the CIS checks
		targetCheck := checks[0]
		cisScanner := &mockScanner{
			name: "cis_matching_scanner",
			meta: scanner.ScannerMeta{
				ID:            "cis_scanner",
				Service:       "test",
				CheckIDs:      []string{targetCheck},
				ExecutionCost: scanner.CostLight,
			},
		}

		nonCisScanner := &mockScanner{
			name: "unrelated_scanner",
			meta: scanner.ScannerMeta{
				ID:            "unrelated_scanner",
				Service:       "other",
				CheckIDs:      []string{"custom_unrelated_check_xyz_not_in_cis"},
				ExecutionCost: scanner.CostLight,
			},
		}

		filtered := preFilterScanners([]scanner.Scanner{cisScanner, nonCisScanner}, nil, checks, "")
		require.Len(t, filtered, 1)
		assert.Equal(t, "cis_matching_scanner", filtered[0].Name())
	})

	t.Run("Filter by --mode quick: skips CostHeavy scanners", func(t *testing.T) {
		filtered := preFilterScanners(allScanners, nil, nil, "quick")
		require.Len(t, filtered, 3)
		for _, sc := range filtered {
			assert.NotEqual(t, ec2HeavyScanner.Name(), sc.Name(), "CostHeavy scanner must be skipped in quick mode")
		}
	})
}

// ---------------------------------------------------------------------------
// 4. JSON Round-Trip & Pipability
// ---------------------------------------------------------------------------

func TestCLI_JSONRoundTripAndPipability(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Generate JSON scan report from `scan iac`
	tfPath := filepath.Join(tmpDir, "main.tf")
	require.NoError(t, os.WriteFile(tfPath, []byte(`
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}
`), 0644))

	scanReportPath := filepath.Join(tmpDir, "scan_report.json")
	resetFlagsForTest()
	code := runMain([]string{"scan", "iac", tfPath, "-f", "json", "-o", scanReportPath})
	assert.Equal(t, 0, code)

	results, err := output.LoadResultsFromFile(scanReportPath)
	require.NoError(t, err)
	require.NotEmpty(t, results, "expected scan report to contain findings")

	// 2. Feed it into `possum diff` as baseline and head
	t.Run("Diff file input", func(t *testing.T) {
		diffOut := filepath.Join(tmpDir, "diff_summary.txt")

		// Same report as baseline and head -> 0 new findings -> exit 0
		resetFlagsForTest()
		code = runMain([]string{"diff", scanReportPath, scanReportPath, "-f", "table", "-o", diffOut})
		assert.Equal(t, 0, code)

		diffContent, err := os.ReadFile(diffOut)
		require.NoError(t, err)
		assert.Contains(t, string(diffContent), "New Findings:      0")

		// Diff with markdown-pr format
		resetFlagsForTest()
		code = runMain([]string{"diff", scanReportPath, scanReportPath, "-f", "markdown-pr"})
		assert.Equal(t, 0, code)

		// Diff with json format
		resetFlagsForTest()
		code = runMain([]string{"diff", scanReportPath, scanReportPath, "-f", "json"})
		assert.Equal(t, 0, code)
	})

	// 3. Feed it into `possum remediate`
	t.Run("Remediate file input", func(t *testing.T) {
		// Create a findings report with remediable S3 finding
		remediableReport := filepath.Join(tmpDir, "remediable.json")
		remediableFindings := []model.ScanResult{
			{
				RuleID:       "s3_bucket_level_public_access_block",
				Title:        "Public Access Block Disabled",
				ResourceID:   "arn:aws:s3:::leak-bucket",
				ResourceType: "AWS::S3::Bucket",
				Region:       "us-east-1",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
			},
		}
		var buf bytes.Buffer
		require.NoError(t, output.NewJSONFormatter(true).Format(&buf, remediableFindings))
		require.NoError(t, os.WriteFile(remediableReport, buf.Bytes(), 0644))

		scriptOut := filepath.Join(tmpDir, "fix.sh")
		resetFlagsForTest()
		code = runMain([]string{"remediate", remediableReport, "-e", scriptOut, "--dry-run=true"})
		assert.Equal(t, 0, code)

		scriptData, err := os.ReadFile(scriptOut)
		require.NoError(t, err)
		assert.Contains(t, string(scriptData), "#!/usr/bin/env bash")
		assert.Contains(t, string(scriptData), "DRY_RUN=true")
	})

	t.Run("Remediate stdin piping", func(t *testing.T) {
		remediableFindings := []model.ScanResult{
			{
				RuleID:       "s3_bucket_level_public_access_block",
				Title:        "Public Access Block Disabled",
				ResourceID:   "arn:aws:s3:::piped-bucket",
				ResourceType: "AWS::S3::Bucket",
				Region:       "us-east-1",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
			},
		}
		var buf bytes.Buffer
		require.NoError(t, output.NewJSONFormatter(true).Format(&buf, remediableFindings))

		oldStdin := os.Stdin
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		defer func() { os.Stdin = oldStdin }()

		go func() {
			_, _ = w.Write(buf.Bytes())
			_ = w.Close()
		}()

		scriptOut := filepath.Join(tmpDir, "fix_piped.sh")
		resetFlagsForTest()
		code := runMain([]string{"remediate", "-e", scriptOut})
		assert.Equal(t, 0, code)

		scriptData, err := os.ReadFile(scriptOut)
		require.NoError(t, err)
		assert.Contains(t, string(scriptData), "piped-bucket")
	})

	t.Run("Remediate without findings", func(t *testing.T) {
		emptyReport := filepath.Join(tmpDir, "empty.json")
		require.NoError(t, os.WriteFile(emptyReport, []byte("[]"), 0644))
		resetFlagsForTest()
		code = runMain([]string{"remediate", emptyReport})
		assert.Equal(t, 0, code)
	})

	t.Run("Remediate and TUI error without file or pipe", func(t *testing.T) {
		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"remediate"}))

		resetFlagsForTest()
		assert.Equal(t, 2, runMain([]string{"tui"}))
	})

	// 4. Feed it into `possum tui` (verify parsing model from file)
	t.Run("TUI file input", func(t *testing.T) {
		oldStdin := os.Stdin
		r, w, err := os.Pipe()
		require.NoError(t, err)
		os.Stdin = r
		defer func() { os.Stdin = oldStdin }()

		// Send "q\n" to quit the interactive UI immediately
		go func() {
			_, _ = w.WriteString("q\n")
			_ = w.Close()
		}()

		resetFlagsForTest()
		code = runMain([]string{"tui", scanReportPath})
		assert.Equal(t, 0, code, "tui should parse model from file and exit cleanly on 'q'")
	})
}

// ---------------------------------------------------------------------------
// 5. Additional IaC, Cloud, and Rules Catalog Coverage
// ---------------------------------------------------------------------------

func TestCLI_IaCFormatsAndSuppressions(t *testing.T) {
	tmpDir := t.TempDir()
	tfPath := filepath.Join(tmpDir, "main.tf")
	require.NoError(t, os.WriteFile(tfPath, []byte(`
resource "aws_ebs_volume" "test_vol" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}
`), 0644))

	// Test all supported output formats
	for _, fmtName := range []string{"table", "json", "sarif", "junit", "csv", "mermaid", "html"} {
		t.Run("Format "+fmtName, func(t *testing.T) {
			outPath := filepath.Join(tmpDir, "scan."+fmtName)
			resetFlagsForTest()
			code := runMain([]string{"scan", "iac", tfPath, "-f", fmtName, "-o", outPath})
			assert.Equal(t, 0, code)
			fi, err := os.Stat(outPath)
			require.NoError(t, err)
			assert.Greater(t, fi.Size(), int64(0))
		})
	}

	t.Run("Ignore file suppression", func(t *testing.T) {
		ignoreFile := filepath.Join(tmpDir, ".possumignore")
		require.NoError(t, os.WriteFile(ignoreFile, []byte(`
# Suppress all ebs_volume_encryption checks
check: ebs_volume_encryption
reason: "Accepted legacy test volume"
`), 0644))

		resetFlagsForTest()
		code := runMain([]string{"scan", "iac", tfPath, "--ignore-file", ignoreFile, "-f", "json"})
		assert.Equal(t, 0, code)
	})

	t.Run("Terraform plan JSON extraction", func(t *testing.T) {
		planFile := filepath.Join(tmpDir, "tfplan.json")
		planJSON := `{
  "format_version": "0.1",
  "terraform_version": "1.5.0",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.data",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data",
      "provider_name": "aws",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "test-plan-bucket",
          "tags": {
            "Environment": "production"
          }
        }
      }
    },
    {
      "address": "aws_s3_bucket.old",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "old",
      "provider_name": "aws",
      "change": {
        "actions": ["delete"]
      }
    }
  ]
}`
		require.NoError(t, os.WriteFile(planFile, []byte(planJSON), 0644))

		ruleFile := filepath.Join(tmpDir, "rule.yaml")
		require.NoError(t, os.WriteFile(ruleFile, []byte(`
id: plan_custom_rule
name: Check Plan Owner Tag
resource_type: aws_s3_bucket
severity: HIGH
condition: "tags.Owner != ''"
message: "Missing owner tag in plan"
`), 0644))

		resetFlagsForTest()
		code := runMain([]string{"scan", "iac", planFile, "--custom-rules", ruleFile, "-f", "table"})
		assert.Equal(t, 0, code)
	})
}

func TestCLI_CloudCommands(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	// Cloud status before login
	resetFlagsForTest()
	code := runMain([]string{"cloud", "status"})
	assert.Equal(t, 0, code)

	// Cloud login
	resetFlagsForTest()
	code = runMain([]string{
		"cloud", "login",
		"--key", "pos_live_1234567890abcdef",
		"--url", "https://app.possum.io",
		"--account", "123456789012",
	})
	assert.Equal(t, 0, code)

	// Cloud status after login
	resetFlagsForTest()
	code = runMain([]string{"cloud", "status"})
	assert.Equal(t, 0, code)

	// Cloud logout
	resetFlagsForTest()
	code = runMain([]string{"cloud", "logout"})
	assert.Equal(t, 0, code)
}

func TestCLI_RulesCatalogCommands(t *testing.T) {
	// Rules list with filters
	resetFlagsForTest()
	code := runMain([]string{
		"rules", "list",
		"--service", "s3",
		"--severity", "HIGH",
		"--search", "public",
		"-f", "table",
	})
	assert.Equal(t, 0, code)

	// Rules list in JSON
	resetFlagsForTest()
	code = runMain([]string{
		"rules", "list",
		"--service", "s3",
		"-f", "json",
	})
	assert.Equal(t, 0, code)

	// Rules info in table and json
	resetFlagsForTest()
	code = runMain([]string{"rules", "info", "s3_bucket_level_public_access_block", "-f", "table"})
	assert.Equal(t, 0, code)

	resetFlagsForTest()
	code = runMain([]string{"rules", "get", "s3_bucket_level_public_access_block", "-f", "json"})
	assert.Equal(t, 0, code)
}

func TestCLI_InvalidFailOnSeverityReturnsError(t *testing.T) {
	resetFlagsForTest()
	tmpDir := t.TempDir()
	tfPath := filepath.Join(tmpDir, "main.tf")
	require.NoError(t, os.WriteFile(tfPath, []byte(`
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = false
}
`), 0644))

	rootCmd.SetArgs([]string{"scan", "iac", tfPath, "--fail-on", "HGIH"})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.False(t, errors.Is(err, model.ErrThresholdExceeded), "typo in --fail-on must return validation error (exit 2), not ErrThresholdExceeded")
	assert.Contains(t, err.Error(), "invalid severity")

	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "--fail-on", "HGIH"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.False(t, errors.Is(err, model.ErrThresholdExceeded))
	assert.Contains(t, err.Error(), "invalid severity")
}

func TestCLI_InvalidFormatModeAndRulesValidation(t *testing.T) {
	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "--mode", "invalid-mode"})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scan mode")

	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "-f", "badformat"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid output format")

	resetFlagsForTest()
	rootCmd.SetArgs([]string{"rules", "list", "--severity", "HGIH"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity")

	resetFlagsForTest()
	rootCmd.SetArgs([]string{"rules", "info", "s3_bucket_level_public_access_block", "-f", "json"})
	err = rootCmd.Execute()
	require.NoError(t, err)
}

func TestCLI_DiffReturnsThresholdExceededInAllFormats(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "base.json")
	headPath := filepath.Join(tmpDir, "head.json")
	outPath := filepath.Join(tmpDir, "diff.out")

	baseResults := []model.ScanResult{}
	headResults := []model.ScanResult{
		{
			RuleID:       "s3_bucket_level_public_access_block",
			Title:        "Public S3 Bucket",
			ResourceID:   "arn:aws:s3:::leaked-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			Severity:     model.SeverityCritical,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
		},
	}

	var baseBuf, headBuf bytes.Buffer
	require.NoError(t, output.NewJSONFormatter(true).Format(&baseBuf, baseResults))
	require.NoError(t, output.NewJSONFormatter(true).Format(&headBuf, headResults))
	require.NoError(t, os.WriteFile(basePath, baseBuf.Bytes(), 0644))
	require.NoError(t, os.WriteFile(headPath, headBuf.Bytes(), 0644))

	for _, format := range []string{"markdown-pr", "json", "table"} {
		t.Run(format, func(t *testing.T) {
			resetFlagsForTest()
			rootCmd.SetArgs([]string{"diff", basePath, headPath, "-f", format, "-o", outPath})
			err := rootCmd.Execute()
			require.Error(t, err)
			assert.True(t, errors.Is(err, model.ErrThresholdExceeded), "expected ErrThresholdExceeded for format %s, got: %v", format, err)

			content, readErr := os.ReadFile(outPath)
			require.NoError(t, readErr)
			assert.NotEmpty(t, content, "expected diff report output to be written before returning ErrThresholdExceeded")
		})
	}
}

func TestCLI_JSONRoundTrip(t *testing.T) {
	original := []model.ScanResult{
		{
			RuleID:       "ec2_sg_open",
			ResourceID:   "sg-12345",
			ResourceType: "AWS::EC2::SecurityGroup",
			Region:       "us-east-1",
			Severity:     model.SeverityHigh,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
			CostWasteMo:  12.5,
		},
		{
			RuleID:       "s3_public_bucket",
			ResourceID:   "arn:aws:s3:::prod-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			Severity:     model.SeverityCritical,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
		},
	}

	var buf bytes.Buffer
	require.NoError(t, output.NewJSONFormatter(true).Format(&buf, original))

	loaded, err := output.LoadResults(&buf)
	require.NoError(t, err)
	require.Len(t, loaded, 2)
	assert.Equal(t, "s3_public_bucket", loaded[0].RuleID)
	assert.Equal(t, "ec2_sg_open", loaded[1].RuleID)
}

func TestCLI_ScanIaCWithConfigAndCustomRules(t *testing.T) {
	tmpDir := t.TempDir()
	tfPath := filepath.Join(tmpDir, "main.tf")
	require.NoError(t, os.WriteFile(tfPath, []byte(`
resource "aws_s3_bucket" "data" {
  bucket = "corp-data"
  tags = {
    Environment = "dev"
  }
}
`), 0644))

	rulesDir := filepath.Join(tmpDir, "rules")
	require.NoError(t, os.MkdirAll(rulesDir, 0755))
	ruleFile := filepath.Join(rulesDir, "tag_rule.yaml")
	require.NoError(t, os.WriteFile(ruleFile, []byte(`
id: custom_s3_prod_tag
name: S3 Bucket Must Have Owner Tag
resource_type: aws_s3_bucket
severity: HIGH
condition: "tags.Owner != ''"
message: "S3 bucket is missing Owner tag"
`), 0644))

	outFile := filepath.Join(tmpDir, "out.csv")
	cfgPath := filepath.Join(tmpDir, ".possum.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
version: "1"
scan:
  fail_on: "HIGH"
output:
  format: "csv"
`), 0644))

	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "iac", tfPath, "--config", cfgPath, "--custom-rules", rulesDir, "-o", outFile})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.True(t, errors.Is(err, model.ErrThresholdExceeded))

	csvData, readErr := os.ReadFile(outFile)
	require.NoError(t, readErr)
	assert.Contains(t, string(csvData), "custom_s3_prod_tag")
}

func TestCLI_ScanAWS_ValidationErrors(t *testing.T) {
	// 1. Invalid FailOn
	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "--fail-on", "INVALID_SEVERITY"})
	err := rootCmd.Execute()
	require.Error(t, err)

	// 2. Invalid Scan Mode
	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "--mode", "turbo_invalid"})
	err = rootCmd.Execute()
	require.Error(t, err)

	// 3. Invalid Output Format
	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "--format", "unsupported_xyz"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid output format")

	// 4. Missing / Invalid Config File
	resetFlagsForTest()
	rootCmd.SetArgs([]string{"scan", "aws", "--config", "/nonexistent/possum/config.yaml"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid config file")
}

