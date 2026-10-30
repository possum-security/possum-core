package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/output"
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
	awsFailOn = ""
	awsFormat = "table"
	awsMode = "standard"
	awsOutputFile = ""
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

	// Also verify scan aws validates --fail-on HGIH before any network calls
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
	// Sorted by severity desc: CRITICAL first, then HIGH
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
