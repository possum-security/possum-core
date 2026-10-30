package output

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update golden files")

func deterministicFindings() []model.ScanResult {
	fixedTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	return []model.ScanResult{
		{
			RuleID:       "s3_bucket_level_public_access_block",
			Title:        "S3 bucket public access block disabled",
			Severity:     model.SeverityCritical,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
			ResourceID:   "arn:aws:s3:::production-customer-data",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			AccountID:    "123456789012",
			Description:  "S3 Block Public Access is disabled on bucket.",
			Remediation:  "aws s3api put-public-access-block --bucket production-customer-data",
			CostWasteMo:  0.0,
			EvaluatedAt:  fixedTime,
			Metrics: map[string]interface{}{
				"File": "terraform/s3.tf",
				"Line": 42,
			},
		},
		{
			RuleID:       "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
			Title:        "Security group allows ingress from internet to any port",
			Severity:     model.SeverityHigh,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
			ResourceID:   "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0",
			ResourceType: "AWS::EC2::SecurityGroup",
			Region:       "us-east-1",
			AccountID:    "123456789012",
			Description:  "Security group has unrestricted ingress rule from 0.0.0.0/0.",
			Remediation:  "Restrict security group ingress to specific IP CIDRs or security groups.",
			CostWasteMo:  0.0,
			EvaluatedAt:  fixedTime,
			Metrics: map[string]interface{}{
				"File": "terraform/security_groups.tf",
				"Line": 105,
			},
		},
		{
			RuleID:       "ebs_volume_unused_attached",
			Title:        "Unattached EBS Volume Generating Waste",
			Severity:     model.SeverityMedium,
			Status:       model.StatusFail,
			Category:     model.CategoryFinOps,
			ResourceID:   "arn:aws:ec2:us-east-1:123456789012:volume/vol-0987654321fedcba0",
			ResourceType: "AWS::EC2::Volume",
			Region:       "us-east-1",
			AccountID:    "123456789012",
			IsOrphaned:   true,
			CostWasteMo:  38.50,
			Description:  "EBS volume is not attached to any EC2 instance.",
			Remediation:  "Delete unattached EBS volume or snapshot and archive.",
			EvaluatedAt:  fixedTime,
		},
		{
			RuleID:       "iam_root_mfa_enabled",
			Title:        "Root MFA Enabled",
			Severity:     model.SeverityCritical,
			Status:       model.StatusPass,
			Category:     model.CategorySecurity,
			ResourceID:   "arn:aws:iam::123456789012:root",
			ResourceType: "AWS::IAM::User",
			Region:       "global",
			AccountID:    "123456789012",
			Description:  "MFA is enabled on AWS root account.",
			CostWasteMo:  0.0,
			EvaluatedAt:  fixedTime,
		},
	}
}

var (
	htmlTimestampRegex = regexp.MustCompile(`Generated:\s*[^<]+`)
	sarifVersionRegex  = regexp.MustCompile(`("name":\s*"possum",\s*\n\s*"version":\s*")[^"]*(")`)
)

func normalizeOutput(format string, raw string) string {
	switch format {
	case "html":
		return htmlTimestampRegex.ReplaceAllString(raw, "Generated: 2026-01-15T10:00:00Z")
	case "sarif":
		return sarifVersionRegex.ReplaceAllString(raw, "${1}v0.1.0-dev${2}")
	default:
		return raw
	}
}

func TestOutput_GoldenFiles(t *testing.T) {
	testCases := []struct {
		name       string
		format     string
		goldenFile string
		formatter  Formatter
	}{
		{
			name:       "SARIF Output",
			format:     "sarif",
			goldenFile: "report.sarif.golden",
			formatter:  NewSARIFFormatter(),
		},
		{
			name:       "JUnit Output",
			format:     "junit",
			goldenFile: "report.junit.golden",
			formatter:  NewJUnitFormatter(),
		},
		{
			name:       "HTML Output",
			format:     "html",
			goldenFile: "report.html.golden",
			formatter:  NewHTMLFormatter(),
		},
		{
			name:       "CSV Output",
			format:     "csv",
			goldenFile: "report.csv.golden",
			formatter:  NewCSVFormatter(),
		},
	}

	testdataDir := filepath.Join("testdata")
	require.NoError(t, os.MkdirAll(testdataDir, 0755))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings := deterministicFindings()
			var buf bytes.Buffer
			err := tc.formatter.Format(&buf, findings)
			require.NoError(t, err)

			actual := normalizeOutput(tc.format, buf.String())
			goldenPath := filepath.Join(testdataDir, tc.goldenFile)

			if *update {
				err := os.WriteFile(goldenPath, []byte(actual), 0644)
				require.NoError(t, err, "failed to update golden file %s", goldenPath)
				return
			}

			expectedBytes, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "golden file %s missing, run 'go test ./pkg/output -update' to generate", goldenPath)

			expected := string(expectedBytes)
			assert.Equal(t, expected, actual, "output does not match golden file %s", tc.goldenFile)
		})
	}
}
