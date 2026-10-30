package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadResults_EnvelopeAndRawArray(t *testing.T) {
	expected := sampleResults()

	// 1. JSONEnvelope output (as produced by `possum scan aws -f json`)
	var envBuf bytes.Buffer
	require.NoError(t, NewJSONFormatter(true).Format(&envBuf, expected))

	loadedEnv, err := LoadResults(&envBuf)
	require.NoError(t, err)
	require.Len(t, loadedEnv, len(expected))
	assert.Equal(t, expected[0].ResourceID, loadedEnv[0].ResourceID)
	assert.Equal(t, expected[1].RuleID, loadedEnv[1].RuleID)

	// 2. Raw JSON array output
	var arrBuf bytes.Buffer
	require.NoError(t, NewJSONFormatter(false).Format(&arrBuf, expected))

	loadedArr, err := LoadResults(&arrBuf)
	require.NoError(t, err)
	require.Len(t, loadedArr, len(expected))
	assert.Equal(t, expected[0].ResourceID, loadedArr[0].ResourceID)
	assert.Equal(t, expected[1].RuleID, loadedArr[1].RuleID)

	// 3. LoadResultsFromFile with both formats
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "envelope.json")
	arrPath := filepath.Join(tmpDir, "array.json")

	var envFileBuf, arrFileBuf bytes.Buffer
	require.NoError(t, NewJSONFormatter(true).Format(&envFileBuf, expected))
	require.NoError(t, NewJSONFormatter(false).Format(&arrFileBuf, expected))
	require.NoError(t, os.WriteFile(envPath, envFileBuf.Bytes(), 0644))
	require.NoError(t, os.WriteFile(arrPath, arrFileBuf.Bytes(), 0644))

	fromEnvFile, err := LoadResultsFromFile(envPath)
	require.NoError(t, err)
	assert.Len(t, fromEnvFile, len(expected))

	fromArrFile, err := LoadResultsFromFile(arrPath)
	require.NoError(t, err)
	assert.Len(t, fromArrFile, len(expected))

	// 4. Invalid inputs should error
	_, err = LoadResults(strings.NewReader(""))
	assert.Error(t, err)

	_, err = LoadResults(strings.NewReader(`{"unrelated": 123}`))
	assert.Error(t, err)
}

func TestJSONEnvelope_SchemaVersionAndDeterministicSorting(t *testing.T) {
	unsorted := []model.ScanResult{
		{RuleID: "rule_b", ResourceID: "res_2", Region: "us-west-2", Severity: model.SeverityLow, Status: model.StatusFail},
		{RuleID: "rule_a", ResourceID: "res_1", Region: "us-east-1", Severity: model.SeverityCritical, Status: model.StatusFail},
		{RuleID: "rule_a", ResourceID: "res_0", Region: "us-east-1", Severity: model.SeverityCritical, Status: model.StatusFail},
		{RuleID: "rule_c", ResourceID: "res_3", Region: "eu-west-1", Severity: model.SeverityHigh, Status: model.StatusFail},
	}

	var buf bytes.Buffer
	require.NoError(t, NewJSONFormatter(true).Format(&buf, unsorted))

	var env JSONEnvelope
	require.NoError(t, json.Unmarshal(buf.Bytes(), &env))
	assert.Equal(t, "1.0", env.SchemaVersion)
	require.Len(t, env.Results, 4)

	// CRITICAL comes first, sorted by RuleID asc then ResourceID asc
	assert.Equal(t, "res_0", env.Results[0].ResourceID)
	assert.Equal(t, "res_1", env.Results[1].ResourceID)
	assert.Equal(t, "res_3", env.Results[2].ResourceID)
	assert.Equal(t, "res_2", env.Results[3].ResourceID)
}

func TestSARIFFormatter_NonNullEmptyAndSuppressedFiltering(t *testing.T) {
	// Empty / suppressed / pass-only results should still serialize rules: [] and results: [] (never null)
	results := []model.ScanResult{
		{
			RuleID:     "s3_public",
			ResourceID: "arn:aws:s3:::suppressed-bucket",
			Region:     "us-east-1",
			Severity:   model.SeverityCritical,
			Status:     model.StatusSuppressed,
		},
		{
			RuleID:     "s3_public",
			ResourceID: "arn:aws:s3:::pass-bucket",
			Region:     "us-east-1",
			Severity:   model.SeverityCritical,
			Status:     model.StatusPass,
		},
	}

	var buf bytes.Buffer
	require.NoError(t, NewSARIFFormatter().Format(&buf, results))
	rawJSON := buf.String()
	assert.NotContains(t, rawJSON, `"rules": null`)
	assert.NotContains(t, rawJSON, `"results": null`)
	assert.Contains(t, rawJSON, `"rules": []`)
	assert.Contains(t, rawJSON, `"results": []`)
}

func TestSARIFFormatter_FingerprintsSecuritySeverityAndLocations(t *testing.T) {
	results := []model.ScanResult{
		{
			RuleID:       "iac_sg_open",
			Title:        "Security group open",
			ResourceID:   "aws_security_group.web",
			ResourceType: "aws_security_group",
			Region:       "iac",
			Severity:     model.SeverityCritical,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
			Metrics: map[string]interface{}{
				"File": "main.tf",
				"Line": 42,
			},
		},
		{
			RuleID:       "s3_public_bucket",
			Title:        "Public S3 Bucket",
			ResourceID:   "arn:aws:s3:::prod-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			Severity:     model.SeverityHigh,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
		},
		{
			RuleID:       "suppressed_rule",
			ResourceID:   "arn:aws:s3:::ignored-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			Severity:     model.SeverityHigh,
			Status:       model.StatusSuppressed,
		},
	}

	var buf bytes.Buffer
	require.NoError(t, NewSARIFFormatter().Format(&buf, results))

	var report SARIFReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &report))
	require.Len(t, report.Runs, 1)
	run := report.Runs[0]

	// Suppressed finding is excluded
	require.Len(t, run.Results, 2)
	require.Len(t, run.Tool.Driver.Rules, 2)

	// Rule 0 is CRITICAL -> security-severity "9.0"
	require.NotNil(t, run.Tool.Driver.Rules[0].Properties)
	assert.Equal(t, "9.0", run.Tool.Driver.Rules[0].Properties.SecuritySeverity)
	assert.NotEmpty(t, run.Tool.Driver.Rules[0].Properties.Tags)

	// Rule 1 is HIGH -> security-severity "7.0"
	require.NotNil(t, run.Tool.Driver.Rules[1].Properties)
	assert.Equal(t, "7.0", run.Tool.Driver.Rules[1].Properties.SecuritySeverity)

	// Result 0 has File/Line physical location and partialFingerprints
	res0 := run.Results[0]
	assert.NotEmpty(t, res0.PartialFingerprints["primaryLocationLineHash"])
	require.Len(t, res0.Locations, 1)
	assert.Equal(t, "main.tf", res0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	require.NotNil(t, res0.Locations[0].PhysicalLocation.Region)
	assert.Equal(t, 42, res0.Locations[0].PhysicalLocation.Region.StartLine)

	// Result 1 has cloud ARN relative URI + logicalLocations
	res1 := run.Results[1]
	assert.NotEmpty(t, res1.PartialFingerprints["primaryLocationLineHash"])
	require.Len(t, res1.Locations, 1)
	assert.NotContains(t, res1.Locations[0].PhysicalLocation.ArtifactLocation.URI, ":")
	require.Len(t, res1.Locations[0].LogicalLocations, 1)
	assert.Equal(t, "arn:aws:s3:::prod-bucket", res1.Locations[0].LogicalLocations[0].FullyQualifiedName)
}

func TestCSVFormatter_JUnitAndHTML(t *testing.T) {
	results := sampleResults()

	// CSV
	var csvBuf bytes.Buffer
	require.NoError(t, NewCSVFormatter().Format(&csvBuf, results))
	rows, err := csv.NewReader(&csvBuf).ReadAll()
	require.NoError(t, err)
	require.Len(t, rows, 4) // 1 header + 3 results
	assert.Equal(t, "rule_id", rows[0][0])
	assert.Equal(t, "my-prod-bucket", rows[1][5]) // CRITICAL FAIL sorted first

	// JUnit
	var junitBuf bytes.Buffer
	require.NoError(t, NewJUnitFormatter().Format(&junitBuf, results))
	var suites JUnitTestSuites
	require.NoError(t, xml.Unmarshal(junitBuf.Bytes(), &suites))
	assert.Equal(t, 3, suites.Tests)
	assert.Equal(t, 2, suites.Failures)

	// HTML
	var htmlBuf bytes.Buffer
	require.NoError(t, NewHTMLFormatter().Format(&htmlBuf, results))
	assert.Contains(t, htmlBuf.String(), "<!DOCTYPE html>")
	assert.Contains(t, htmlBuf.String(), "my-prod-bucket")
}
