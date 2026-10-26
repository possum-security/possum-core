package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/amirmahdy/possum-core/pkg/model"
)

func sampleResults() []model.ScanResult {
	return []model.ScanResult{
		{
			ResourceID:   "vol-0123456789abcdef0",
			ResourceType: "AWS::EC2::Volume",
			Region:       "us-east-1",
			RuleID:       "ebs_volume_unused_attached",
			Title:        "Unattached EBS Volume",
			Severity:     model.SeverityHigh,
			Status:       model.StatusFail,
			Category:     model.CategoryFinOps,
			IsOrphaned:   true,
			CostWasteMo:  35.0,
			Description:  "EBS volume is not attached to any EC2 instance.",
			Remediation:  "Delete unattached EBS volume.",
			EvaluatedAt:  time.Now(),
		},
		{
			ResourceID:   "my-prod-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			RuleID:       "s3_bucket_level_public_access_block",
			Title:        "S3 Public Access Block Disabled",
			Severity:     model.SeverityCritical,
			Status:       model.StatusFail,
			Category:     model.CategorySecurity,
			CostWasteMo:  0,
			Description:  "Public access block is disabled on S3 bucket.",
			Remediation:  "Enable public access block.",
			EvaluatedAt:  time.Now(),
		},
		{
			ResourceID:   "my-safe-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			RuleID:       "s3_bucket_level_public_access_block",
			Title:        "S3 Public Access Block Enabled",
			Severity:     model.SeverityCritical,
			Status:       model.StatusPass,
			Category:     model.CategorySecurity,
			EvaluatedAt:  time.Now(),
		},
	}
}

func TestSummaryCalculation(t *testing.T) {
	results := sampleResults()
	summary := CalculateSummary(results)

	if summary.TotalEvaluated != 3 {
		t.Errorf("Expected 3 evaluated, got %d", summary.TotalEvaluated)
	}
	if summary.PassCount != 1 {
		t.Errorf("Expected 1 pass, got %d", summary.PassCount)
	}
	if summary.FailCount != 2 {
		t.Errorf("Expected 2 fails, got %d", summary.FailCount)
	}
	if summary.CriticalCount != 1 {
		t.Errorf("Expected 1 critical, got %d", summary.CriticalCount)
	}
	if summary.HighCount != 1 {
		t.Errorf("Expected 1 high, got %d", summary.HighCount)
	}
	if summary.TotalMonthlyWasteMo != 35.0 {
		t.Errorf("Expected $35.00 waste, got %f", summary.TotalMonthlyWasteMo)
	}
	if summary.OrphanedCount != 1 {
		t.Errorf("Expected 1 orphaned resource, got %d", summary.OrphanedCount)
	}
}

func TestTableFormatter(t *testing.T) {
	results := sampleResults()
	formatter := NewTableFormatter("us-east-1", true) // Disable color for deterministic output testing

	var buf bytes.Buffer
	err := formatter.Format(&buf, results)
	if err != nil {
		t.Fatalf("Table formatting failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "vol-0123456789abcdef0") {
		t.Errorf("Output missing volume ID")
	}
	if !strings.Contains(out, "1 CRITICAL | 1 HIGH | 0 MEDIUM | 1 PASS") {
		t.Errorf("Output missing expected summary breakdown, got:\n%s", out)
	}
	if !strings.Contains(out, "$35.00/month") {
		t.Errorf("Output missing waste summary")
	}
	if !strings.Contains(out, "FINSECOPS INSIGHT") {
		t.Errorf("Output missing FinSecOps teaser")
	}
}

func TestJSONFormatter(t *testing.T) {
	results := sampleResults()
	formatter := NewJSONFormatter(true)

	var buf bytes.Buffer
	err := formatter.Format(&buf, results)
	if err != nil {
		t.Fatalf("JSON formatting failed: %v", err)
	}

	var env JSONEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if env.Summary.TotalEvaluated != 3 {
		t.Errorf("Expected 3 results in JSON summary, got %d", env.Summary.TotalEvaluated)
	}
	if len(env.Results) != 3 {
		t.Errorf("Expected 3 results array, got %d", len(env.Results))
	}
}

func TestSARIFFormatter(t *testing.T) {
	results := sampleResults()
	formatter := NewSARIFFormatter()

	var buf bytes.Buffer
	err := formatter.Format(&buf, results)
	if err != nil {
		t.Fatalf("SARIF formatting failed: %v", err)
	}

	var report SARIFReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to parse SARIF output: %v", err)
	}

	if report.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("Expected 1 run, got %d", len(report.Runs))
	}
	run := report.Runs[0]
	if run.Tool.Driver.Name != "possum" {
		t.Errorf("Expected driver name possum, got %s", run.Tool.Driver.Name)
	}
	// SARIF only contains failures (2 fails)
	if len(run.Results) != 2 {
		t.Errorf("Expected 2 SARIF results, got %d", len(run.Results))
	}
}

func TestJUnitFormatter(t *testing.T) {
	results := sampleResults()
	formatter := NewJUnitFormatter()

	var buf bytes.Buffer
	err := formatter.Format(&buf, results)
	if err != nil {
		t.Fatalf("JUnit formatting failed: %v", err)
	}

	var suites JUnitTestSuites
	if err := xml.Unmarshal(buf.Bytes(), &suites); err != nil {
		t.Fatalf("Failed to parse JUnit XML: %v", err)
	}

	if suites.Tests != 3 {
		t.Errorf("Expected 3 tests, got %d", suites.Tests)
	}
	if suites.Failures != 2 {
		t.Errorf("Expected 2 failures, got %d", suites.Failures)
	}
}
