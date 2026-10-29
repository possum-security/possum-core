package rules

import (
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
)

func TestEmbeddedRuleCatalog(t *testing.T) {
	catalog, err := NewRuleCatalog()
	if err != nil {
		t.Fatalf("Failed to initialize embedded RuleCatalog: %v", err)
	}

	total := catalog.TotalChecks()
	if total < 200 {
		t.Errorf("Expected at least 200 embedded checks, got %d", total)
	}

	services := catalog.ListServices()
	if len(services) == 0 {
		t.Error("Expected services to be populated")
	}

	// Verify known check lookup
	check, ok := catalog.GetCheck("s3_bucket_level_public_access_block")
	if !ok {
		t.Errorf("Check s3_bucket_level_public_access_block not found in embedded catalog")
	} else {
		if check.ServiceName != "s3" {
			t.Errorf("Expected service name 's3', got %s", check.ServiceName)
		}
		if check.Severity != "HIGH" {
			t.Errorf("Expected severity 'HIGH', got %s", check.Severity)
		}
		if check.Remediation.Recommendation.Text == "" && check.Remediation.Code.CLI == "" {
			t.Errorf("Expected remediation details to be non-empty")
		}
	}

	// Verify filtering
	s3Checks := catalog.ListChecks(CheckFilter{ServiceName: "s3"})
	if len(s3Checks) == 0 {
		t.Errorf("Expected to find S3 checks, got 0")
	}
}

func TestRuleCatalog_EnrichResult(t *testing.T) {
	catalog := GetDefaultCatalog()

	res := model.ScanResult{
		RuleID:       "s3_bucket_level_public_access_block",
		ResourceID:   "arn:aws:s3:::my-bucket",
		ResourceType: "AWS::S3::Bucket",
	}

	catalog.EnrichResult(&res)

	if res.Title == "" {
		t.Error("Expected Title to be enriched from catalog")
	}
	if res.Description == "" {
		t.Error("Expected Description to be enriched from catalog")
	}
	if res.Remediation == "" {
		t.Error("Expected Remediation to be enriched from catalog")
	}
	if len(res.Compliance) == 0 {
		t.Error("Expected Compliance frameworks to be populated from catalog")
	}
}

func TestRuleCatalog_ComplianceFrameworks(t *testing.T) {
	catalog := GetDefaultCatalog()

	frameworks := catalog.ListComplianceFrameworks()
	if len(frameworks) == 0 {
		t.Error("Expected at least one compliance framework in catalog")
	}

	checks := catalog.GetChecksByFramework("cis-3.0")
	if len(checks) == 0 {
		// Try cis_1.4 or soc2 or pci
		checks = catalog.GetChecksByFramework("cis")
	}
	if len(checks) == 0 {
		t.Error("Expected checks to be found for CIS framework")
	}
}
