package secaas_test

import (
	"testing"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	"github.com/amirmahdy/possum-core/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// TestSecaasScannersInitializationAndInterface verifies that all SecaaS scanners instantiate,
// implement the Scanner interface, and return non-empty scanner names.
func TestSecaasScannersInitializationAndInterface(t *testing.T) {
	cfg := aws.Config{}

	scanners := []scanner.Scanner{
		secaas.NewS3Scanner(cfg),
		secaas.NewLambdaScanner(cfg),
		secaas.NewDynamoDBScanner(cfg),
		secaas.NewCloudTrailScanner(cfg),
		secaas.NewVPCScanner(cfg),
		secaas.NewKMSScanner(cfg),
		secaas.NewAPIGatewayScanner(cfg),
		secaas.NewRDSScanner(cfg),
		secaas.NewELBScanner(cfg),
		secaas.NewMessagingScanner(cfg),
		secaas.NewEKSScanner(cfg),
		secaas.NewCognitoScanner(cfg),
		secaas.NewCloudFormationScanner(cfg),
		secaas.NewACMScanner(cfg),
		secaas.NewVPCAdvancedScanner(cfg),
		secaas.NewIAMScanner(cfg),
		secaas.NewCloudFrontScanner(cfg),
		secaas.NewRoute53Scanner(cfg),
		secaas.NewRedshiftScanner(cfg),
		secaas.NewNeptuneScanner(cfg),
		secaas.NewBackupScanner(cfg),
		secaas.NewDMSScanner(cfg),
	}

	if len(scanners) == 0 {
		t.Fatalf("Expected scanners to be instantiated, got 0")
	}

	for _, s := range scanners {
		if s.Name() == "" {
			t.Errorf("Scanner %T returned empty name", s)
		}
	}
}

// TestScanResultSchemaValidation tests the unified ScanResult struct contract.
func TestScanResultSchemaValidation(t *testing.T) {
	result := scanner.ScanResult{
		ResourceID:   "arn:aws:s3:::test-bucket",
		ResourceType: "SecaaS-S3",
		Region:       "us-east-1",
		RuleID:       "s3_bucket_level_public_access_block",
		Severity:     "HIGH",
	}

	if result.RuleID == "" {
		t.Errorf("Expected non-empty RuleID")
	}

	if result.Severity != "HIGH" && result.Severity != "CRITICAL" && result.Severity != "MEDIUM" && result.Severity != "LOW" && result.Severity != "INFO" {
		t.Errorf("Unexpected Severity level: %s", result.Severity)
	}
}
