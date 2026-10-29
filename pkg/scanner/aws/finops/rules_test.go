package finops

import (
	"testing"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestFinOps_BuildFinOpsResult(t *testing.T) {
	// Orphaned/failed finding
	resFail := BuildFinOpsResult(FinOpsResultParams{
		ResourceID:   "vol-0123456789",
		ResourceType: "EBS",
		Region:       "us-east-1",
		RuleID:       RuleEBSVolumeUnused,
		DisplayName:  "orphan-data-vol",
		IsOrphaned:   true,
		Cost:         25.50,
		Title:        "Unattached EBS Volume",
		Description:  "Volume is not attached to any EC2 instance.",
		Remediation:  "Delete volume",
	})

	assert.Equal(t, "vol-0123456789", resFail.ResourceID)
	assert.Equal(t, RuleEBSVolumeUnused, resFail.RuleID)
	assert.Equal(t, model.CategoryFinOps, resFail.Category)
	assert.Equal(t, model.StatusFail, resFail.Status)
	assert.Equal(t, model.SeverityMedium, resFail.Severity)
	assert.Equal(t, 25.50, resFail.CostWasteMo)

	metrics, ok := resFail.Metrics.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "orphan-data-vol", metrics["DisplayName"])

	// Active/healthy finding
	resPass := BuildFinOpsResult(FinOpsResultParams{
		ResourceID:   "vol-attached-active",
		ResourceType: "EBS",
		Region:       "us-east-1",
		RuleID:       RuleEBSVolumeUnused,
		IsOrphaned:   false,
		Cost:         25.50,
		Title:        "Attached EBS Volume",
	})

	assert.Equal(t, model.StatusPass, resPass.Status)
	assert.Equal(t, model.SeverityInfo, resPass.Severity)
	assert.Equal(t, 0.0, resPass.CostWasteMo)
}

func TestFinOps_MetaScannersContract(t *testing.T) {
	dummyCfg := aws.Config{Region: "us-east-1"}

	scanners := []scanner.MetaScanner{
		NewEBSScanner(dummyCfg),
		NewEC2Scanner(dummyCfg),
		NewEIPScanner(dummyCfg),
		NewNATGatewayScanner(dummyCfg),
		NewRDSScanner(dummyCfg),
		NewELBScanner(dummyCfg),
		NewLambdaScanner(dummyCfg),
		NewENIScanner(dummyCfg),
		NewCloudFormationScanner(dummyCfg),
		NewDynamoDBScanner(dummyCfg),
		NewRedshiftScanner(dummyCfg),
		NewCloudFrontScanner(dummyCfg),
		NewS3Scanner(dummyCfg),
		NewCostExplorerScanner(dummyCfg, 30),
		NewECRScanner(dummyCfg, 180, true),
		NewECSScanner(dummyCfg),
	}

	for _, sc := range scanners {
		meta := sc.Meta()
		assert.NotEmpty(t, meta.ID, "Scanner %s has empty Meta.ID", sc.Name())
		assert.NotEmpty(t, meta.Service, "Scanner %s has empty Meta.Service", sc.Name())
		assert.NotEmpty(t, meta.CheckIDs, "Scanner %s has empty Meta.CheckIDs", sc.Name())
		assert.Equal(t, model.CategoryFinOps, meta.Category)
	}
}
