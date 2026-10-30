package aws

import (
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
)

func TestARN_FormatARN(t *testing.T) {
	tests := []struct {
		name         string
		service      string
		region       string
		accountID    string
		resourceType string
		resourceID   string
		expected     string
	}{
		{
			name:       "S3 Bucket",
			service:    "s3",
			resourceID: "my-audit-bucket",
			expected:   "arn:aws:s3:::my-audit-bucket",
		},
		{
			name:         "IAM Role",
			service:      "iam",
			accountID:    "111222333444",
			resourceType: "role",
			resourceID:   "AppAdminRole",
			expected:     "arn:aws:iam::111222333444:role/AppAdminRole",
		},
		{
			name:         "EC2 Instance",
			service:      "ec2",
			region:       "us-east-1",
			accountID:    "111222333444",
			resourceType: "instance",
			resourceID:   "i-0123456789abcdef0",
			expected:     "arn:aws:ec2:us-east-1:111222333444:instance/i-0123456789abcdef0",
		},
		{
			name:         "EBS Volume",
			service:      "ec2",
			region:       "eu-west-1",
			accountID:    "111222333444",
			resourceType: "volume",
			resourceID:   "vol-0987654321",
			expected:     "arn:aws:ec2:eu-west-1:111222333444:volume/vol-0987654321",
		},
		{
			name:       "Already an ARN",
			service:    "s3",
			resourceID: "arn:aws:s3:::existing-arn-bucket",
			expected:   "arn:aws:s3:::existing-arn-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatARN(tt.service, tt.region, tt.accountID, tt.resourceType, tt.resourceID)
			assert.Equal(t, tt.expected, got)
			assert.True(t, IsARN(got))
		})
	}
}

func TestARN_StandardizeResultARN(t *testing.T) {
	res := model.ScanResult{
		ResourceID:   "my-prod-assets",
		ResourceType: "S3",
		Region:       "us-east-1",
		AccountID:    "999888777666",
		RuleID:       "s3_bucket_level_public_access_block",
		Nodes: []model.Node{
			{ID: "my-prod-assets", NodeType: "S3"},
		},
		Edges: []model.Edge{
			{From: "INTERNET", To: "my-prod-assets", Relation: "accesses"},
		},
	}

	StandardizeResultARN(&res, "999888777666", "us-east-1")

	expectedARN := "arn:aws:s3:::my-prod-assets"
	assert.Equal(t, expectedARN, res.ResourceID)
	assert.Equal(t, expectedARN, res.Nodes[0].ID)
	assert.Equal(t, expectedARN, res.Edges[0].To)

	metrics, ok := res.Metrics.(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, "my-prod-assets", metrics["DisplayName"])
}

func TestARN_NormalizeRegion(t *testing.T) {
	assert.Equal(t, "global", NormalizeRegion("global", "us-east-1"))
	assert.Equal(t, "global", NormalizeRegion("GLOBAL", "us-east-1"))
	assert.Equal(t, "us-west-2", NormalizeRegion("", "us-west-2"))
	assert.Equal(t, "us-west-2", NormalizeRegion("regional", "us-west-2"))
	assert.Equal(t, "us-east-1", NormalizeRegion("us-east-1a", "us-west-2"))
	assert.Equal(t, "eu-central-1", NormalizeRegion("eu-central-1b", "us-east-1"))
	assert.Equal(t, "us-gov-west-1", NormalizeRegion("us-gov-west-1a", "us-east-1"))
}

func TestARN_StandardizeResultARN_PreservesAndNormalizesAccountAndRegion(t *testing.T) {
	// 1. Regional resource with AZ in Region and empty AccountID
	ebsRes := model.ScanResult{
		ResourceID:   "vol-0abc123def456",
		ResourceType: "AWS::EC2::Volume",
		Region:       "us-east-1a",
		RuleID:       "ec2_ebs_volume_encryption",
	}
	StandardizeResultARN(&ebsRes, "222233334444", "us-east-1")
	assert.Equal(t, "222233334444", ebsRes.AccountID)
	assert.Equal(t, "us-east-1", ebsRes.Region)
	assert.Equal(t, "arn:aws:ec2:us-east-1:222233334444:volume/vol-0abc123def456", ebsRes.ResourceID)

	// 2. Global resource with "regional" placeholder
	iamRes := model.ScanResult{
		ResourceID:   "AdminRole",
		ResourceType: "AWS::IAM::Role",
		Region:       "regional",
		AccountID:    "333344445555",
		RuleID:       "iam_admin_policy",
	}
	StandardizeResultARN(&iamRes, "111122223333", "us-west-2")
	assert.Equal(t, "333344445555", iamRes.AccountID)
	assert.Equal(t, "global", iamRes.Region)
	assert.Equal(t, "arn:aws:iam::333344445555:role/AdminRole", iamRes.ResourceID)

	// 3. Existing ARN extracts AccountID and Region when missing/placeholder
	rdsRes := model.ScanResult{
		ResourceID:   "arn:aws:rds:eu-west-1:777788889999:db:prod-mysql",
		ResourceType: "AWS::RDS::DBInstance",
		Region:       "regional",
		RuleID:       "rds_instance_public_access",
	}
	StandardizeResultARN(&rdsRes, "", "us-east-1")
	assert.Equal(t, "777788889999", rdsRes.AccountID)
	assert.Equal(t, "eu-west-1", rdsRes.Region)
	assert.Equal(t, "arn:aws:rds:eu-west-1:777788889999:db:prod-mysql", rdsRes.ResourceID)
}

func TestARN_StandardizeResultsARN(t *testing.T) {
	results := []model.ScanResult{
		{
			ResourceID:   "vol-12345",
			ResourceType: "AWS::EC2::Volume",
			Region:       "us-east-1",
			RuleID:       "ebs_volume_unused_attached",
		},
	}
	standardized := StandardizeResultsARN(results, "123456789012", "us-east-1")
	assert.Equal(t, "123456789012", standardized[0].AccountID)
	assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:volume/vol-12345", standardized[0].ResourceID)
}

