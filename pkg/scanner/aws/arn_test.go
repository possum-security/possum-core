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
