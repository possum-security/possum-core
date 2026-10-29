package iac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIaC_ScanPlanJSON(t *testing.T) {
	planJSON := `{
  "format_version": "1.0",
  "terraform_version": "1.7.0",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.bad_bucket",
      "type": "aws_s3_bucket",
      "name": "bad_bucket",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "my-unprotected-data"
        }
      }
    },
    {
      "address": "aws_security_group.allow_ssh",
      "type": "aws_security_group",
      "name": "allow_ssh",
      "change": {
        "actions": ["create"],
        "after": {
          "ingress": [
            {
              "cidr_blocks": ["0.0.0.0/0"],
              "from_port": 22,
              "to_port": 22,
              "protocol": "tcp"
            }
          ]
        }
      }
    },
    {
      "address": "aws_ebs_volume.data_vol",
      "type": "aws_ebs_volume",
      "name": "data_vol",
      "change": {
        "actions": ["create"],
        "after": {
          "size": 100,
          "encrypted": false
        }
      }
    }
  ]
}`

	scanner := NewScanner()
	findings, err := scanner.ScanPlan(strings.NewReader(planJSON))
	require.NoError(t, err)

	require.Len(t, findings, 3)

	ruleIDs := []string{findings[0].RuleID, findings[1].RuleID, findings[2].RuleID}
	assert.Contains(t, ruleIDs, "s3_bucket_level_public_access_block")
	assert.Contains(t, ruleIDs, "ec2_security_group_open_to_world")
	assert.Contains(t, ruleIDs, "ebs_volume_encryption_enabled")

	// Verify cost waste estimation on EBS volume
	for _, f := range findings {
		if f.RuleID == "ebs_volume_encryption_enabled" {
			assert.InDelta(t, 8.0, f.CostWasteMo, 0.01) // 100GB * $0.08
		}
	}
}

func TestIaC_ScanTFFile(t *testing.T) {
	tfContent := `
resource "aws_s3_bucket" "public_site" {
  bucket = "static-assets"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	tmpDir := t.TempDir()
	tfPath := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(tfPath, []byte(tfContent), 0644)
	require.NoError(t, err)

	scanner := NewScanner()
	findings, err := scanner.ScanTFFile(tfPath)
	require.NoError(t, err)

	assert.NotEmpty(t, findings)
	var foundS3, foundSG bool
	for _, f := range findings {
		if f.RuleID == "s3_bucket_level_public_access_block" {
			foundS3 = true
		}
		if f.RuleID == "ec2_security_group_open_to_world" {
			foundSG = true
		}
	}
	assert.True(t, foundS3, "Expected s3 public access finding")
	assert.True(t, foundSG, "Expected open security group finding")
}
