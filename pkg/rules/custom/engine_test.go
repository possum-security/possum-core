package custom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_YAMLRuleLoadingAndEvaluation(t *testing.T) {
	yamlRule := `
id: custom_s3_retention_tag
name: S3 Bucket Retention Tag Mandatory
service: s3
resource_type: S3
severity: HIGH
category: SECURITY
condition: "resource.tags['Retention'] in ['30d', '90d', '365d']"
message: "S3 bucket must have a compliant Retention tag"
remediation: "Add an approved Retention tag to the S3 bucket"
compliance:
  - "internal-data-governance-2026"
`
	rule, err := LoadRule(strings.NewReader(yamlRule))
	require.NoError(t, err)
	assert.Equal(t, "custom_s3_retention_tag", rule.ID)
	assert.Equal(t, model.SeverityHigh, rule.Severity)

	engine := NewEngine(*rule)

	// Context 1: Non-compliant bucket (missing or bad tag)
	badCtx := ResourceContext{
		ResourceID:   "my-prod-data",
		ResourceType: "S3",
		Region:       "us-east-1",
		Tags: map[string]string{
			"Retention": "none",
			"Owner":     "secops",
		},
	}
	findings := engine.EvaluateContext(badCtx)
	require.Len(t, findings, 1)
	assert.Equal(t, "custom_s3_retention_tag", findings[0].RuleID)
	assert.Equal(t, model.StatusFail, findings[0].Status)
	assert.Equal(t, model.SeverityHigh, findings[0].Severity)
	assert.Equal(t, "my-prod-data", findings[0].ResourceID)

	// Context 2: Compliant bucket
	goodCtx := ResourceContext{
		ResourceID:   "my-compliant-bucket",
		ResourceType: "S3",
		Region:       "us-east-1",
		Tags: map[string]string{
			"Retention": "90d",
		},
	}
	goodFindings := engine.EvaluateContext(goodCtx)
	assert.Empty(t, goodFindings)
}

func TestEngine_StructuredConditions(t *testing.T) {
	rule := Rule{
		ID:           "ec2_prod_monitoring",
		ResourceType: "EC2",
		Severity:     model.SeverityCritical,
		Mode:         "violate",
		Conditions: &StructuredCondition{
			And: []*ConditionNode{
				{Field: "tags.Environment", Op: "==", Value: "production"},
				{Field: "Properties.DetailedMonitoring", Op: "!=", Value: "true"},
			},
		},
		Message: "Production instances must have detailed monitoring enabled",
	}

	engine := NewEngine(rule)

	// Prod instance with detailed monitoring false -> violation
	res1 := engine.EvaluateContext(ResourceContext{
		ResourceID:   "i-0123456789",
		ResourceType: "EC2",
		Tags:         map[string]string{"Environment": "production"},
		Properties:   map[string]interface{}{"DetailedMonitoring": "false"},
	})
	assert.Len(t, res1, 1)

	// Non-prod instance -> no violation
	res2 := engine.EvaluateContext(ResourceContext{
		ResourceID:   "i-staging-001",
		ResourceType: "EC2",
		Tags:         map[string]string{"Environment": "staging"},
		Properties:   map[string]interface{}{"DetailedMonitoring": "false"},
	})
	assert.Empty(t, res2)
}

func TestEngine_DirectoryLoading(t *testing.T) {
	tmpDir := t.TempDir()
	r1 := `
id: rule_one
resource_type: "*"
severity: LOW
condition: "tags.Team != ''"
`
	err := os.WriteFile(filepath.Join(tmpDir, "r1.yaml"), []byte(r1), 0644)
	require.NoError(t, err)

	engine := NewEngine()
	count, err := engine.LoadDirectory(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Len(t, engine.Rules(), 1)
}
