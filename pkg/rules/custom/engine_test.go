package custom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
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

func TestEngine_RichExpressions_BooleansComparisonsMethodsAndNestedMaps(t *testing.T) {
	ctx := ResourceContext{
		ResourceID:   "arn:aws:rds:us-east-1:123456789012:db:prod-orders-db",
		ResourceType: "RDS",
		Region:       "us-east-1",
		Tags: map[string]string{
			"env":         "production",
			"cost-center": "fin-104",
			"owner":       "platform-team@example.com",
		},
		Properties: map[string]interface{}{
			"storage_size":        250,
			"backup_retention":    14,
			"publicly_accessible": false,
			"encryption": map[string]interface{}{
				"enabled":    true,
				"kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
			},
			"engine": "aurora-postgresql",
		},
	}

	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{
			name:     "nested tag bracket access and && operator",
			expr:     "resource.tags['env'] == 'production' && resource.tags['cost-center'].startsWith('fin-')",
			expected: true,
		},
		{
			name:     "boolean and/or with parentheses and comparisons",
			expr:     "(resource.tags['env'] == 'staging' or resource.tags['env'] == 'production') and properties.storage_size >= 100 and properties.backup_retention > 7",
			expected: true,
		},
		{
			name:     "negation with ! and nested map access",
			expr:     "!properties.publicly_accessible && properties.encryption.enabled == true && properties.encryption['kms_key_id'].startsWith('arn:aws:kms:')",
			expected: true,
		},
		{
			name:     "contains method on string field",
			expr:     "properties.engine.contains('postgres') && resource.tags['owner'].contains('@example.com')",
			expected: true,
		},
		{
			name:     "in and not in list operators",
			expr:     "region in ['us-east-1', 'us-west-2'] && resource.tags['env'] not in ['dev', 'sandbox']",
			expected: true,
		},
		{
			name:     "numeric < and <= comparisons",
			expr:     "properties.backup_retention <= 30 && properties.backup_retention < 7",
			expected: false,
		},
		{
			name:     "|| operator where right branch succeeds",
			expr:     "resource.tags['env'] == 'dev' || properties.encryption.enabled == true",
			expected: true,
		},
	}

	engine := NewEngine()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := Rule{
				ID:           "test_rule",
				ResourceType: "RDS",
				Condition:    tc.expr,
			}
			passed, err := engine.EvaluateRule(rule, ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, passed)
		})
	}
}

func TestEngine_CompilationAndEvaluationErrorsSurfaced(t *testing.T) {
	// 1. Invalid expression syntax must fail LoadRule
	badYAML := `
id: broken_rule
resource_type: S3
severity: HIGH
condition: "resource.tags['env'] === 'prod'"
`
	_, err := LoadRule(strings.NewReader(badYAML))
	require.Error(t, err, "LoadRule must fail on invalid operator '==='")

	// 2. Unclosed string literal must fail LoadRule
	unclosedYAML := `
id: unclosed_quote
resource_type: S3
condition: "resource.tags['env] == 'prod'"
`
	_, err = LoadRule(strings.NewReader(unclosedYAML))
	require.Error(t, err, "LoadRule must fail on unclosed quote")

	// 3. Unknown method call must fail validation
	unknownMethodRule := Rule{
		ID:        "unknown_method",
		Condition: "resource.tags['env'].magicMatch('prod')",
	}
	require.Error(t, ValidateRule(unknownMethodRule))

	// 4. LoadDirectory must surface errors when a directory contains an invalid rule file
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "bad.yaml"), []byte(badYAML), 0644))
	engine := NewEngine()
	_, err = engine.LoadDirectory(tmpDir)
	require.Error(t, err, "LoadDirectory must surface rule validation error")

	// 5. Evaluate must surface runtime evaluation errors (e.g. numeric comparison on non-numeric value)
	evalEngine := NewEngine(Rule{
		ID:           "bad_numeric_compare",
		ResourceType: "S3",
		Condition:    "resource.tags['env'] > 100",
	})
	_, evalErr := evalEngine.Evaluate(ResourceContext{
		ResourceID:   "bucket-1",
		ResourceType: "S3",
		Tags:         map[string]string{"env": "non-numeric"},
	})
	require.Error(t, evalErr, "Evaluate must surface numeric comparison error")
	assert.NotEmpty(t, evalEngine.LastErrors())

	// 6. Verify docs/examples/custom-rules.yaml loads and evaluates cleanly
	exampleFile, err := os.Open("../../../docs/examples/custom-rules.yaml")
	if err == nil {
		defer exampleFile.Close()
		exRule, err := LoadRule(exampleFile)
		require.NoError(t, err)
		assert.Equal(t, "custom_prod_s3_governance", exRule.ID)
	}
}

func TestEngine_OperatorsAndStructuredNodes(t *testing.T) {
	rule := Rule{
		ID:           "test_operators",
		ResourceType: "*",
		Severity:     model.SeverityHigh,
		Conditions: &StructuredCondition{
			And: []*ConditionNode{
				{Field: "tags.Name", Op: "startswith", Value: "prod-"},
				{Field: "tags.Name", Op: "endswith", Value: "-app"},
				{Field: "tags.Name", Op: "contains", Value: "web"},
				{Field: "tags.Environment", Op: "in", Value: []interface{}{"prod", "production"}},
				{Field: "tags.Tier", Op: "not_in", Value: []interface{}{"deprecated", "legacy"}},
				{Field: "tags.Owner", Op: "exists"},
				{Field: "tags.EmptyField", Op: "empty"},
				{Field: "Properties.Size", Op: ">", Value: 10},
				{Field: "Properties.Size", Op: "<=", Value: 50},
			},
		},
	}

	require.NoError(t, ValidateRule(rule))
	engine := NewEngine(rule)

	// Context matching all conditions
	matchingCtx := ResourceContext{
		ResourceID:   "res-1",
		ResourceType: "AWS::EC2::Instance",
		Tags: map[string]string{
			"Name":        "prod-web-app",
			"Environment": "production",
			"Tier":        "frontend",
			"Owner":       "secops",
			"EmptyField":  "",
		},
		Properties: map[string]interface{}{
			"Size": 25,
		},
	}
	findings := engine.EvaluateContext(matchingCtx)
	assert.Empty(t, findings) // Compliant (no violation)

	// Context failing one condition
	nonMatchingCtx := matchingCtx
	nonMatchingCtx.Tags = map[string]string{
		"Name": "dev-db",
	}
	findingsBad := engine.EvaluateContext(nonMatchingCtx)
	assert.Len(t, findingsBad, 1) // Violation detected
}

func TestEngine_StructuredCondition_OrAndNot(t *testing.T) {
	rule := Rule{
		ID:           "test_or_not",
		ResourceType: "S3",
		Severity:     model.SeverityCritical,
		Conditions: &StructuredCondition{
			Or: []*ConditionNode{
				{Field: "tags.Environment", Op: "==", Value: "sandbox"},
				{
					Not: &ConditionNode{
						Field: "tags.Encrypted",
						Op:    "==",
						Value: "false",
					},
				},
			},
		},
	}
	require.NoError(t, ValidateRule(rule))
	engine := NewEngine(rule)

	// Sandbox environment -> passes OR branch 1
	resSandbox := engine.EvaluateContext(ResourceContext{
		ResourceID:   "b-sandbox",
		ResourceType: "S3",
		Tags:         map[string]string{"Environment": "sandbox", "Encrypted": "false"},
	})
	assert.Empty(t, resSandbox)

	// Encrypted != false -> passes NOT branch
	resEncrypted := engine.EvaluateContext(ResourceContext{
		ResourceID:   "b-prod",
		ResourceType: "S3",
		Tags:         map[string]string{"Environment": "prod", "Encrypted": "true"},
	})
	assert.Empty(t, resEncrypted)

	// Prod + unencrypted -> fails both
	resBad := engine.EvaluateContext(ResourceContext{
		ResourceID:   "b-bad",
		ResourceType: "S3",
		Tags:         map[string]string{"Environment": "prod", "Encrypted": "false"},
	})
	assert.Len(t, resBad, 1)
}

func TestEngine_ValidationErrorsAndEdgeCases(t *testing.T) {
	// Unknown operator
	badOpRule := Rule{
		ID: "bad_op",
		Conditions: &StructuredCondition{
			And: []*ConditionNode{
				{Field: "tags.Owner", Op: "unsupported_operator"},
			},
		},
	}
	require.Error(t, ValidateRule(badOpRule))

	// Nil node
	nilNodeRule := Rule{
		ID: "nil_node",
		Conditions: &StructuredCondition{
			And: []*ConditionNode{nil},
		},
	}
	require.Error(t, ValidateRule(nilNodeRule))

	// LoadDirectory on non-existent directory
	engine := NewEngine()
	_, err := engine.LoadDirectory("/non/existent/path/123456")
	require.Error(t, err)
}
