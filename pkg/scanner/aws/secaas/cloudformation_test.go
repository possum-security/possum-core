package secaas

import (
	"context"
	"fmt"
	"testing"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCloudFormationApi struct {
	describeStacksPages []*cloudformation.DescribeStacksOutput
	pageIndex           int
	err                 error
}

func (m *mockCloudFormationApi) DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.describeStacksPages) == 0 {
		return &cloudformation.DescribeStacksOutput{}, nil
	}
	if m.pageIndex < len(m.describeStacksPages) {
		page := m.describeStacksPages[m.pageIndex]
		m.pageIndex++
		return page, nil
	}
	return &cloudformation.DescribeStacksOutput{}, nil
}

func TestCloudFormationScanner_Compliant(t *testing.T) {
	stackID := "arn:aws:cloudformation:us-east-1:123456789012:stack/secure-stack/d0a7a0b0-1234"
	stackName := "secure-stack"
	roleARN := "arn:aws:iam::123456789012:role/cloudformation-deploy-role"

	mockClient := &mockCloudFormationApi{
		describeStacksPages: []*cloudformation.DescribeStacksOutput{
			{
				Stacks: []cftypes.Stack{
					{
						StackId:                     aws.String(stackID),
						StackName:                   aws.String(stackName),
						RoleARN:                     aws.String(roleARN),
						EnableTerminationProtection: aws.Bool(true),
						Outputs: []cftypes.Output{
							{
								OutputKey:   aws.String("VpcId"),
								OutputValue: aws.String("vpc-0123456789abcdef0"),
								Description: aws.String("VPC identifier for application tier"),
							},
							{
								OutputKey:   aws.String("PublicSubnetId"),
								OutputValue: aws.String("subnet-0123456789abcdef1"),
								Description: aws.String("Subnet identifier for web servers"),
							},
						},
					},
				},
			},
		},
	}

	cfScanner := NewCloudFormationScannerWithClient(mockClient)
	assert.Equal(t, "CloudFormation-SecaaS-Scanner", cfScanner.Name())

	results, err := cfScanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		assert.Equal(t, stackID, r.ResourceID)
		assert.Equal(t, "SecaaS-CloudFormation", r.ResourceType)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)
		assert.False(t, r.IsOrphaned)
		resultsByRule[r.RuleID] = r
	}

	// 1. Termination protection
	termRes, ok := resultsByRule["cloudformation_stacks_termination_protection_enabled"]
	require.True(t, ok)
	assert.Equal(t, "PASS", termRes.Status)
	assert.Equal(t, "INFO", termRes.Severity)
	termMetrics := termRes.Metrics.(map[string]interface{})
	assert.Equal(t, stackName, termMetrics["StackName"])
	assert.Equal(t, roleARN, termMetrics["RoleARN"])

	// 2. Output secrets
	secRes, ok := resultsByRule["cloudformation_stack_outputs_find_secrets"]
	require.True(t, ok)
	assert.Equal(t, "PASS", secRes.Status)
	assert.Equal(t, "INFO", secRes.Severity)
	secMetrics := secRes.Metrics.(map[string]interface{})
	assert.Equal(t, stackName, secMetrics["StackName"])
	assert.Equal(t, roleARN, secMetrics["RoleARN"])
	assert.Nil(t, secMetrics["SecurityIssues"])
}

func TestCloudFormationScanner_NonCompliant_SecretsInOutputs(t *testing.T) {
	stackID := "arn:aws:cloudformation:us-east-1:123456789012:stack/leak-stack/e1b8b1c1-5678"
	stackName := "leak-stack"
	roleARN := "arn:aws:iam::123456789012:role/cfn-role"

	tests := []struct {
		name       string
		outputs    []cftypes.Output
		keywordHit string
	}{
		{
			name: "Output value contains AWS Access Key (AKIA)",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("AccessKey"),
					OutputValue: aws.String("AKIAIOSFODNN7EXAMPLE"),
					Description: aws.String("IAM user access key"),
				},
			},
			keywordHit: "AKIA",
		},
		{
			name: "Output value contains RSA Private Key",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("ServerKey"),
					OutputValue: aws.String("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0..."),
					Description: aws.String("SSL certificate private key"),
				},
			},
			keywordHit: "private key pattern",
		},
		{
			name: "Output key contains password keyword",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("DatabasePassword"),
					OutputValue: aws.String("mypassword123"),
					Description: aws.String("Master DB password"),
				},
			},
			keywordHit: "password",
		},
		{
			name: "Output key contains secret keyword",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("ClientSecret"),
					OutputValue: aws.String("xyz789"),
					Description: aws.String("OAuth client secret"),
				},
			},
			keywordHit: "secret",
		},
		{
			name: "Output key contains api_key keyword",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("Stripe_API_KEY"),
					OutputValue: aws.String("sk_live_123456"),
					Description: aws.String("Payment gateway key"),
				},
			},
			keywordHit: "api_key",
		},
		{
			name: "Output key contains token keyword",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("AuthToken"),
					OutputValue: aws.String("ghp_testtoken987654"),
					Description: aws.String("GitHub integration token"),
				},
			},
			keywordHit: "token",
		},
		{
			name: "Output description contains private_key keyword",
			outputs: []cftypes.Output{
				{
					OutputKey:   aws.String("SSHKeyMaterial"),
					OutputValue: aws.String("ssh-rsa AAAAB3..."),
					Description: aws.String("Deployer private_key for host access"),
				},
			},
			keywordHit: "private_key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient := &mockCloudFormationApi{
				describeStacksPages: []*cloudformation.DescribeStacksOutput{
					{
						Stacks: []cftypes.Stack{
							{
								StackId:                     aws.String(stackID),
								StackName:                   aws.String(stackName),
								RoleARN:                     aws.String(roleARN),
								EnableTerminationProtection: aws.Bool(true),
								Outputs:                     tc.outputs,
							},
						},
					},
				},
			}

			cfScanner := NewCloudFormationScannerWithClient(mockClient)
			results, err := cfScanner.Scan(context.Background())
			require.NoError(t, err)

			var secretResult *scanner.ScanResult
			for _, r := range results {
				if r.RuleID == "cloudformation_stack_outputs_find_secrets" {
					secretResult = &r
					break
				}
			}

			require.NotNil(t, secretResult, "Expected cloudformation_stack_outputs_find_secrets result")
			assert.Equal(t, stackID, secretResult.ResourceID)
			assert.Equal(t, "SecaaS-CloudFormation", secretResult.ResourceType)
			assert.Equal(t, "FAIL", secretResult.Status)
			assert.Equal(t, "CRITICAL", secretResult.Severity)
			assert.True(t, secretResult.IsOrphaned)

			metrics := secretResult.Metrics.(map[string]interface{})
			assert.Equal(t, "Remove secrets from CloudFormation stack outputs; use Secrets Manager dynamic references or NoEcho.", metrics["Recommendation"])
			issues, ok := metrics["SecurityIssues"].([]string)
			require.True(t, ok)
			assert.NotEmpty(t, issues)

			foundKeyword := false
			for _, issue := range issues {
				if assert.Contains(t, issue, tc.keywordHit) {
					foundKeyword = true
					break
				}
			}
			assert.True(t, foundKeyword, "Expected keyword hit %s in issues: %v", tc.keywordHit, issues)
		})
	}
}

func TestCloudFormationScanner_NonCompliant_TerminationProtection(t *testing.T) {
	stackID := "arn:aws:cloudformation:us-east-1:123456789012:stack/insecure-stack/f2c9c2d2-9012"
	stackName := "insecure-stack"

	mockClient := &mockCloudFormationApi{
		describeStacksPages: []*cloudformation.DescribeStacksOutput{
			{
				Stacks: []cftypes.Stack{
					{
						StackId:                     aws.String(stackID),
						StackName:                   aws.String(stackName),
						RoleARN:                     nil,             // Missing RoleARN
						EnableTerminationProtection: aws.Bool(false), // Disabled
						Outputs:                     nil,
					},
				},
			},
		},
	}

	cfScanner := NewCloudFormationScannerWithClient(mockClient)
	results, err := cfScanner.Scan(context.Background())
	require.NoError(t, err)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsByRule[r.RuleID] = r
	}

	termRes, ok := resultsByRule["cloudformation_stacks_termination_protection_enabled"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", termRes.Status)
	assert.Equal(t, "MEDIUM", termRes.Severity)
	assert.True(t, termRes.IsOrphaned)

	// Outputs check should still pass because outputs are empty
	secRes, ok := resultsByRule["cloudformation_stack_outputs_find_secrets"]
	require.True(t, ok)
	assert.Equal(t, "PASS", secRes.Status)
	assert.Equal(t, "INFO", secRes.Severity)
}

func TestCloudFormationScanner_Pagination(t *testing.T) {
	mockClient := &mockCloudFormationApi{
		describeStacksPages: []*cloudformation.DescribeStacksOutput{
			{
				NextToken: aws.String("page2-token"),
				Stacks: []cftypes.Stack{
					{
						StackId:   aws.String("stack-page-1"),
						StackName: aws.String("stack-1"),
					},
				},
			},
			{
				Stacks: []cftypes.Stack{
					{
						StackId:   aws.String("stack-page-2"),
						StackName: aws.String("stack-2"),
					},
				},
			},
		},
	}

	cfScanner := NewCloudFormationScannerWithClient(mockClient)
	results, err := cfScanner.Scan(context.Background())
	require.NoError(t, err)

	// 2 stacks * 2 checks each = 4 results
	assert.Len(t, results, 4)
	resourceIDs := make(map[string]bool)
	for _, r := range results {
		resourceIDs[r.ResourceID] = true
	}
	assert.True(t, resourceIDs["stack-page-1"])
	assert.True(t, resourceIDs["stack-page-2"])
}

func TestCloudFormationScanner_ResourceLimit(t *testing.T) {
	mockClient := &mockCloudFormationApi{
		describeStacksPages: []*cloudformation.DescribeStacksOutput{
			{
				Stacks: []cftypes.Stack{
					{StackId: aws.String("stack-1"), StackName: aws.String("s1")},
					{StackId: aws.String("stack-2"), StackName: aws.String("s2")},
					{StackId: aws.String("stack-3"), StackName: aws.String("s3")},
				},
			},
		},
	}

	cfScanner := NewCloudFormationScannerWithClient(mockClient)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)

	results, err := cfScanner.Scan(ctx)
	require.NoError(t, err)

	// Only 1 stack processed -> 2 checks
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "stack-1", r.ResourceID)
	}
}

func TestCloudFormationScanner_ClientError(t *testing.T) {
	mockClient := &mockCloudFormationApi{
		err: fmt.Errorf("aws api throttled"),
	}

	cfScanner := NewCloudFormationScannerWithClient(mockClient)
	results, err := cfScanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "aws api throttled")
}

func TestCloudFormationScanner_NilClient(t *testing.T) {
	cfScanner := NewCloudFormationScannerWithClient(nil)
	results, err := cfScanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "cloudformation client is not initialized")
}
