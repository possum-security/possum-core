package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSecurityHubApi struct {
	describeHubFn func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

func (m *mockSecurityHubApi) DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	if m.describeHubFn != nil {
		return m.describeHubFn(ctx, params, optFns...)
	}
	return &securityhub.DescribeHubOutput{}, nil
}

func TestSecurityHubScanner_EnabledPass(t *testing.T) {
	mock := &mockSecurityHubApi{
		describeHubFn: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
			return &securityhub.DescribeHubOutput{
				HubArn:             aws.String("arn:aws:securityhub:us-east-1:123456789012:hub/default"),
				SubscribedAt:       aws.String("2023-01-01T00:00:00Z"),
				AutoEnableControls: aws.Bool(true),
			}, nil
		},
	}

	scanner := NewSecurityHubScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "SecurityHub-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, "arn:aws:securityhub:us-east-1:123456789012:hub/default", res.ResourceID)
	assert.Equal(t, "SecaaS-SecurityHub", res.ResourceType)
	assert.Equal(t, "us-east-1", res.Region)
	assert.Equal(t, "PASS", res.Status)
	assert.Equal(t, "securityhub_enabled", res.RuleID)
	assert.Equal(t, "INFO", res.Severity)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "arn:aws:securityhub:us-east-1:123456789012:hub/default", metrics["HubArn"])
	assert.Equal(t, "2023-01-01T00:00:00Z", metrics["SubscribedAt"])
	assert.Equal(t, true, metrics["AutoEnableControls"])

	require.Len(t, res.Nodes, 1)
	assert.Equal(t, "arn:aws:securityhub:us-east-1:123456789012:hub/default", res.Nodes[0].ID)
	assert.Equal(t, "SecaaS-SecurityHub", res.Nodes[0].NodeType)
}

func TestSecurityHubScanner_NotFoundFail(t *testing.T) {
	mock := &mockSecurityHubApi{
		describeHubFn: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
			return nil, &securityhubtypes.ResourceNotFoundException{
				Message: aws.String("Hub not found in region"),
			}
		},
	}

	scanner := NewSecurityHubScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, "securityhub-us-east-1", res.ResourceID)
	assert.Equal(t, "SecaaS-SecurityHub", res.ResourceType)
	assert.Equal(t, "FAIL", res.Status)
	assert.Equal(t, "securityhub_enabled", res.RuleID)
	assert.Equal(t, "HIGH", res.Severity)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Enable AWS Security Hub in all active regions.", metrics["Recommendation"])
	assert.Contains(t, metrics["SecurityIssues"], "AWS Security Hub is not enabled in this region")
}

func TestSecurityHubScanner_GenericErrorFail(t *testing.T) {
	mock := &mockSecurityHubApi{
		describeHubFn: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
			return nil, errors.New("InvalidAccessException: Account 123456789012 is not subscribed to AWS Security Hub")
		},
	}

	scanner := NewSecurityHubScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, "securityhub-eu-west-1", res.ResourceID)
	assert.Equal(t, "FAIL", res.Status)
	assert.Equal(t, "HIGH", res.Severity)
}

func TestSecurityHubScanner_NilOutputFail(t *testing.T) {
	mock := &mockSecurityHubApi{
		describeHubFn: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
			return nil, nil
		},
	}

	scanner := NewSecurityHubScannerWithClient(mock, "ap-northeast-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, "FAIL", res.Status)
	assert.Equal(t, "HIGH", res.Severity)
}

func TestSecurityHubScanner_GlobalRegion(t *testing.T) {
	mock := &mockSecurityHubApi{
		describeHubFn: func(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
			return nil, errors.New("disabled")
		},
	}

	scanner := NewSecurityHubScannerWithClient(mock, "")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "securityhub-global", results[0].ResourceID)
	assert.Equal(t, "global", results[0].Region)
}
