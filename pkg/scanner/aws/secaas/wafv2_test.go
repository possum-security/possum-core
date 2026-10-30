package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockWAFv2ScannerApi struct {
	listWebACLsFn             func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	getLoggingConfigurationFn func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error)
}

func (m *mockWAFv2ScannerApi) ListWebACLs(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
	if m.listWebACLsFn != nil {
		return m.listWebACLsFn(ctx, params, optFns...)
	}
	return &wafv2.ListWebACLsOutput{}, nil
}

func (m *mockWAFv2ScannerApi) GetLoggingConfiguration(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
	if m.getLoggingConfigurationFn != nil {
		return m.getLoggingConfigurationFn(ctx, params, optFns...)
	}
	return &wafv2.GetLoggingConfigurationOutput{}, nil
}

func TestWAFv2Scanner_LoggingEnabledPass(t *testing.T) {
	webACLArn := "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-web-acl/a1b2c3d4"
	logDest := "arn:aws:kinesis:us-east-1:123456789012:stream/aws-waf-logs"

	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			assert.Equal(t, wafv2types.ScopeRegional, params.Scope)
			return &wafv2.ListWebACLsOutput{
				WebACLs: []wafv2types.WebACLSummary{
					{
						ARN:  aws.String(webACLArn),
						Name: aws.String("my-web-acl"),
						Id:   aws.String("a1b2c3d4"),
					},
				},
			}, nil
		},
		getLoggingConfigurationFn: func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
			assert.Equal(t, webACLArn, *params.ResourceArn)
			return &wafv2.GetLoggingConfigurationOutput{
				LoggingConfiguration: &wafv2types.LoggingConfiguration{
					ResourceArn:           aws.String(webACLArn),
					LogDestinationConfigs: []string{logDest},
				},
			}, nil
		},
	}

	scanner := NewWAFv2ScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "WAFv2-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, webACLArn, res.ResourceID)
	assert.Equal(t, "SecaaS-WAFv2", res.ResourceType)
	assert.Equal(t, "us-east-1", res.Region)
	assert.Equal(t, "PASS", res.Status)
	assert.Equal(t, "wafv2_webacl_logging_enabled", res.RuleID)
	assert.Equal(t, "INFO", res.Severity)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "my-web-acl", metrics["WebACLName"])
	assert.Equal(t, "a1b2c3d4", metrics["WebACLId"])
	assert.Equal(t, []string{logDest}, metrics["LogDestinationConfigs"])

	require.Len(t, res.Nodes, 1)
	assert.Equal(t, webACLArn, res.Nodes[0].ID)
	assert.Equal(t, "SecaaS-WAFv2", res.Nodes[0].NodeType)

	require.Len(t, res.Edges, 1)
	assert.Equal(t, webACLArn, res.Edges[0].From)
	assert.Equal(t, logDest, res.Edges[0].To)
	assert.Equal(t, "LOGS_TO", res.Edges[0].Relation)
}

func TestWAFv2Scanner_LoggingDisabledFail(t *testing.T) {
	webACLArn := "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/unlogged-acl/e5f6g7h8"

	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			return &wafv2.ListWebACLsOutput{
				WebACLs: []wafv2types.WebACLSummary{
					{
						ARN:  aws.String(webACLArn),
						Name: aws.String("unlogged-acl"),
						Id:   aws.String("e5f6g7h8"),
					},
				},
			}, nil
		},
		getLoggingConfigurationFn: func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
			return nil, &wafv2types.WAFNonexistentItemException{
				Message: aws.String("Logging configuration not found"),
			}
		},
	}

	scanner := NewWAFv2ScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, webACLArn, res.ResourceID)
	assert.Equal(t, "SecaaS-WAFv2", res.ResourceType)
	assert.Equal(t, "FAIL", res.Status)
	assert.Equal(t, "wafv2_webacl_logging_enabled", res.RuleID)
	assert.Equal(t, "MEDIUM", res.Severity)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Enable logging on WAFv2 WebACLs.", metrics["Recommendation"])
	assert.Contains(t, metrics["SecurityIssues"], "WAFv2 WebACL logging is not configured")
}

func TestWAFv2Scanner_LoggingNilConfigurationFail(t *testing.T) {
	webACLArn := "arn:aws:wafv2:us-west-2:123456789012:regional/webacl/nil-log-acl/i9j0"

	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			return &wafv2.ListWebACLsOutput{
				WebACLs: []wafv2types.WebACLSummary{
					{
						ARN:  aws.String(webACLArn),
						Name: aws.String("nil-log-acl"),
						Id:   aws.String("i9j0"),
					},
				},
			}, nil
		},
		getLoggingConfigurationFn: func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
			return &wafv2.GetLoggingConfigurationOutput{
				LoggingConfiguration: nil,
			}, nil
		},
	}

	scanner := NewWAFv2ScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "MEDIUM", results[0].Severity)
}

func TestWAFv2Scanner_MultipleWebACLs(t *testing.T) {
	acl1Arn := "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/acl-1/1"
	acl2Arn := "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/acl-2/2"

	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			return &wafv2.ListWebACLsOutput{
				WebACLs: []wafv2types.WebACLSummary{
					{ARN: aws.String(acl1Arn), Name: aws.String("acl-1"), Id: aws.String("1")},
					{ARN: aws.String(acl2Arn), Name: aws.String("acl-2"), Id: aws.String("2")},
				},
			}, nil
		},
		getLoggingConfigurationFn: func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
			if *params.ResourceArn == acl1Arn {
				return &wafv2.GetLoggingConfigurationOutput{
					LoggingConfiguration: &wafv2types.LoggingConfiguration{
						ResourceArn: params.ResourceArn,
					},
				}, nil
			}
			return nil, errors.New("not found")
		},
	}

	scanner := NewWAFv2ScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "INFO", results[0].Severity)
	assert.Equal(t, "FAIL", results[1].Status)
	assert.Equal(t, "MEDIUM", results[1].Severity)
}

func TestWAFv2Scanner_ListError(t *testing.T) {
	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	scanner := NewWAFv2ScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "failed to list WAFv2 web ACLs")
}

func TestWAFv2Scanner_Pagination(t *testing.T) {
	calls := 0
	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			calls++
			if params.NextMarker == nil {
				return &wafv2.ListWebACLsOutput{
					WebACLs: []wafv2types.WebACLSummary{
						{ARN: aws.String("arn:1"), Name: aws.String("acl-page1")},
					},
					NextMarker: aws.String("page2-marker"),
				}, nil
			}
			assert.Equal(t, "page2-marker", *params.NextMarker)
			return &wafv2.ListWebACLsOutput{
				WebACLs: []wafv2types.WebACLSummary{
					{ARN: aws.String("arn:2"), Name: aws.String("acl-page2")},
				},
				NextMarker: nil,
			}, nil
		},
		getLoggingConfigurationFn: func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
			return nil, errors.New("no logs")
		},
	}

	scanner := NewWAFv2ScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	require.Len(t, results, 2)
}

func TestWAFv2Scanner_ResourceLimit(t *testing.T) {
	mock := &mockWAFv2ScannerApi{
		listWebACLsFn: func(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error) {
			return &wafv2.ListWebACLsOutput{
				WebACLs: []wafv2types.WebACLSummary{
					{ARN: aws.String("arn:1"), Name: aws.String("acl-1")},
					{ARN: aws.String("arn:2"), Name: aws.String("acl-2")},
				},
			}, nil
		},
		getLoggingConfigurationFn: func(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error) {
			return nil, errors.New("no logs")
		},
	}

	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	scanner := NewWAFv2ScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
