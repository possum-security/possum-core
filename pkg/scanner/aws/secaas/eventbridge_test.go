package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridgetypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEventBridgeApi struct {
	listEventBusesFn func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error)
}

func (m *mockEventBridgeApi) ListEventBuses(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
	if m.listEventBusesFn != nil {
		return m.listEventBusesFn(ctx, params, optFns...)
	}
	return &eventbridge.ListEventBusesOutput{}, nil
}

func TestEventBridgeScanner_Compliant_NoPolicy(t *testing.T) {
	busName := "default"
	busArn := "arn:aws:events:us-east-1:123456789012:event-bus/default"

	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{
						Name:   aws.String(busName),
						Arn:    aws.String(busArn),
						Policy: nil,
					},
				},
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "EventBridge-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	expectedRules := map[string]string{
		"eventbridge_bus_exposed":              "PASS",
		"eventbridge_bus_cross_account_access": "PASS",
	}

	for _, r := range results {
		assert.Equal(t, busName, r.ResourceID)
		assert.Equal(t, "SecaaS-EventBridge", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "INFO", r.Severity)

		expectedStatus, exists := expectedRules[r.RuleID]
		require.True(t, exists, "Unexpected rule %s", r.RuleID)
		assert.Equal(t, expectedStatus, r.Status)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, busArn, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-EventBridge", r.Nodes[0].NodeType)
	}
}

func TestEventBridgeScanner_Compliant_SameAccount(t *testing.T) {
	busName := "internal-app-bus"
	busArn := "arn:aws:events:us-east-1:123456789012:event-bus/internal-app-bus"
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowSameAccount","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"events:PutEvents","Resource":"` + busArn + `"}]}`

	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{
						Name:   aws.String(busName),
						Arn:    aws.String(busArn),
						Policy: aws.String(policy),
					},
				},
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)
	}
}

func TestEventBridgeScanner_Compliant_TrustedOrgCondition(t *testing.T) {
	busName := "org-bus"
	busArn := "arn:aws:events:us-east-1:123456789012:event-bus/org-bus"
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowOrg","Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"` + busArn + `","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1234567890"}}}]}`

	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{
						Name:   aws.String(busName),
						Arn:    aws.String(busArn),
						Policy: aws.String(policy),
					},
				},
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Rule %s expected PASS", r.RuleID)
		assert.Equal(t, "INFO", r.Severity)
	}
}

func TestEventBridgeScanner_NonCompliant_ExposedWildcard(t *testing.T) {
	busName := "public-bus"
	busArn := "arn:aws:events:us-west-2:123456789012:event-bus/public-bus"
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowPublic","Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"` + busArn + `"}]}`

	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{
						Name:   aws.String(busName),
						Arn:    aws.String(busArn),
						Policy: aws.String(policy),
					},
				},
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	expectedSeverities := map[string]string{
		"eventbridge_bus_exposed":              "HIGH",
		"eventbridge_bus_cross_account_access": "MEDIUM",
	}

	for _, r := range results {
		assert.Equal(t, busName, r.ResourceID)
		assert.Equal(t, "SecaaS-EventBridge", r.ResourceType)
		assert.Equal(t, "FAIL", r.Status)

		expectedSev, exists := expectedSeverities[r.RuleID]
		require.True(t, exists, "Unexpected rule %s", r.RuleID)
		assert.Equal(t, expectedSev, r.Severity)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["SecurityIssues"])
		assert.NotEmpty(t, metrics["Recommendation"])
	}
}

func TestEventBridgeScanner_NonCompliant_ExternalAccountCrossAccess(t *testing.T) {
	busName := "partner-bus"
	busArn := "arn:aws:events:ap-southeast-1:123456789012:event-bus/partner-bus"
	// Policy explicitly grants to external account 999999999999 without org condition
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowExternal","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"events:PutEvents","Resource":"` + busArn + `"}]}`

	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{
						Name:   aws.String(busName),
						Arn:    aws.String(busArn),
						Policy: aws.String(policy),
					},
				},
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "ap-southeast-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		if r.RuleID == "eventbridge_bus_exposed" {
			// Not exposed since Principal is not "*"
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
		}
		if r.RuleID == "eventbridge_bus_cross_account_access" {
			// Cross-account finding triggered
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
		}
	}
}

func TestEventBridgeScanner_WildcardWithNonOrgCondition(t *testing.T) {
	busName := "time-restricted-bus"
	busArn := "arn:aws:events:us-east-1:123456789012:event-bus/time-restricted-bus"
	// Has condition, so not exposed without condition, but does not restrict to trusted org
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowWithDate","Effect":"Allow","Principal":"*","Action":"events:PutEvents","Resource":"` + busArn + `","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}}]}`

	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{
						Name:   aws.String(busName),
						Arn:    aws.String(busArn),
						Policy: aws.String(policy),
					},
				},
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		if r.RuleID == "eventbridge_bus_exposed" {
			// Has condition, so not "without condition"
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
		}
		if r.RuleID == "eventbridge_bus_cross_account_access" {
			// External cross-account without trusted org
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
		}
	}
}

func TestEventBridgeScanner_Pagination(t *testing.T) {
	page1Token := "token-1"
	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			if params.NextToken == nil {
				return &eventbridge.ListEventBusesOutput{
					EventBuses: []eventbridgetypes.EventBus{
						{Name: aws.String("bus-page-1"), Arn: aws.String("arn:aws:events:us-east-1:123456789012:event-bus/bus-page-1")},
					},
					NextToken: aws.String(page1Token),
				}, nil
			}
			return &eventbridge.ListEventBusesOutput{
				EventBuses: []eventbridgetypes.EventBus{
					{Name: aws.String("bus-page-2"), Arn: aws.String("arn:aws:events:us-east-1:123456789012:event-bus/bus-page-2")},
				},
				NextToken: nil,
			}, nil
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4) // 2 buses * 2 rules each
}

func TestEventBridgeScanner_ListError(t *testing.T) {
	mock := &mockEventBridgeApi{
		listEventBusesFn: func(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
			return nil, errors.New("AccessDeniedException")
		},
	}

	scanner := NewEventBridgeScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "failed to list EventBridge event buses")
}

func TestEventBridgeScanner_Constructor(t *testing.T) {
	cfg := aws.Config{Region: "ap-northeast-1"}
	scanner := NewEventBridgeScanner(cfg)
	require.NotNil(t, scanner)
	assert.Equal(t, "EventBridge-SecaaS-Scanner", scanner.Name())
	assert.Equal(t, "ap-northeast-1", scanner.region)
}
