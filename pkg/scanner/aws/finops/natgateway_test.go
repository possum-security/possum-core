package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNATGatewayCustomClient struct {
	describeNatGatewaysFn func(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error)
}

func (m *mockNATGatewayCustomClient) DescribeNatGateways(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	if m.describeNatGatewaysFn != nil {
		return m.describeNatGatewaysFn(ctx, params, optFns...)
	}
	return &ec2.DescribeNatGatewaysOutput{}, nil
}

func TestNATGatewayScanner_IdleAndActive(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	youngTime := time.Now().Add(-2 * 24 * time.Hour)

	mockEC2 := &mockNATGatewayCustomClient{
		describeNatGatewaysFn: func(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
			return &ec2.DescribeNatGatewaysOutput{
				NatGateways: []ec2types.NatGateway{
					{
						NatGatewayId: aws.String("nat-idle-1"),
						State:        ec2types.NatGatewayStateAvailable,
						CreateTime:   aws.Time(oldTime),
					},
					{
						NatGatewayId: aws.String("nat-active-2"),
						State:        ec2types.NatGatewayStateAvailable,
						CreateTime:   aws.Time(oldTime),
					},
					{
						NatGatewayId: aws.String("nat-deleted-3"),
						State:        ec2types.NatGatewayStateDeleted,
						CreateTime:   aws.Time(oldTime),
					},
					{
						NatGatewayId: aws.String("nat-young-4"),
						State:        ec2types.NatGatewayStateAvailable,
						CreateTime:   aws.Time(youngTime),
					},
				},
			}, nil
		},
	}

	mockCW := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			for _, dim := range params.Dimensions {
				if aws.ToString(dim.Value) == "nat-idle-1" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(1024)}}, // 1KB < 10MB
					}, nil
				}
				if aws.ToString(dim.Value) == "nat-active-2" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(50 * 1024 * 1024)}}, // 50MB
					}, nil
				}
				if aws.ToString(dim.Value) == "nat-young-4" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}},
					}, nil
				}
			}
			return &cloudwatch.GetMetricStatisticsOutput{}, nil
		},
	}

	sc := finops.NewNATGatewayScannerWithClients(mockEC2, mockCW, "us-east-1")
	assert.Equal(t, "NAT-Gateway-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	// nat-deleted-3 is skipped; remaining 3 are processed
	require.Len(t, results, 3)

	// NAT 1: Idle -> Fail
	assert.Equal(t, "nat-idle-1", results[0].ResourceID)
	assert.Equal(t, finops.RuleNATGatewayIdle, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.Equal(t, 32.85, results[0].CostWasteMo)
	assert.Equal(t, "us-east-1", results[0].Region)

	// NAT 2: Active -> Pass
	assert.Equal(t, "nat-active-2", results[1].ResourceID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// NAT 4: Young -> Pass (too young to flag)
	assert.Equal(t, "nat-young-4", results[2].ResourceID)
	assert.False(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[2].Status)
}

func TestNATGatewayScanner_CloudWatchErrorHandling(t *testing.T) {
	mockEC2 := &mockNATGatewayCustomClient{
		describeNatGatewaysFn: func(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
			return &ec2.DescribeNatGatewaysOutput{
				NatGateways: []ec2types.NatGateway{
					{
						NatGatewayId: aws.String("nat-cw-err"),
						State:        ec2types.NatGatewayStateAvailable,
						CreateTime:   aws.Time(time.Now().Add(-30 * 24 * time.Hour)),
					},
				},
			}, nil
		},
	}

	mockCWErr := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			return nil, errors.New("AccessDenied: User is not authorized")
		},
	}

	sc := finops.NewNATGatewayScannerWithClients(mockEC2, mockCWErr, "us-east-1")
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.False(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[0].Status)
	metrics := results[0].Metrics.(map[string]interface{})
	assert.Contains(t, metrics["MetricFetchError"], "AccessDenied")
}

func TestNATGatewayScanner_ErrorsAndLimits(t *testing.T) {
	// Describe error
	mockErr := &mockNATGatewayCustomClient{
		describeNatGatewaysFn: func(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
			return nil, errors.New("ec2: describe nat gateways failed")
		},
	}
	scErr := finops.NewNATGatewayScannerWithClients(mockErr, nil)
	_, err := scErr.Scan(context.Background())
	assert.Error(t, err)

	// ResourceLimit
	mockValid := &mockNATGatewayCustomClient{
		describeNatGatewaysFn: func(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
			return &ec2.DescribeNatGatewaysOutput{
				NatGateways: []ec2types.NatGateway{
					{NatGatewayId: aws.String("nat-1"), State: ec2types.NatGatewayStateAvailable},
					{NatGatewayId: aws.String("nat-2"), State: ec2types.NatGatewayStateAvailable},
				},
			}, nil
		},
	}
	scLimit := finops.NewNATGatewayScannerWithClients(mockValid, nil)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scLimit.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
