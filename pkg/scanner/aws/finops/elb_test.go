package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockELBCustomClient struct {
	describeLoadBalancersFn func(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
}

func (m *mockELBCustomClient) DescribeLoadBalancers(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	if m.describeLoadBalancersFn != nil {
		return m.describeLoadBalancersFn(ctx, params, optFns...)
	}
	return &elbv2.DescribeLoadBalancersOutput{}, nil
}

func TestELBScanner_IdleAndActive(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	youngTime := time.Now().Add(-2 * 24 * time.Hour)

	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb/50dc6c495c0c9188"
	nlbArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/active-nlb/1234567890123456"
	youngAlbArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/young-alb/9876543210123456"

	mockELB := &mockELBCustomClient{
		describeLoadBalancersFn: func(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
			return &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  aws.String(albArn),
						LoadBalancerName: aws.String("idle-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
						CreatedTime:      aws.Time(oldTime),
					},
					{
						LoadBalancerArn:  aws.String(nlbArn),
						LoadBalancerName: aws.String("active-nlb"),
						Type:             elbtypes.LoadBalancerTypeEnumNetwork,
						CreatedTime:      aws.Time(oldTime),
					},
					{
						LoadBalancerArn:  aws.String(youngAlbArn),
						LoadBalancerName: aws.String("young-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
						CreatedTime:      aws.Time(youngTime),
					},
				},
			}, nil
		},
	}

	mockCW := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			for _, dim := range params.Dimensions {
				if aws.ToString(dim.Value) == "app/idle-alb/50dc6c495c0c9188" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}},
					}, nil
				}
				if aws.ToString(dim.Value) == "net/active-nlb/1234567890123456" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(150000)}},
					}, nil
				}
				if aws.ToString(dim.Value) == "app/young-alb/9876543210123456" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}},
					}, nil
				}
			}
			return &cloudwatch.GetMetricStatisticsOutput{}, nil
		},
	}

	sc := finops.NewELBScannerWithClients(mockELB, mockCW, "us-east-1")
	assert.Equal(t, "ELB-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	// ALB 1: Idle ALB -> Fail
	assert.Equal(t, albArn, results[0].ResourceID)
	assert.Equal(t, finops.RuleELBLoadBalancerIdle, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.Equal(t, 16.42, results[0].CostWasteMo)

	// NLB 2: Active NLB -> Pass
	assert.Equal(t, nlbArn, results[1].ResourceID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// ALB 3: Young ALB -> Pass (too young to flag)
	assert.Equal(t, youngAlbArn, results[2].ResourceID)
	assert.False(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[2].Status)
	assert.Equal(t, 0.0, results[2].CostWasteMo)
}

func TestELBScanner_CloudWatchErrorHandling(t *testing.T) {
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/1234567890123456"

	mockELB := &mockELBCustomClient{
		describeLoadBalancersFn: func(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
			return &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{
						LoadBalancerArn:  aws.String(albArn),
						LoadBalancerName: aws.String("my-alb"),
						Type:             elbtypes.LoadBalancerTypeEnumApplication,
						CreatedTime:      aws.Time(time.Now().Add(-30 * 24 * time.Hour)),
					},
				},
			}, nil
		},
	}

	mockCWErr := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			return nil, errors.New("AccessDenied: User is not authorized to perform: cloudwatch:GetMetricStatistics")
		},
	}

	sc := finops.NewELBScannerWithClients(mockELB, mockCWErr, "us-east-1")
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	// Access denied must NOT cause false positive idle flagging
	assert.False(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[0].Status)
	metrics := results[0].Metrics.(map[string]interface{})
	assert.Contains(t, metrics["MetricFetchError"], "AccessDenied")
}

func TestELBScanner_ErrorsAndLimits(t *testing.T) {
	// Describe error
	mockErr := &mockELBCustomClient{
		describeLoadBalancersFn: func(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
			return nil, errors.New("elb: describe failed")
		},
	}
	scErr := finops.NewELBScannerWithClients(mockErr, nil)
	_, err := scErr.Scan(context.Background())
	assert.Error(t, err)

	// ResourceLimit
	mockValid := &mockELBCustomClient{
		describeLoadBalancersFn: func(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
			return &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbtypes.LoadBalancer{
					{LoadBalancerName: aws.String("lb-1")},
					{LoadBalancerName: aws.String("lb-2")},
				},
			}, nil
		},
	}
	scLimit := finops.NewELBScannerWithClients(mockValid, nil)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scLimit.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
