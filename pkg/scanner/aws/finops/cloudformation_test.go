package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCFNClient struct {
	describeStacksFn func(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	listStacksFn     func(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error)
}

func (m *mockCFNClient) DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
	if m.describeStacksFn != nil {
		return m.describeStacksFn(ctx, params, optFns...)
	}
	return &cloudformation.DescribeStacksOutput{}, nil
}

func (m *mockCFNClient) ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error) {
	if m.listStacksFn != nil {
		return m.listStacksFn(ctx, params, optFns...)
	}
	return &cloudformation.ListStacksOutput{}, nil
}

func TestCloudFormationScanner_Statuses(t *testing.T) {
	recentTime := time.Now().Add(-5 * 24 * time.Hour)
	staleTime := time.Now().Add(-200 * 24 * time.Hour)

	mockClient := &mockCFNClient{
		describeStacksFn: func(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
			return &cloudformation.DescribeStacksOutput{
				Stacks: []types.Stack{
					{
						StackId:      aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/rollback-stack/1"),
						StackName:    aws.String("rollback-stack"),
						StackStatus:  types.StackStatusRollbackComplete,
						CreationTime: aws.Time(recentTime),
					},
					{
						StackId:           aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/failed-stack/2"),
						StackName:         aws.String("failed-stack"),
						StackStatus:       types.StackStatusCreateFailed,
						StackStatusReason: aws.String("Resource creation cancelled"),
						CreationTime:      aws.Time(recentTime),
					},
					{
						StackId:         aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/healthy-stack/3"),
						StackName:       aws.String("healthy-stack"),
						StackStatus:     types.StackStatusCreateComplete,
						CreationTime:    aws.Time(recentTime),
						LastUpdatedTime: aws.Time(recentTime),
					},
					{
						StackId:         aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/ephemeral-dev-stack/4"),
						StackName:       aws.String("ephemeral-dev-stack"),
						StackStatus:     types.StackStatusCreateComplete,
						CreationTime:    aws.Time(staleTime),
						LastUpdatedTime: aws.Time(staleTime),
						Tags: []types.Tag{
							{Key: aws.String("Environment"), Value: aws.String("dev")},
						},
					},
					{
						StackId:         aws.String("arn:aws:cloudformation:us-east-1:123456789012:stack/stale-prod-stack/5"),
						StackName:       aws.String("stale-prod-stack"),
						StackStatus:     types.StackStatusCreateComplete,
						CreationTime:    aws.Time(staleTime),
						LastUpdatedTime: aws.Time(staleTime),
						Tags: []types.Tag{
							{Key: aws.String("Environment"), Value: aws.String("production")},
						},
					},
				},
			}, nil
		},
	}

	sc := finops.NewCloudFormationScannerWithClient(mockClient, "us-east-1")
	assert.Equal(t, "CloudFormation-FinOps-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5)

	// Stack 1: RollbackComplete -> Fail
	assert.Equal(t, "arn:aws:cloudformation:us-east-1:123456789012:stack/rollback-stack/1", results[0].ResourceID)
	assert.Equal(t, finops.RuleCloudFormationStackFailedOrAbandoned, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.Equal(t, "us-east-1", results[0].Region)

	// Stack 2: CreateFailed -> Fail
	assert.Equal(t, "arn:aws:cloudformation:us-east-1:123456789012:stack/failed-stack/2", results[1].ResourceID)
	assert.True(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[1].Status)

	// Stack 3: Healthy active -> Pass
	assert.Equal(t, "arn:aws:cloudformation:us-east-1:123456789012:stack/healthy-stack/3", results[2].ResourceID)
	assert.False(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[2].Status)

	// Stack 4: Ephemeral dev stale -> Fail
	assert.Equal(t, "arn:aws:cloudformation:us-east-1:123456789012:stack/ephemeral-dev-stack/4", results[3].ResourceID)
	assert.True(t, results[3].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[3].Status)

	// Stack 5: Stale prod stack -> Pass (audit recommendation)
	assert.Equal(t, "arn:aws:cloudformation:us-east-1:123456789012:stack/stale-prod-stack/5", results[4].ResourceID)
	assert.False(t, results[4].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[4].Status)
}

func TestCloudFormationScanner_Error(t *testing.T) {
	mockClient := &mockCFNClient{
		describeStacksFn: func(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
			return nil, errors.New("cfn: describe stacks failure")
		},
	}

	sc := finops.NewCloudFormationScannerWithClient(mockClient)
	_, err := sc.Scan(context.Background())
	assert.Error(t, err)
}

func TestCloudFormationScanner_Limit(t *testing.T) {
	mockClient := &mockCFNClient{
		describeStacksFn: func(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error) {
			return &cloudformation.DescribeStacksOutput{
				Stacks: []types.Stack{
					{StackName: aws.String("stack-1"), StackStatus: types.StackStatusCreateComplete},
					{StackName: aws.String("stack-2"), StackStatus: types.StackStatusCreateComplete},
				},
			}, nil
		},
	}

	sc := finops.NewCloudFormationScannerWithClient(mockClient, "us-west-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
