package finops_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockENIClient struct {
	describeNetworkInterfacesFn func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

func (m *mockENIClient) DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	if m.describeNetworkInterfacesFn != nil {
		return m.describeNetworkInterfacesFn(ctx, params, optFns...)
	}
	return &ec2.DescribeNetworkInterfacesOutput{}, nil
}

func TestENIScanner_AvailableAndInUse(t *testing.T) {
	mockClient := &mockENIClient{
		describeNetworkInterfacesFn: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{
						NetworkInterfaceId: aws.String("eni-available-1"),
						Status:             types.NetworkInterfaceStatusAvailable,
					},
					{
						NetworkInterfaceId: aws.String("eni-inuse-2"),
						Status:             types.NetworkInterfaceStatusInUse,
					},
				},
			}, nil
		},
	}

	sc := finops.NewENIScannerWithClient(mockClient, "us-east-1")
	assert.Equal(t, "ENI-FinOps-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Available ENI
	assert.Equal(t, "eni-available-1", results[0].ResourceID)
	assert.Equal(t, finops.RuleENIDetachedUnused, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.Equal(t, model.SeverityLow, results[0].Severity)
	assert.Equal(t, "us-east-1", results[0].Region)

	// In-Use ENI
	assert.Equal(t, "eni-inuse-2", results[1].ResourceID)
	assert.Equal(t, finops.RuleENIDetachedUnused, results[1].RuleID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, model.SeverityInfo, results[1].Severity)
}

func TestENIScanner_Error(t *testing.T) {
	mockClient := &mockENIClient{
		describeNetworkInterfacesFn: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return nil, errors.New("ec2: describe network interfaces failed")
		},
	}

	sc := finops.NewENIScannerWithClient(mockClient)
	_, err := sc.Scan(context.Background())
	assert.Error(t, err)
}

func TestENIScanner_Limit(t *testing.T) {
	mockClient := &mockENIClient{
		describeNetworkInterfacesFn: func(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
			return &ec2.DescribeNetworkInterfacesOutput{
				NetworkInterfaces: []types.NetworkInterface{
					{NetworkInterfaceId: aws.String("eni-1"), Status: types.NetworkInterfaceStatusAvailable},
					{NetworkInterfaceId: aws.String("eni-2"), Status: types.NetworkInterfaceStatusAvailable},
				},
			}, nil
		},
	}

	sc := finops.NewENIScannerWithClient(mockClient, "eu-west-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
