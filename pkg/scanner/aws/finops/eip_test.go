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

type mockEIPClient struct {
	describeAddressesFn func(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

func (m *mockEIPClient) DescribeAddresses(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	if m.describeAddressesFn != nil {
		return m.describeAddressesFn(ctx, params, optFns...)
	}
	return &ec2.DescribeAddressesOutput{}, nil
}

func TestEIPScanner_UnassignedAndAssigned(t *testing.T) {
	assocID := "eipassoc-active-123"

	mockClient := &mockEIPClient{
		describeAddressesFn: func(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
			return &ec2.DescribeAddressesOutput{
				Addresses: []types.Address{
					{
						AllocationId:  aws.String("eipalloc-orphan-1"),
						PublicIp:      aws.String("54.1.2.3"),
						AssociationId: nil,
					},
					{
						AllocationId:  aws.String("eipalloc-active-2"),
						PublicIp:      aws.String("54.2.3.4"),
						AssociationId: &assocID,
					},
					{
						AllocationId:  nil, // classic EIP fallback to PublicIp
						PublicIp:      aws.String("54.3.4.5"),
						AssociationId: nil,
					},
				},
			}, nil
		},
	}

	sc := finops.NewEIPScannerWithClient(mockClient, "us-east-1")
	assert.Equal(t, "EIP-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	// Address 1: Unassigned VPC EIP
	assert.Equal(t, "eipalloc-orphan-1", results[0].ResourceID)
	assert.Equal(t, finops.RuleEIPUnassigned, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.Equal(t, 3.65, results[0].CostWasteMo)

	// Address 2: Assigned EIP
	assert.Equal(t, "eipalloc-active-2", results[1].ResourceID)
	assert.Equal(t, finops.RuleEIPUnassigned, results[1].RuleID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// Address 3: Unassigned Classic EIP (AllocationId empty)
	assert.Equal(t, "54.3.4.5", results[2].ResourceID)
	assert.True(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[2].Status)
	assert.Equal(t, 3.65, results[2].CostWasteMo)
}

func TestEIPScanner_Error(t *testing.T) {
	mockClient := &mockEIPClient{
		describeAddressesFn: func(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
			return nil, errors.New("ec2: describe addresses error")
		},
	}
	sc := finops.NewEIPScannerWithClient(mockClient)
	_, err := sc.Scan(context.Background())
	assert.Error(t, err)
}

func TestEIPScanner_Limit(t *testing.T) {
	mockClient := &mockEIPClient{
		describeAddressesFn: func(ctx context.Context, params *ec2.DescribeAddressesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
			return &ec2.DescribeAddressesOutput{
				Addresses: []types.Address{
					{AllocationId: aws.String("eip-1"), PublicIp: aws.String("1.1.1.1")},
					{AllocationId: aws.String("eip-2"), PublicIp: aws.String("2.2.2.2")},
				},
			}, nil
		},
	}
	sc := finops.NewEIPScannerWithClient(mockClient, "us-west-2")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
