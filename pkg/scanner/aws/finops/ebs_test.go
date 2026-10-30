package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEBSClient struct {
	describeVolumesFn   func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	describeSnapshotsFn func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

func (m *mockEBSClient) DescribeVolumes(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if m.describeVolumesFn != nil {
		return m.describeVolumesFn(ctx, params, optFns...)
	}
	return &ec2.DescribeVolumesOutput{}, nil
}

func (m *mockEBSClient) DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if m.describeSnapshotsFn != nil {
		return m.describeSnapshotsFn(ctx, params, optFns...)
	}
	return &ec2.DescribeSnapshotsOutput{}, nil
}

func TestEBSScanner_UnattachedAndAttachedVolumes(t *testing.T) {
	oldTime := time.Now().Add(-100 * 24 * time.Hour)
	recentTime := time.Now().Add(-10 * 24 * time.Hour)

	mockClient := &mockEBSClient{
		describeVolumesFn: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{
				Volumes: []types.Volume{
					{
						VolumeId:         aws.String("vol-unattached-1"),
						State:            types.VolumeStateAvailable,
						Size:             aws.Int32(100),
						VolumeType:       types.VolumeTypeGp3,
						AvailabilityZone: aws.String("us-east-1a"),
					},
					{
						VolumeId:         aws.String("vol-attached-2"),
						State:            types.VolumeStateInUse,
						Size:             aws.Int32(50),
						VolumeType:       types.VolumeTypeGp2,
						AvailabilityZone: aws.String("us-east-1b"),
					},
				},
			}, nil
		},
		describeSnapshotsFn: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{
				Snapshots: []types.Snapshot{
					{
						SnapshotId:  aws.String("snap-old-orphaned"),
						VolumeSize:  aws.Int32(20),
						StartTime:   aws.Time(oldTime),
						Description: aws.String("Created by CreateImage(i-1234) for ami-5678"),
					},
					{
						SnapshotId:  aws.String("snap-recent-active"),
						VolumeSize:  aws.Int32(10),
						StartTime:   aws.Time(recentTime),
						Description: aws.String("Daily backup"),
					},
				},
			}, nil
		},
	}

	sc := finops.NewEBSScannerWithClient(mockClient, "us-east-1")
	assert.Equal(t, "EBS-and-Snapshot-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	// Volume 1: Unattached
	assert.Equal(t, "vol-unattached-1", results[0].ResourceID)
	assert.Equal(t, finops.RuleEBSVolumeUnused, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.Equal(t, 8.0, results[0].CostWasteMo) // 100 * 0.08
	assert.Equal(t, "us-east-1", results[0].Region)

	// Volume 2: Attached
	assert.Equal(t, "vol-attached-2", results[1].ResourceID)
	assert.Equal(t, finops.RuleEBSVolumeUnused, results[1].RuleID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// Snapshot 1: Old Orphaned
	assert.Equal(t, "snap-old-orphaned", results[2].ResourceID)
	assert.Equal(t, finops.RuleEBSSnapshotOrphaned, results[2].RuleID)
	assert.True(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[2].Status)
	assert.Equal(t, 1.0, results[2].CostWasteMo) // 20 * 0.05

	// Snapshot 2: Recent Active
	assert.Equal(t, "snap-recent-active", results[3].ResourceID)
	assert.Equal(t, finops.RuleEBSSnapshotOrphaned, results[3].RuleID)
	assert.False(t, results[3].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[3].Status)
	assert.Equal(t, 0.0, results[3].CostWasteMo)
}

func TestEBSScanner_Errors(t *testing.T) {
	// Volume error
	mockErrVol := &mockEBSClient{
		describeVolumesFn: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return nil, errors.New("ec2: describe volumes failure")
		},
	}
	scVol := finops.NewEBSScannerWithClient(mockErrVol, "us-east-1")
	_, err := scVol.Scan(context.Background())
	assert.Error(t, err)

	// Snapshot error
	mockErrSnap := &mockEBSClient{
		describeVolumesFn: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{}, nil
		},
		describeSnapshotsFn: func(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
			return nil, errors.New("ec2: describe snapshots failure")
		},
	}
	scSnap := finops.NewEBSScannerWithClient(mockErrSnap, "us-east-1")
	_, err = scSnap.Scan(context.Background())
	assert.Error(t, err)
}

func TestEBSScanner_ResourceLimit(t *testing.T) {
	mockClient := &mockEBSClient{
		describeVolumesFn: func(ctx context.Context, params *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{
				Volumes: []types.Volume{
					{VolumeId: aws.String("vol-1"), State: types.VolumeStateAvailable, Size: aws.Int32(10)},
					{VolumeId: aws.String("vol-2"), State: types.VolumeStateAvailable, Size: aws.Int32(10)},
				},
			}, nil
		},
	}
	sc := finops.NewEBSScannerWithClient(mockClient)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
