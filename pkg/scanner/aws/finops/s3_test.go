package finops_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockS3Client struct {
	listBucketsFn                     func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	getBucketLifecycleConfigurationFn func(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
}

func (m *mockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if m.listBucketsFn != nil {
		return m.listBucketsFn(ctx, params, optFns...)
	}
	return &s3.ListBucketsOutput{}, nil
}

func (m *mockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	if m.getBucketLifecycleConfigurationFn != nil {
		return m.getBucketLifecycleConfigurationFn(ctx, params, optFns...)
	}
	return &s3.GetBucketLifecycleConfigurationOutput{}, nil
}

func TestS3Scanner_LifecycleAndWaste(t *testing.T) {
	oneHundredGB := 100.0 * 1024.0 * 1024.0 * 1024.0

	mockS3 := &mockS3Client{
		listBucketsFn: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []s3types.Bucket{
					{Name: aws.String("no-lifecycle-big-bucket")},
					{Name: aws.String("has-lifecycle-bucket")},
					{Name: aws.String("empty-no-lifecycle-bucket")},
				},
			}, nil
		},
		getBucketLifecycleConfigurationFn: func(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
			if aws.ToString(params.Bucket) == "has-lifecycle-bucket" {
				return &s3.GetBucketLifecycleConfigurationOutput{
					Rules: []s3types.LifecycleRule{
						{Status: s3types.ExpirationStatusEnabled},
					},
				}, nil
			}
			return nil, errors.New("NoSuchLifecycleConfiguration")
		},
	}

	mockCW := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			for _, dim := range params.Dimensions {
				if aws.ToString(dim.Name) == "BucketName" && aws.ToString(dim.Value) == "no-lifecycle-big-bucket" {
					return &cloudwatch.GetMetricStatisticsOutput{
						Datapoints: []cwtypes.Datapoint{
							{Average: aws.Float64(oneHundredGB)},
						},
					}, nil
				}
			}
			return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{}}, nil
		},
	}

	sc := finops.NewS3ScannerWithClients(mockS3, mockCW, "us-east-1")
	assert.Equal(t, "S3-FinOps-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	// Bucket 1: No lifecycle, 100GB -> Fail
	assert.Equal(t, "no-lifecycle-big-bucket", results[0].ResourceID)
	assert.Equal(t, finops.RuleS3BucketLifecycleMissing, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.InDelta(t, 0.69, results[0].CostWasteMo, 0.01) // 100 * 0.023 * 0.30 = 0.69
	assert.Equal(t, "global", results[0].Region)

	// Bucket 2: Has lifecycle -> Pass
	assert.Equal(t, "has-lifecycle-bucket", results[1].ResourceID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// Bucket 3: Empty bucket without lifecycle -> Fail, 0 cost
	assert.Equal(t, "empty-no-lifecycle-bucket", results[2].ResourceID)
	assert.True(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[2].Status)
	assert.Equal(t, 0.0, results[2].CostWasteMo)
}

func TestS3Scanner_ErrorsAndNilCW(t *testing.T) {
	// ListBuckets error
	mockErr := &mockS3Client{
		listBucketsFn: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return nil, errors.New("s3: list buckets error")
		},
	}
	scErr := finops.NewS3ScannerWithClient(mockErr)
	_, err := scErr.Scan(context.Background())
	assert.Error(t, err)

	// Nil CloudWatch client handled gracefully
	mockValid := &mockS3Client{
		listBucketsFn: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []s3types.Bucket{{Name: aws.String("b1")}},
			}, nil
		},
		getBucketLifecycleConfigurationFn: func(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
			return nil, errors.New("NoSuchLifecycleConfiguration")
		},
	}
	scNilCW := finops.NewS3ScannerWithClient(mockValid)
	results, err := scNilCW.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, 0.0, results[0].CostWasteMo)
}

func TestS3Scanner_Limit(t *testing.T) {
	mockClient := &mockS3Client{
		listBucketsFn: func(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
			return &s3.ListBucketsOutput{
				Buckets: []s3types.Bucket{
					{Name: aws.String("b1")},
					{Name: aws.String("b2")},
				},
			}, nil
		},
	}
	sc := finops.NewS3ScannerWithClient(mockClient)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
