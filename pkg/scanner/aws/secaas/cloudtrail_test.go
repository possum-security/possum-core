package secaas_test

import (
	"context"
	"testing"

	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type mockCloudTrailAPI struct {
	describeTrailsOutput    *cloudtrail.DescribeTrailsOutput
	describeTrailsErr       error
	getEventSelectorsOutput *cloudtrail.GetEventSelectorsOutput
	getEventSelectorsErr    error
}

func (m *mockCloudTrailAPI) DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	if m.describeTrailsErr != nil {
		return nil, m.describeTrailsErr
	}
	return m.describeTrailsOutput, nil
}

func (m *mockCloudTrailAPI) GetEventSelectors(ctx context.Context, params *cloudtrail.GetEventSelectorsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	if m.getEventSelectorsErr != nil {
		return nil, m.getEventSelectorsErr
	}
	return m.getEventSelectorsOutput, nil
}

type mockCloudTrailS3API struct {
	getPublicAccessBlockOutput *s3.GetPublicAccessBlockOutput
	getPublicAccessBlockErr    error
	getBucketLoggingOutput     *s3.GetBucketLoggingOutput
	getBucketLoggingErr        error
}

func (m *mockCloudTrailS3API) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if m.getPublicAccessBlockErr != nil {
		return nil, m.getPublicAccessBlockErr
	}
	return m.getPublicAccessBlockOutput, nil
}

func (m *mockCloudTrailS3API) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if m.getBucketLoggingErr != nil {
		return nil, m.getBucketLoggingErr
	}
	return m.getBucketLoggingOutput, nil
}

func TestCloudTrailScanner_FullyCompliantTrail_AllPass(t *testing.T) {
	mockCT := &mockCloudTrailAPI{
		describeTrailsOutput: &cloudtrail.DescribeTrailsOutput{
			TrailList: []cttypes.Trail{
				{
					Name:                      aws.String("audit-trail"),
					TrailARN:                  aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail"),
					HomeRegion:                aws.String("us-east-1"),
					IsMultiRegionTrail:        aws.Bool(true),
					LogFileValidationEnabled:  aws.Bool(true),
					CloudWatchLogsLogGroupArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:CloudTrailLogGroup:*"),
					KmsKeyId:                  aws.String("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
					S3BucketName:              aws.String("my-cloudtrail-bucket"),
				},
			},
		},
		getEventSelectorsOutput: &cloudtrail.GetEventSelectorsOutput{
			EventSelectors: []cttypes.EventSelector{
				{
					ReadWriteType: cttypes.ReadWriteTypeAll,
					DataResources: []cttypes.DataResource{
						{
							Type:   aws.String("AWS::S3::Object"),
							Values: []string{"arn:aws:s3:::"},
						},
					},
				},
			},
		},
	}

	mockS3 := &mockCloudTrailS3API{
		getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
			PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(true),
				BlockPublicPolicy:     aws.Bool(true),
				IgnorePublicAcls:      aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(true),
			},
		},
		getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
			LoggingEnabled: &s3types.LoggingEnabled{
				TargetBucket: aws.String("logging-bucket"),
			},
		},
	}

	sc := secaas.NewCloudTrailScannerWithClients(mockCT, mockS3)
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedChecks := []string{
		"cloudtrail_multi_region_enabled",
		"cloudtrail_log_file_validation_enabled",
		"cloudtrail_cloudwatch_logging_enabled",
		"cloudtrail_kms_encryption_enabled",
		"cloudtrail_s3_dataevents_write_enabled",
		"cloudtrail_s3_dataevents_read_enabled",
		"cloudtrail_logs_s3_bucket_is_not_publicly_accessible",
		"cloudtrail_logs_s3_bucket_access_logging_enabled",
	}

	if len(results) != len(expectedChecks) {
		t.Fatalf("expected %d results, got %d", len(expectedChecks), len(results))
	}

	for _, r := range results {
		if r.Status != "PASS" {
			t.Errorf("expected check %s to PASS, got %s", r.RuleID, r.Status)
		}
	}
}

func TestCloudTrailScanner_NonCompliantTrail_AllFail(t *testing.T) {
	mockCT := &mockCloudTrailAPI{
		describeTrailsOutput: &cloudtrail.DescribeTrailsOutput{
			TrailList: []cttypes.Trail{
				{
					Name:                     aws.String("insecure-trail"),
					TrailARN:                 aws.String("arn:aws:cloudtrail:us-east-1:123456789012:trail/insecure-trail"),
					HomeRegion:               aws.String("us-east-1"),
					IsMultiRegionTrail:       aws.Bool(false),
					LogFileValidationEnabled: aws.Bool(false),
					S3BucketName:             aws.String("insecure-bucket"),
				},
			},
		},
		getEventSelectorsOutput: &cloudtrail.GetEventSelectorsOutput{
			EventSelectors: []cttypes.EventSelector{},
		},
	}

	mockS3 := &mockCloudTrailS3API{
		getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
			PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
				BlockPublicAcls: aws.Bool(false),
			},
		},
		getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
			LoggingEnabled: nil,
		},
	}

	sc := secaas.NewCloudTrailScannerWithClients(mockCT, mockS3)
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range results {
		if r.Status != "FAIL" {
			t.Errorf("expected check %s to FAIL, got %s", r.RuleID, r.Status)
		}
	}
}

func TestCloudTrailScanner_NoTrails_Fails(t *testing.T) {
	mockCT := &mockCloudTrailAPI{
		describeTrailsOutput: &cloudtrail.DescribeTrailsOutput{
			TrailList: []cttypes.Trail{},
		},
	}

	sc := secaas.NewCloudTrailScannerWithClients(mockCT, nil)
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result for missing trails, got %d", len(results))
	}
	if results[0].RuleID != "cloudtrail_multi_region_enabled" || results[0].Status != "FAIL" {
		t.Errorf("expected FAIL on cloudtrail_multi_region_enabled, got %+v", results[0])
	}
}
