package finops

import (
	"context"
	"time"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Scanner struct {
	client   *s3.Client
	cwClient *cloudwatch.Client
}

func NewS3Scanner(cfg aws.Config) *S3Scanner {
	return &S3Scanner{
		client:   s3.NewFromConfig(cfg),
		cwClient: cloudwatch.NewFromConfig(cfg),
	}
}

func (s *S3Scanner) Name() string {
	return "S3-FinOps-Scanner"
}

func (s *S3Scanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	output, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range output.Buckets {
		if limit > 0 && processedCount >= limit {
			break
		}
		processedCount++

		bucketName := aws.ToString(bucket.Name)

		_, err := s.client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: aws.String(bucketName),
		})

		hasLifecycle := true
		if err != nil {
			hasLifecycle = false
		}

		sizeBytes := fetchS3BucketSize(ctx, s.cwClient, bucketName)
		monthlyCost := (sizeBytes / (1024.0 * 1024.0 * 1024.0)) * 0.023

		metrics := map[string]interface{}{
			"BucketName":             bucketName,
			"EstimatedMonthlyCost":   monthlyCost,
			"MissingLifecyclePolicy": !hasLifecycle,
		}
		if !hasLifecycle {
			metrics["Recommendation"] = "Implement S3 lifecycle policy to transition or delete old objects"
		}

		results = append(results, scanner.ScanResult{
			ResourceID:   bucketName,
			ResourceType: "S3",
			Region:       "global",
			IsOrphaned:   false,
			Metrics:      metrics,
		})
	}
	return results, nil
}

func fetchS3BucketSize(ctx context.Context, client *cloudwatch.Client, bucketName string) float64 {
	endTime := time.Now()
	startTime := endTime.Add(-48 * time.Hour)

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/S3"),
		MetricName: aws.String("BucketSizeBytes"),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("BucketName"),
				Value: aws.String(bucketName),
			},
			{
				Name:  aws.String("StorageType"),
				Value: aws.String("StandardStorage"),
			},
		},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(24 * 60 * 60),
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	}

	output, err := client.GetMetricStatistics(ctx, input)
	if err != nil || len(output.Datapoints) == 0 {
		return 0
	}
	return aws.ToFloat64(output.Datapoints[0].Average)
}
