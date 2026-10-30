package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// CloudWatchMetricAPI defines the CloudWatch API subset needed for metric queries.
type CloudWatchMetricAPI interface {
	GetMetricStatistics(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

// FetchCloudWatchMetric fetches a specific metric over the last 24 hours.
// It is used by scanners like EC2 and RDS to evaluate right-sizing and usage.
func FetchCloudWatchMetric(ctx context.Context, client CloudWatchMetricAPI, namespace, metricName string, dimensionName, dimensionValue string, stat cwtypes.Statistic) (float64, error) {
	return FetchCloudWatchMetricWithDimensions(ctx, client, namespace, metricName, []cwtypes.Dimension{
		{
			Name:  aws.String(dimensionName),
			Value: aws.String(dimensionValue),
		},
	}, stat)
}

// FetchCloudWatchMetricWithDimensions fetches a specific metric over the last 24 hours using multiple dimensions.
func FetchCloudWatchMetricWithDimensions(ctx context.Context, client CloudWatchMetricAPI, namespace, metricName string, dimensions []cwtypes.Dimension, stat cwtypes.Statistic) (float64, error) {
	if client == nil {
		return 0, fmt.Errorf("cloudwatch client is nil")
	}

	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(namespace),
		MetricName: aws.String(metricName),
		Dimensions: dimensions,
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(24 * 60 * 60), // 1 day period
		Statistics: []cwtypes.Statistic{stat},
	}

	output, err := client.GetMetricStatistics(ctx, input)
	if err != nil {
		return 0, err
	}
	if output == nil || len(output.Datapoints) == 0 {
		return 0, nil
	}

	switch stat {
	case cwtypes.StatisticMaximum:
		maxVal := aws.ToFloat64(output.Datapoints[0].Maximum)
		for _, dp := range output.Datapoints[1:] {
			if v := aws.ToFloat64(dp.Maximum); v > maxVal {
				maxVal = v
			}
		}
		return maxVal, nil
	case cwtypes.StatisticSum:
		sumVal := 0.0
		for _, dp := range output.Datapoints {
			sumVal += aws.ToFloat64(dp.Sum)
		}
		return sumVal, nil
	case cwtypes.StatisticAverage:
		sumVal := 0.0
		for _, dp := range output.Datapoints {
			sumVal += aws.ToFloat64(dp.Average)
		}
		return sumVal / float64(len(output.Datapoints)), nil
	default:
		return 0, fmt.Errorf("unsupported cloudwatch statistic: %s", stat)
	}
}
