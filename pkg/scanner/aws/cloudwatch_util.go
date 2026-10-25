package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// FetchCloudWatchMetric fetches a specific metric over the last 24 hours.
// It is used by scanners like EC2 and RDS to evaluate right-sizing and usage.
func FetchCloudWatchMetric(ctx context.Context, client *cloudwatch.Client, namespace, metricName string, dimensionName, dimensionValue string, stat cwtypes.Statistic) (float64, error) {
	endTime := time.Now()
	startTime := endTime.Add(-24 * time.Hour)

	input := &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(namespace),
		MetricName: aws.String(metricName),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String(dimensionName),
				Value: aws.String(dimensionValue),
			},
		},
		StartTime:  aws.Time(startTime),
		EndTime:    aws.Time(endTime),
		Period:     aws.Int32(24 * 60 * 60), // 1 day period
		Statistics: []cwtypes.Statistic{stat},
	}

	output, err := client.GetMetricStatistics(ctx, input)
	if err != nil || len(output.Datapoints) == 0 {
		return 0, err
	}

	dp := output.Datapoints[0]

	switch stat {
	case cwtypes.StatisticMaximum:
		return aws.ToFloat64(dp.Maximum), nil
	case cwtypes.StatisticSum:
		return aws.ToFloat64(dp.Sum), nil
	case cwtypes.StatisticAverage:
		return aws.ToFloat64(dp.Average), nil
	default:
		return 0, nil
	}
}
