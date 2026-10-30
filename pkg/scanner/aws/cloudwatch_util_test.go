package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCloudWatchAPI struct {
	output *cloudwatch.GetMetricStatisticsOutput
	err    error
}

func (m *mockCloudWatchAPI) GetMetricStatistics(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	return m.output, m.err
}

func TestFetchCloudWatchMetric(t *testing.T) {
	ctx := context.Background()

	// 1. Nil client error
	_, err := FetchCloudWatchMetric(ctx, nil, "AWS/EC2", "CPUUtilization", "InstanceId", "i-123", cwtypes.StatisticAverage)
	require.Error(t, err)

	// 2. Client error returned
	clientErr := &mockCloudWatchAPI{err: errors.New("access denied")}
	_, err = FetchCloudWatchMetric(ctx, clientErr, "AWS/EC2", "CPUUtilization", "InstanceId", "i-123", cwtypes.StatisticAverage)
	require.Error(t, err)

	// 3. Empty datapoints -> returns 0, nil
	clientEmpty := &mockCloudWatchAPI{output: &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{}}}
	val, err := FetchCloudWatchMetric(ctx, clientEmpty, "AWS/EC2", "CPUUtilization", "InstanceId", "i-123", cwtypes.StatisticAverage)
	require.NoError(t, err)
	assert.Equal(t, 0.0, val)

	// 4. Maximum statistic
	clientMax := &mockCloudWatchAPI{output: &cloudwatch.GetMetricStatisticsOutput{
		Datapoints: []cwtypes.Datapoint{
			{Maximum: aws.Float64(12.5)},
			{Maximum: aws.Float64(45.2)},
			{Maximum: aws.Float64(30.1)},
		},
	}}
	maxVal, err := FetchCloudWatchMetric(ctx, clientMax, "AWS/EC2", "CPUUtilization", "InstanceId", "i-123", cwtypes.StatisticMaximum)
	require.NoError(t, err)
	assert.InDelta(t, 45.2, maxVal, 0.001)

	// 5. Average statistic
	clientAvg := &mockCloudWatchAPI{output: &cloudwatch.GetMetricStatisticsOutput{
		Datapoints: []cwtypes.Datapoint{
			{Average: aws.Float64(10.0)},
			{Average: aws.Float64(20.0)},
		},
	}}
	avgVal, err := FetchCloudWatchMetric(ctx, clientAvg, "AWS/EC2", "CPUUtilization", "InstanceId", "i-123", cwtypes.StatisticAverage)
	require.NoError(t, err)
	assert.InDelta(t, 15.0, avgVal, 0.001)

	// 6. Sum statistic
	clientSum := &mockCloudWatchAPI{output: &cloudwatch.GetMetricStatisticsOutput{
		Datapoints: []cwtypes.Datapoint{
			{Sum: aws.Float64(100.0)},
			{Sum: aws.Float64(250.0)},
		},
	}}
	sumVal, err := FetchCloudWatchMetric(ctx, clientSum, "AWS/EC2", "NetworkIn", "InstanceId", "i-123", cwtypes.StatisticSum)
	require.NoError(t, err)
	assert.InDelta(t, 350.0, sumVal, 0.001)
}
