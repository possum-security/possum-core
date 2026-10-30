package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLambdaCustomClient struct {
	listFunctionsFn func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

func (m *mockLambdaCustomClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if m.listFunctionsFn != nil {
		return m.listFunctionsFn(ctx, params, optFns...)
	}
	return &lambda.ListFunctionsOutput{}, nil
}

func TestLambdaScanner_RecommendationsAndOptimization(t *testing.T) {
	oldDateStr := time.Now().Add(-30 * 24 * time.Hour).Format("2006-01-02T15:04:05.000+0000")
	youngDateStr := time.Now().Add(-1 * 24 * time.Hour).Format(time.RFC3339)

	mockLambda := &mockLambdaCustomClient{
		listFunctionsFn: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []lambdatypes.FunctionConfiguration{
					{
						FunctionName: aws.String("dormant-fn"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:dormant-fn"),
						MemorySize:   aws.Int32(128),
						Timeout:      aws.Int32(30),
						LastModified: aws.String(oldDateStr),
					},
					{
						FunctionName: aws.String("throttled-fn"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:throttled-fn"),
						MemorySize:   aws.Int32(512),
						Timeout:      aws.Int32(30),
						LastModified: aws.String(oldDateStr),
					},
					{
						FunctionName: aws.String("high-duration-fn"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:high-duration-fn"),
						MemorySize:   aws.Int32(512),
						Timeout:      aws.Int32(10), // 10s = 10000ms
						LastModified: aws.String(oldDateStr),
					},
					{
						FunctionName: aws.String("overprovisioned-mem-fn"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:overprovisioned-mem-fn"),
						MemorySize:   aws.Int32(2048),
						Timeout:      aws.Int32(60),
						LastModified: aws.String(oldDateStr),
					},
					{
						FunctionName: aws.String("young-fn"),
						MemorySize:   aws.Int32(128),
						Timeout:      aws.Int32(3),
						LastModified: aws.String(youngDateStr),
					},
				},
			}, nil
		},
	}

	mockCW := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			fnName := ""
			for _, dim := range params.Dimensions {
				if aws.ToString(dim.Name) == "FunctionName" {
					fnName = aws.ToString(dim.Value)
				}
			}
			metricName := aws.ToString(params.MetricName)

			switch fnName {
			case "dormant-fn":
				// 0 invocations
				return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}}}, nil
			case "throttled-fn":
				if metricName == "Invocations" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(5000)}}}, nil
				}
				if metricName == "Throttles" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(25)}}}, nil
				}
				return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: aws.Float64(100), Maximum: aws.Float64(200)}}}, nil
			case "high-duration-fn":
				if metricName == "Invocations" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(1000)}}}, nil
				}
				if metricName == "Duration" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: aws.Float64(8000), Maximum: aws.Float64(9000)}}}, nil // 9000ms >= 75% of 10000ms
				}
				return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}}}, nil
			case "overprovisioned-mem-fn":
				if metricName == "Invocations" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(50000)}}}, nil
				}
				if metricName == "Duration" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: aws.Float64(50), Maximum: aws.Float64(80)}}}, nil // 50ms < 200ms
				}
				return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}}}, nil
			case "young-fn":
				return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Sum: aws.Float64(0)}}}, nil
			}
			return &cloudwatch.GetMetricStatisticsOutput{}, nil
		},
	}

	sc := finops.NewLambdaScannerWithClients(mockLambda, mockCW, "us-east-1")
	assert.Equal(t, "Lambda-FinOps-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5)

	// Dormant function -> Fail
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:dormant-fn", results[0].ResourceID)
	assert.Equal(t, finops.RuleLambdaFunctionUnused, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	m0 := results[0].Metrics.(map[string]interface{})
	assert.Equal(t, "Dormant Function", m0["IssueType"])

	// Throttled function -> Pass with scale up recommendation
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	m1 := results[1].Metrics.(map[string]interface{})
	assert.Equal(t, "Scale Up (Throttled)", m1["IssueType"])

	// High duration function -> Pass with scale up memory recommendation
	assert.False(t, results[2].IsOrphaned)
	m2 := results[2].Metrics.(map[string]interface{})
	assert.Equal(t, "Scale Up (High Duration/Memory)", m2["IssueType"])

	// Overprovisioned memory function -> Pass with downsize recommendation
	assert.False(t, results[3].IsOrphaned)
	m3 := results[3].Metrics.(map[string]interface{})
	assert.Equal(t, "Over-Provisioned Memory", m3["IssueType"])

	// Young function -> Pass
	assert.False(t, results[4].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[4].Status)
}

func TestLambdaScanner_ErrorsAndLimits(t *testing.T) {
	// ListFunctions error
	mockErr := &mockLambdaCustomClient{
		listFunctionsFn: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return nil, errors.New("lambda: list functions error")
		},
	}
	scErr := finops.NewLambdaScannerWithClients(mockErr, nil)
	_, err := scErr.Scan(context.Background())
	assert.Error(t, err)

	// ResourceLimit
	mockValid := &mockLambdaCustomClient{
		listFunctionsFn: func(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
			return &lambda.ListFunctionsOutput{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionName: aws.String("fn-1")},
					{FunctionName: aws.String("fn-2")},
				},
			}, nil
		},
	}
	scLimit := finops.NewLambdaScannerWithClients(mockValid, nil)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scLimit.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
