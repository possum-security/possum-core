package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDynamoDBClient struct {
	listTablesFn    func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	describeTableFn func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

func (m *mockDynamoDBClient) ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	if m.listTablesFn != nil {
		return m.listTablesFn(ctx, params, optFns...)
	}
	return &dynamodb.ListTablesOutput{}, nil
}

func (m *mockDynamoDBClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if m.describeTableFn != nil {
		return m.describeTableFn(ctx, params, optFns...)
	}
	return &dynamodb.DescribeTableOutput{}, nil
}

type mockCWClient struct {
	getMetricStatisticsFn func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

func (m *mockCWClient) GetMetricStatistics(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	if m.getMetricStatisticsFn != nil {
		return m.getMetricStatisticsFn(ctx, params, optFns...)
	}
	return &cloudwatch.GetMetricStatisticsOutput{}, nil
}

func TestDynamoDBScanner_Scan(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)

	mockClient := &mockDynamoDBClient{
		listTablesFn: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"high-provisioned-table", "low-provisioned-table", "on-demand-table", "error-table"},
			}, nil
		},
		describeTableFn: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			name := aws.ToString(params.TableName)
			switch name {
			case "high-provisioned-table":
				return &dynamodb.DescribeTableOutput{
					Table: &ddbtypes.TableDescription{
						TableName:        aws.String(name),
						TableArn:         aws.String("arn:aws:dynamodb:us-east-1:123456789012:table/high-provisioned-table"),
						CreationDateTime: aws.Time(oldTime),
						ProvisionedThroughput: &ddbtypes.ProvisionedThroughputDescription{
							ReadCapacityUnits:  aws.Int64(20),
							WriteCapacityUnits: aws.Int64(20),
						},
					},
				}, nil
			case "low-provisioned-table":
				return &dynamodb.DescribeTableOutput{
					Table: &ddbtypes.TableDescription{
						TableName:        aws.String(name),
						CreationDateTime: aws.Time(oldTime),
						ProvisionedThroughput: &ddbtypes.ProvisionedThroughputDescription{
							ReadCapacityUnits:  aws.Int64(5),
							WriteCapacityUnits: aws.Int64(5),
						},
					},
				}, nil
			case "on-demand-table":
				return &dynamodb.DescribeTableOutput{
					Table: &ddbtypes.TableDescription{
						TableName:        aws.String(name),
						CreationDateTime: aws.Time(oldTime),
					},
				}, nil
			default:
				return nil, errors.New("table not found or access denied")
			}
		},
	}

	sc := finops.NewDynamoDBScannerWithClients(mockClient, &mockCWClient{}, "us-east-1")
	assert.Equal(t, "DynamoDB-FinOps-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	// 3 valid tables (error-table is skipped)
	require.Len(t, results, 3)

	// High provisioned table -> Fail
	assert.Equal(t, "arn:aws:dynamodb:us-east-1:123456789012:table/high-provisioned-table", results[0].ResourceID)
	assert.Equal(t, finops.RuleDynamoDBProvisionedCapacityUnused, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	assert.InDelta(t, 11.20, results[0].CostWasteMo, 0.01) // 20*0.09 + 20*0.47 = 1.8 + 9.4 = 11.2
	assert.Equal(t, "us-east-1", results[0].Region)

	// Low provisioned table -> Pass
	assert.Equal(t, "low-provisioned-table", results[1].ResourceID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// On-Demand table -> Pass
	assert.Equal(t, "on-demand-table", results[2].ResourceID)
	assert.False(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[2].Status)
}

func TestDynamoDBScanner_Error(t *testing.T) {
	mockClient := &mockDynamoDBClient{
		listTablesFn: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return nil, errors.New("dynamodb: list tables failure")
		},
	}
	sc := finops.NewDynamoDBScannerWithClients(mockClient, nil)
	_, err := sc.Scan(context.Background())
	assert.Error(t, err)
}

func TestDynamoDBScanner_Limit(t *testing.T) {
	mockClient := &mockDynamoDBClient{
		listTablesFn: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{
				TableNames: []string{"t1", "t2"},
			}, nil
		},
		describeTableFn: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{TableName: params.TableName},
			}, nil
		},
	}
	sc := finops.NewDynamoDBScannerWithClients(mockClient, nil, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
