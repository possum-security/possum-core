package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRedshiftCustomClient struct {
	describeClustersFn func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
}

func (m *mockRedshiftCustomClient) DescribeClusters(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	if m.describeClustersFn != nil {
		return m.describeClustersFn(ctx, params, optFns...)
	}
	return &redshift.DescribeClustersOutput{}, nil
}

func TestRedshiftScanner_IdleAndActive(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	youngTime := time.Now().Add(-2 * 24 * time.Hour)

	mockRS := &mockRedshiftCustomClient{
		describeClustersFn: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{
						ClusterIdentifier: aws.String("idle-cluster-1"),
						NodeType:          aws.String("dc2.large"),
						NumberOfNodes:     aws.Int32(2),
						ClusterCreateTime: aws.Time(oldTime),
					},
					{
						ClusterIdentifier: aws.String("active-cluster-2"),
						NodeType:          aws.String("ra3.xlplus"),
						NumberOfNodes:     aws.Int32(4),
						ClusterCreateTime: aws.Time(oldTime),
					},
					{
						ClusterIdentifier: aws.String("young-cluster-3"),
						NodeType:          aws.String("dc2.8xlarge"),
						NumberOfNodes:     aws.Int32(1),
						ClusterCreateTime: aws.Time(youngTime),
					},
				},
			}, nil
		},
	}

	mockCW := &mockCWClient{
		getMetricStatisticsFn: func(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
			clusterID := ""
			for _, dim := range params.Dimensions {
				if aws.ToString(dim.Name) == "ClusterIdentifier" {
					clusterID = aws.ToString(dim.Value)
				}
			}
			metricName := aws.ToString(params.MetricName)

			switch clusterID {
			case "idle-cluster-1":
				if metricName == "CPUUtilization" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: aws.Float64(2.5)}}}, nil
				}
				if metricName == "DatabaseConnections" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Maximum: aws.Float64(0)}}}, nil
				}
			case "active-cluster-2":
				if metricName == "CPUUtilization" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: aws.Float64(65.0)}}}, nil
				}
				if metricName == "DatabaseConnections" {
					return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Maximum: aws.Float64(25)}}}, nil
				}
			case "young-cluster-3":
				return &cloudwatch.GetMetricStatisticsOutput{Datapoints: []cwtypes.Datapoint{{Average: aws.Float64(1.0), Maximum: aws.Float64(0)}}}, nil
			}
			return &cloudwatch.GetMetricStatisticsOutput{}, nil
		},
	}

	sc := finops.NewRedshiftScannerWithClients(mockRS, mockCW, "us-east-1")
	assert.Equal(t, "Redshift-FinOps-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	// Cluster 1: Idle -> Fail
	assert.Equal(t, "idle-cluster-1", results[0].ResourceID)
	assert.Equal(t, finops.RuleRedshiftClusterIdle, results[0].RuleID)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, model.StatusFail, results[0].Status)
	// hourlyRate 0.25 * 2 nodes * 730 = 365
	assert.InDelta(t, 365.0, results[0].CostWasteMo, 0.1)

	// Cluster 2: Active -> Pass
	assert.Equal(t, "active-cluster-2", results[1].ResourceID)
	assert.False(t, results[1].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[1].Status)
	assert.Equal(t, 0.0, results[1].CostWasteMo)

	// Cluster 3: Young -> Pass
	assert.Equal(t, "young-cluster-3", results[2].ResourceID)
	assert.False(t, results[2].IsOrphaned)
	assert.Equal(t, model.StatusPass, results[2].Status)
}

func TestRedshiftScanner_ErrorsAndLimits(t *testing.T) {
	// Describe error
	mockErr := &mockRedshiftCustomClient{
		describeClustersFn: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return nil, errors.New("redshift: describe clusters error")
		},
	}
	scErr := finops.NewRedshiftScannerWithClients(mockErr, nil)
	_, err := scErr.Scan(context.Background())
	assert.Error(t, err)

	// ResourceLimit
	mockValid := &mockRedshiftCustomClient{
		describeClustersFn: func(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
			return &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{ClusterIdentifier: aws.String("c-1")},
					{ClusterIdentifier: aws.String("c-2")},
				},
			}, nil
		},
	}
	scLimit := finops.NewRedshiftScannerWithClients(mockValid, nil)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scLimit.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
