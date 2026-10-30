package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCloudWatchClient struct {
	err     error
	output  *cloudwatch.GetMetricStatisticsOutput
	handler func(params *cloudwatch.GetMetricStatisticsInput) (*cloudwatch.GetMetricStatisticsOutput, error)
	inputs  []*cloudwatch.GetMetricStatisticsInput
}

func (m *mockCloudWatchClient) GetMetricStatistics(ctx context.Context, params *cloudwatch.GetMetricStatisticsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error) {
	m.inputs = append(m.inputs, params)
	if m.handler != nil {
		return m.handler(params)
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.output != nil {
		return m.output, nil
	}
	return &cloudwatch.GetMetricStatisticsOutput{}, nil
}

type mockEC2DescribeInstancesClient struct {
	output *ec2.DescribeInstancesOutput
	err    error
}

func (m *mockEC2DescribeInstancesClient) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

type mockRDSClient struct {
	output *rds.DescribeDBInstancesOutput
	err    error
}

func (m *mockRDSClient) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

type mockECSClient struct {
	clustersOutput *ecs.ListClustersOutput
	servicesOutput *ecs.ListServicesOutput
	describeOutput *ecs.DescribeServicesOutput
}

func (m *mockECSClient) ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return m.clustersOutput, nil
}

func (m *mockECSClient) ListServices(ctx context.Context, params *ecs.ListServicesInput, optFns ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	return m.servicesOutput, nil
}

func (m *mockECSClient) DescribeServices(ctx context.Context, params *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return m.describeOutput, nil
}

type mockCloudFrontClient struct {
	output *cloudfront.ListDistributionsOutput
}

func (m *mockCloudFrontClient) ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return m.output, nil
}

type mockELBClient struct {
	output *elbv2.DescribeLoadBalancersOutput
}

func (m *mockELBClient) DescribeLoadBalancers(ctx context.Context, params *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	return m.output, nil
}

type mockNATGatewayClient struct {
	output *ec2.DescribeNatGatewaysOutput
}

func (m *mockNATGatewayClient) DescribeNatGateways(ctx context.Context, params *ec2.DescribeNatGatewaysInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNatGatewaysOutput, error) {
	return m.output, nil
}

type mockLambdaClient struct {
	output *lambda.ListFunctionsOutput
}

func (m *mockLambdaClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	return m.output, nil
}

type mockRedshiftClient struct {
	output *redshift.DescribeClustersOutput
}

func (m *mockRedshiftClient) DescribeClusters(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	return m.output, nil
}

func dimensionsToMap(dims []cwtypes.Dimension) map[string]string {
	res := make(map[string]string, len(dims))
	for _, d := range dims {
		res[aws.ToString(d.Name)] = aws.ToString(d.Value)
	}
	return res
}

func TestCloudWatch_AccessDenied_DoesNotFlagAsZombieOrIdle(t *testing.T) {
	accessDeniedErr := errors.New("AccessDenied: User is not authorized to perform: cloudwatch:GetMetricStatistics")
	oldTime := time.Now().Add(-30 * 24 * time.Hour)

	t.Run("EC2", func(t *testing.T) {
		ec2Mock := &mockEC2DescribeInstancesClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:   aws.String("i-0123456789abcdef0"),
								InstanceType: ec2types.InstanceTypeM5Large,
								LaunchTime:   &oldTime,
								State: &ec2types.InstanceState{
									Name: ec2types.InstanceStateNameRunning,
								},
								Placement: &ec2types.Placement{
									AvailabilityZone: aws.String("us-east-1a"),
								},
							},
						},
					},
				},
			},
		}
		cwMock := &mockCloudWatchClient{err: accessDeniedErr}
		sc := finops.NewEC2ScannerWithClients(ec2Mock, cwMock, "us-east-1")

		results, err := sc.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, results, 1)

		assert.False(t, results[0].IsOrphaned)
		assert.Equal(t, model.StatusPass, results[0].Status)
		assert.Equal(t, 0.0, results[0].CostWasteMo)
		assert.Equal(t, "us-east-1", results[0].Region)
		metrics := results[0].Metrics.(map[string]interface{})
		assert.Contains(t, metrics["MetricFetchError"], "AccessDenied")
	})

	t.Run("RDS", func(t *testing.T) {
		rdsMock := &mockRDSClient{
			output: &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier: aws.String("prod-postgres"),
						DBInstanceClass:      aws.String("db.m5.large"),
						DBInstanceStatus:     aws.String("available"),
						InstanceCreateTime:   &oldTime,
						AvailabilityZone:     aws.String("us-west-2b"),
					},
				},
			},
		}
		cwMock := &mockCloudWatchClient{err: accessDeniedErr}
		sc := finops.NewRDSScannerWithClients(rdsMock, cwMock, "us-west-2")

		results, err := sc.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, results, 1)

		assert.False(t, results[0].IsOrphaned)
		assert.Equal(t, model.StatusPass, results[0].Status)
		assert.Equal(t, 0.0, results[0].CostWasteMo)
		assert.Equal(t, "us-west-2", results[0].Region)
		metrics := results[0].Metrics.(map[string]interface{})
		assert.Contains(t, metrics["MetricFetchError"], "AccessDenied")
	})

	t.Run("ECS", func(t *testing.T) {
		ecsMock := &mockECSClient{
			clustersOutput: &ecs.ListClustersOutput{
				ClusterArns: []string{"arn:aws:ecs:us-east-1:123456789012:cluster/prod-cluster"},
			},
			servicesOutput: &ecs.ListServicesOutput{
				ServiceArns: []string{"arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/web-api"},
			},
			describeOutput: &ecs.DescribeServicesOutput{
				Services: []ecstypes.Service{
					{
						ServiceName:  aws.String("web-api"),
						ServiceArn:   aws.String("arn:aws:ecs:us-east-1:123456789012:service/prod-cluster/web-api"),
						ClusterArn:   aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/prod-cluster"),
						RunningCount: 3,
						DesiredCount: 3,
						CreatedAt:    &oldTime,
					},
				},
			},
		}
		cwMock := &mockCloudWatchClient{err: accessDeniedErr}
		sc := finops.NewECSScannerWithClients(ecsMock, cwMock, "us-east-1")

		results, err := sc.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, results, 1)

		assert.False(t, results[0].IsOrphaned)
		assert.Equal(t, model.StatusPass, results[0].Status)
		assert.Equal(t, 0.0, results[0].CostWasteMo)
		assert.Equal(t, "us-east-1", results[0].Region)
		metrics := results[0].Metrics.(map[string]interface{})
		assert.Contains(t, metrics["MetricFetchError"], "AccessDenied")
	})

	t.Run("CloudFront", func(t *testing.T) {
		cfMock := &mockCloudFrontClient{
			output: &cloudfront.ListDistributionsOutput{
				DistributionList: &cftypes.DistributionList{
					Items: []cftypes.DistributionSummary{
						{
							Id:               aws.String("E1234567890ABC"),
							DomainName:       aws.String("d111111abcdef8.cloudfront.net"),
							LastModifiedTime: &oldTime,
						},
					},
				},
			},
		}
		cwMock := &mockCloudWatchClient{err: accessDeniedErr}
		sc := finops.NewCloudFrontScannerWithClients(cfMock, cwMock)

		results, err := sc.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, results, 1)

		assert.False(t, results[0].IsOrphaned)
		assert.Equal(t, model.StatusPass, results[0].Status)
		assert.Equal(t, 0.0, results[0].CostWasteMo)
		metrics := results[0].Metrics.(map[string]interface{})
		assert.Contains(t, metrics["MetricFetchError"], "AccessDenied")
	})

	t.Run("Lambda_And_Redshift", func(t *testing.T) {
		lambdaMock := &mockLambdaClient{
			output: &lambda.ListFunctionsOutput{
				Functions: []lambdatypes.FunctionConfiguration{
					{
						FunctionName: aws.String("my-func"),
						FunctionArn:  aws.String("arn:aws:lambda:us-east-1:123456789012:function:my-func"),
						MemorySize:   aws.Int32(512),
						Timeout:      aws.Int32(10),
					},
				},
			},
		}
		cwMock := &mockCloudWatchClient{err: accessDeniedErr}
		lScanner := finops.NewLambdaScannerWithClients(lambdaMock, cwMock, "us-east-1")
		lResults, err := lScanner.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, lResults, 1)
		assert.False(t, lResults[0].IsOrphaned)

		rsMock := &mockRedshiftClient{
			output: &redshift.DescribeClustersOutput{
				Clusters: []redshifttypes.Cluster{
					{
						ClusterIdentifier: aws.String("analytics-dw"),
						NodeType:          aws.String("dc2.large"),
						NumberOfNodes:     aws.Int32(2),
						ClusterCreateTime: &oldTime,
					},
				},
			},
		}
		rsScanner := finops.NewRedshiftScannerWithClients(rsMock, cwMock, "us-east-1")
		rsResults, err := rsScanner.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, rsResults, 1)
		assert.False(t, rsResults[0].IsOrphaned)
	})
}

func TestECSScanner_CloudWatchDimensions(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	ecsMock := &mockECSClient{
		clustersOutput: &ecs.ListClustersOutput{
			ClusterArns: []string{"arn:aws:ecs:us-east-1:123456789012:cluster/production-cluster"},
		},
		servicesOutput: &ecs.ListServicesOutput{
			ServiceArns: []string{"arn:aws:ecs:us-east-1:123456789012:service/production-cluster/checkout-service"},
		},
		describeOutput: &ecs.DescribeServicesOutput{
			Services: []ecstypes.Service{
				{
					ServiceName:  aws.String("checkout-service"),
					ServiceArn:   aws.String("arn:aws:ecs:us-east-1:123456789012:service/production-cluster/checkout-service"),
					ClusterArn:   aws.String("arn:aws:ecs:us-east-1:123456789012:cluster/production-cluster"),
					RunningCount: 2,
					DesiredCount: 2,
					CreatedAt:    &oldTime,
				},
			},
		},
	}

	cwMock := &mockCloudWatchClient{
		output: &cloudwatch.GetMetricStatisticsOutput{
			Datapoints: []cwtypes.Datapoint{
				{
					Maximum: aws.Float64(4.0),
				},
			},
		},
	}

	sc := finops.NewECSScannerWithClients(ecsMock, cwMock, "us-east-1")
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].IsOrphaned)
	assert.Equal(t, "us-east-1", results[0].Region)

	require.Len(t, cwMock.inputs, 2)
	for _, input := range cwMock.inputs {
		assert.Equal(t, "AWS/ECS", aws.ToString(input.Namespace))
		dims := dimensionsToMap(input.Dimensions)
		assert.Equal(t, "production-cluster", dims["ClusterName"], "expected ClusterName short name dimension")
		assert.Equal(t, "checkout-service", dims["ServiceName"], "expected ServiceName dimension")
	}
}

func TestCloudFrontScanner_CloudWatchDimensions(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	cfMock := &mockCloudFrontClient{
		output: &cloudfront.ListDistributionsOutput{
			DistributionList: &cftypes.DistributionList{
				Items: []cftypes.DistributionSummary{
					{
						Id:               aws.String("E999888777666"),
						DomainName:       aws.String("d999888777666.cloudfront.net"),
						LastModifiedTime: &oldTime,
					},
				},
			},
		},
	}

	cwMock := &mockCloudWatchClient{
		output: &cloudwatch.GetMetricStatisticsOutput{
			Datapoints: []cwtypes.Datapoint{
				{
					Sum: aws.Float64(0),
				},
			},
		},
	}

	sc := finops.NewCloudFrontScannerWithClients(cfMock, cwMock)
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].IsOrphaned)

	require.Len(t, cwMock.inputs, 2)
	for _, input := range cwMock.inputs {
		assert.Equal(t, "AWS/CloudFront", aws.ToString(input.Namespace))
		dims := dimensionsToMap(input.Dimensions)
		assert.Equal(t, "E999888777666", dims["DistributionId"], "expected DistributionId dimension")
		assert.Equal(t, "Global", dims["Region"], "expected Region=Global dimension")
	}
}

func TestMinimumResourceAge_PreventsFlaggingNewResources(t *testing.T) {
	launchedYesterday := time.Now().Add(-24 * time.Hour)
	launchedMonthAgo := time.Now().Add(-30 * 24 * time.Hour)

	cwIdleMock := &mockCloudWatchClient{
		output: &cloudwatch.GetMetricStatisticsOutput{
			Datapoints: []cwtypes.Datapoint{
				{
					Maximum: aws.Float64(0.0),
					Sum:     aws.Float64(0.0),
					Average: aws.Float64(0.0),
				},
			},
		},
	}

	t.Run("EC2_LaunchedYesterday_NotFlagged", func(t *testing.T) {
		ec2Mock := &mockEC2DescribeInstancesClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:   aws.String("i-new-instance"),
								InstanceType: ec2types.InstanceTypeT3Large,
								LaunchTime:   &launchedYesterday,
								State: &ec2types.InstanceState{
									Name: ec2types.InstanceStateNameRunning,
								},
								Placement: &ec2types.Placement{
									AvailabilityZone: aws.String("eu-west-1c"),
								},
							},
							{
								InstanceId:   aws.String("i-old-zombie"),
								InstanceType: ec2types.InstanceTypeT3Large,
								LaunchTime:   &launchedMonthAgo,
								State: &ec2types.InstanceState{
									Name: ec2types.InstanceStateNameRunning,
								},
								Placement: &ec2types.Placement{
									AvailabilityZone: aws.String("eu-west-1c"),
								},
							},
						},
					},
				},
			},
		}

		// Also verify AZ-to-region stripping when scanner region is empty
		sc := finops.NewEC2ScannerWithClients(ec2Mock, cwIdleMock)
		results, err := sc.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, results, 2)

		assert.Equal(t, "i-new-instance", results[0].ResourceID)
		assert.False(t, results[0].IsOrphaned, "instance launched yesterday should not be flagged as idle")
		assert.Equal(t, 0.0, results[0].CostWasteMo)
		assert.Equal(t, "eu-west-1", results[0].Region)

		assert.Equal(t, "i-old-zombie", results[1].ResourceID)
		assert.True(t, results[1].IsOrphaned, "instance launched 30 days ago with 0 utilization should be flagged")
		assert.Greater(t, results[1].CostWasteMo, 0.0)
		assert.Equal(t, "eu-west-1", results[1].Region)
	})

	t.Run("RDS_ELB_NATGateway_LaunchedYesterday_NotFlagged", func(t *testing.T) {
		rdsMock := &mockRDSClient{
			output: &rds.DescribeDBInstancesOutput{
				DBInstances: []rdstypes.DBInstance{
					{
						DBInstanceIdentifier: aws.String("new-db"),
						DBInstanceClass:      aws.String("db.t3.medium"),
						DBInstanceStatus:     aws.String("available"),
						InstanceCreateTime:   &launchedYesterday,
					},
				},
			},
		}
		rdsScanner := finops.NewRDSScannerWithClients(rdsMock, cwIdleMock, "us-east-1")
		rdsRes, err := rdsScanner.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, rdsRes, 1)
		assert.False(t, rdsRes[0].IsOrphaned)

		elbMock := &mockELBClient{
			output: &elbv2.DescribeLoadBalancersOutput{
				LoadBalancers: []elbv2types.LoadBalancer{
					{
						LoadBalancerName: aws.String("new-alb"),
						LoadBalancerArn:  aws.String("arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/new-alb/50dc6c495c0c9188"),
						Type:             elbv2types.LoadBalancerTypeEnumApplication,
						CreatedTime:      &launchedYesterday,
					},
				},
			},
		}
		elbScanner := finops.NewELBScannerWithClients(elbMock, cwIdleMock, "us-east-1")
		elbRes, err := elbScanner.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, elbRes, 1)
		assert.False(t, elbRes[0].IsOrphaned)

		natMock := &mockNATGatewayClient{
			output: &ec2.DescribeNatGatewaysOutput{
				NatGateways: []ec2types.NatGateway{
					{
						NatGatewayId: aws.String("nat-new"),
						State:        ec2types.NatGatewayStateAvailable,
						CreateTime:   &launchedYesterday,
					},
				},
			},
		}
		natScanner := finops.NewNATGatewayScannerWithClients(natMock, cwIdleMock, "us-east-1")
		natRes, err := natScanner.Scan(context.Background())
		require.NoError(t, err)
		require.Len(t, natRes, 1)
		assert.False(t, natRes[0].IsOrphaned)
	})
}

func TestRDSScanner_CostWaste_ZombieVsOverProvisioned(t *testing.T) {
	oldTime := time.Now().Add(-30 * 24 * time.Hour)
	rdsMock := &mockRDSClient{
		output: &rds.DescribeDBInstancesOutput{
			DBInstances: []rdstypes.DBInstance{
				{
					DBInstanceIdentifier: aws.String("zombie-db"),
					DBInstanceClass:      aws.String("db.m5.large"),
					DBInstanceStatus:     aws.String("available"),
					InstanceCreateTime:   &oldTime,
				},
				{
					DBInstanceIdentifier: aws.String("underutilized-db"),
					DBInstanceClass:      aws.String("db.m5.large"),
					DBInstanceStatus:     aws.String("available"),
					InstanceCreateTime:   &oldTime,
				},
			},
		},
	}

	cwMock := &mockCloudWatchClient{
		handler: func(params *cloudwatch.GetMetricStatisticsInput) (*cloudwatch.GetMetricStatisticsOutput, error) {
			dims := dimensionsToMap(params.Dimensions)
			dbID := dims["DBInstanceIdentifier"]
			metric := aws.ToString(params.MetricName)
			if dbID == "zombie-db" {
				return &cloudwatch.GetMetricStatisticsOutput{
					Datapoints: []cwtypes.Datapoint{{Maximum: aws.Float64(0.0)}},
				}, nil
			}
			if metric == "DatabaseConnections" {
				return &cloudwatch.GetMetricStatisticsOutput{
					Datapoints: []cwtypes.Datapoint{{Maximum: aws.Float64(10.0)}},
				}, nil
			}
			return &cloudwatch.GetMetricStatisticsOutput{
				Datapoints: []cwtypes.Datapoint{{Maximum: aws.Float64(5.0)}},
			}, nil
		},
	}

	sc := finops.NewRDSScannerWithClients(rdsMock, cwMock, "us-east-1")
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	expectedMonthly := 0.171 * 730
	assert.Equal(t, "zombie-db", results[0].ResourceID)
	assert.True(t, results[0].IsOrphaned)
	assert.InDelta(t, expectedMonthly, results[0].CostWasteMo, 0.01)

	assert.Equal(t, "underutilized-db", results[1].ResourceID)
	assert.True(t, results[1].IsOrphaned)
	assert.InDelta(t, expectedMonthly*0.5, results[1].CostWasteMo, 0.01)
}
