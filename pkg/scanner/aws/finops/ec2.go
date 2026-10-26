package finops

import (
	"context"
	"fmt"
	"time"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var instanceCostMap = map[string]float64{
	"t2.nano":     0.0058,
	"t2.micro":    0.0116,
	"t2.small":    0.0232,
	"t2.medium":   0.0464,
	"t2.large":    0.0928,
	"t2.xlarge":   0.1856,
	"t2.2xlarge":  0.3712,
	"t3.micro":    0.0104,
	"t3.small":    0.0208,
	"t3.medium":   0.0416,
	"t3.large":    0.0832,
	"t3.xlarge":   0.1664,
	"t3.2xlarge":  0.3328,
	"m5.large":    0.096,
	"m5.xlarge":   0.192,
	"m5.2xlarge":  0.384,
	"m5.4xlarge":  0.768,
	"m5.8xlarge":  1.536,
	"m5.12xlarge": 2.304,
	"m5.16xlarge": 3.072,
	"m5.24xlarge": 4.608,
	"c5.large":    0.085,
	"c5.xlarge":   0.17,
	"c5.2xlarge":  0.34,
	"c5.4xlarge":  0.68,
	"c5.9xlarge":  1.53,
	"c5.18xlarge": 3.06,
	"r5.large":    0.126,
	"r5.xlarge":   0.252,
	"r5.2xlarge":  0.504,
	"r5.4xlarge":  1.008,
	"r5.12xlarge": 3.024,
	"r5.24xlarge": 6.048,
	"p3.2xlarge":  3.06,
	"p3.8xlarge":  12.24,
	"p3.16xlarge": 24.48,
}

// EC2Scanner checks for Zombie and Over-provisioned EC2 instances.
type EC2Scanner struct {
	ec2Client *ec2.Client
	cwClient  *cloudwatch.Client
}

func NewEC2Scanner(cfg aws.Config) *EC2Scanner {
	return &EC2Scanner{
		ec2Client: ec2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *EC2Scanner) Name() string {
	return "EC2-Advanced-Scanner"
}

func (s *EC2Scanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := ec2.NewDescribeInstancesPaginator(s.ec2Client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, reservation := range page.Reservations {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			for _, instance := range reservation.Instances {
				instanceID := aws.ToString(instance.InstanceId)
				state := string(instance.State.Name)

				isOrphaned := false

				instanceName := ""
				for _, tag := range instance.Tags {
					if aws.ToString(tag.Key) == "Name" {
						instanceName = aws.ToString(tag.Value)
						break
					}
				}

				hourlyRate, hasCost := instanceCostMap[string(instance.InstanceType)]
				monthlyCost := hourlyRate * 730

				if !hasCost {
					monthlyCost = 25.0 // Generic fallback cost if not found
				}

				metrics := map[string]interface{}{
					"InstanceType":         string(instance.InstanceType),
					"State":                state,
					"InstanceName":         instanceName,
					"EstimatedMonthlyCost": monthlyCost,
				}
				if !hasCost {
					metrics["CostEstimateAvailable"] = false
				}

				if instance.State.Name == types.InstanceStateNameRunning {
					// 1. Fetch 30-day Max CPU for right-sizing
					maxCPU, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/EC2", "CPUUtilization", "InstanceId", instanceID, cwtypes.StatisticMaximum)
					metrics["MaxCPU_30Days"] = maxCPU

					// 2. Fetch Network I/O (Sum) to detect Zombies
					netIn, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/EC2", "NetworkIn", "InstanceId", instanceID, cwtypes.StatisticSum)
					netOut, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/EC2", "NetworkOut", "InstanceId", instanceID, cwtypes.StatisticSum)
					metrics["NetworkIn_30Days"] = netIn
					metrics["NetworkOut_30Days"] = netOut

					// 3. (Optional) Fetch Memory if CloudWatch Agent is installed
					// AWS doesn't provide memory natively, so we look in the CWAgent namespace
					maxMem, err := FetchCloudWatchMetric(ctx, s.cwClient, "CWAgent", "mem_used_percent", "InstanceId", instanceID, cwtypes.StatisticMaximum)
					if err == nil && maxMem > 0 {
						metrics["MaxMemory_30Days"] = maxMem
					}

					// --- Anomaly Detection Logic ---
					// 1. SCALE UP DETECT: CPU or Memory exceeds 75% utilization (performance & reliability risk)
					memVal := 0.0
					if val, ok := metrics["MaxMemory_30Days"]; ok {
						memVal = val.(float64)
					}

					if maxCPU >= 75.0 || memVal >= 75.0 {
						metrics["IssueType"] = "Scale Up (High Utilization)"
						metrics["Recommendation"] = fmt.Sprintf("Scale Up Instance (%s) — High utilization detected (Max CPU: %.1f%%, Max Memory: %.1f%% exceeds 75%% threshold). Upgrade from %s to a larger instance size or compute/memory-optimized family to prevent throttling and outages.", instanceID, maxCPU, memVal, string(instance.InstanceType))
					} else if maxCPU < 2.0 && (netIn+netOut) < 10000000 {
						// 2. ZOMBIE DETECT: Very low Max CPU AND basically zero network traffic over 30 days
						isOrphaned = true
						metrics["IssueType"] = "Zombie Instance"
						metrics["Recommendation"] = fmt.Sprintf("Terminate Instance — estimated waste: $%.2f/month", monthlyCost)
					} else if maxCPU < 15.0 || (memVal > 0 && memVal < 30.0) {
						// 3. RIGHT-SIZE DETECT: Max CPU never exceeds 15% (and not already a zombie)
						metrics["IssueType"] = "Over-Provisioned Instance"
						metrics["Recommendation"] = fmt.Sprintf("Downsize Instance Type — current cost: $%.2f/month, Max CPU: %.1f%%", monthlyCost, maxCPU)
					}
				}

				var nodes []graph.Node
				var edges []graph.Edge
				nodes = append(nodes, graph.Node{ID: instanceID, NodeType: "SecaaS-EC2"})
				for _, sg := range instance.SecurityGroups {
					edges = append(edges, graph.Edge{From: aws.ToString(sg.GroupId), To: instanceID, Relation: "ATTACHED_TO"})
				}
				if instance.IamInstanceProfile != nil && instance.IamInstanceProfile.Arn != nil {
					edges = append(edges, graph.Edge{From: instanceID, To: aws.ToString(instance.IamInstanceProfile.Arn), Relation: "HAS_ROLE"})
				}
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "EC2",
					Region:       aws.ToString(instance.Placement.AvailabilityZone),
					IsOrphaned:   isOrphaned,
					Metrics:      metrics,
					Nodes:        nodes,
					Edges:        edges,
				})
			}
		}
	}

	return results, nil
}

func FetchCloudWatchMetric(ctx context.Context, client *cloudwatch.Client, namespace, metricName string, dimensionName, dimensionValue string, stat cwtypes.Statistic) (float64, error) {
	endTime := time.Now()
	startTime := endTime.Add(-30 * 24 * time.Hour)

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
		Period:     aws.Int32(30 * 24 * 60 * 60),
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
