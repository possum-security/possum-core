package finops

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

// ECSScanner scans ECS clusters and services to detect over-utilized (scale up),
// under-utilized (downsize), and orphaned (0 tasks) container workloads.
type ECSScanner struct {
	ecsClient *ecs.Client
	cwClient  *cloudwatch.Client
}

func NewECSScanner(cfg aws.Config) *ECSScanner {
	return &ECSScanner{
		ecsClient: ecs.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *ECSScanner) Name() string {
	return "ECS-FinOps-Scanner"
}

func (s *ECSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// 1. List Clusters
	clusterPaginator := ecs.NewListClustersPaginator(s.ecsClient, &ecs.ListClustersInput{})
	for clusterPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		cPage, err := clusterPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, clusterArn := range cPage.ClusterArns {
			if limit > 0 && processedCount >= limit {
				break
			}

			// 2. List Services in Cluster
			svcPaginator := ecs.NewListServicesPaginator(s.ecsClient, &ecs.ListServicesInput{
				Cluster: aws.String(clusterArn),
			})

			for svcPaginator.HasMorePages() {
				sPage, err := svcPaginator.NextPage(ctx)
				if err != nil {
					break
				}
				if len(sPage.ServiceArns) == 0 {
					continue
				}

				// Describe Services (up to 10 at a time)
				descOut, err := s.ecsClient.DescribeServices(ctx, &ecs.DescribeServicesInput{
					Cluster:  aws.String(clusterArn),
					Services: sPage.ServiceArns,
				})
				if err != nil {
					continue
				}

				for _, svc := range descOut.Services {
					if limit > 0 && processedCount >= limit {
						break
					}
					processedCount++

					svcName := aws.ToString(svc.ServiceName)
					clusterName := aws.ToString(svc.ClusterArn)
					runningCount := svc.RunningCount
					desiredCount := svc.DesiredCount
					launchType := string(svc.LaunchType)
					if launchType == "" && svc.CapacityProviderStrategy != nil {
						launchType = "FARGATE"
					}

					// Approximate monthly cost for Fargate tasks: ~$30/vCPU/month + $3.30/GB/month
					monthlyCost := float64(desiredCount) * 45.00
					if desiredCount == 0 {
						monthlyCost = 0.0
					}

					metrics := map[string]interface{}{
						"ServiceName":          svcName,
						"Cluster":              clusterName,
						"RunningCount":         runningCount,
						"DesiredCount":         desiredCount,
						"LaunchType":           launchType,
						"EstimatedMonthlyCost": monthlyCost,
					}

					isOrphaned := false
					var recommendation string

					// Fetch CloudWatch CPU and Memory metrics
					maxCPU, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/ECS", "CPUUtilization", "ServiceName", svcName, cwtypes.StatisticMaximum)
					maxMem, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/ECS", "MemoryUtilization", "ServiceName", svcName, cwtypes.StatisticMaximum)
					metrics["MaxCPU_30Days"] = maxCPU
					metrics["MaxMemory_30Days"] = maxMem

					// Check for scale-up vs downsize vs zombie
					if runningCount == 0 && desiredCount == 0 {
						isOrphaned = true
						metrics["IssueType"] = "Dormant Service (0 Desired Tasks)"
						recommendation = "Decommission inactive ECS service to reduce configuration overhead."
					} else if maxCPU >= 75.0 || maxMem >= 75.0 {
						metrics["IssueType"] = "Scale Up (High Utilization)"
						recommendation = fmt.Sprintf("Scale Up ECS Service — High utilization detected (Max CPU: %.1f%%, Max Memory: %.1f%% exceeds 75%% threshold). Increase task CPU/Memory reservations or scale out desired task count to prevent container throttling and OOM kills.", maxCPU, maxMem)
					} else if runningCount > 0 && maxCPU < 10.0 && maxMem < 20.0 {
						metrics["IssueType"] = "Over-Provisioned Service"
						recommendation = fmt.Sprintf("Downsize ECS Service — Low resource utilization (Max CPU: %.1f%%, Max Memory: %.1f%%). Consider reducing task size or decreasing desired task count to optimize spend.", maxCPU, maxMem)
					}

					if recommendation != "" {
						metrics["Recommendation"] = recommendation
					}

					var nodes []graph.Node
					nodes = append(nodes, graph.Node{
						ID:       aws.ToString(svc.ServiceArn),
						NodeType: "ECS",
						Data: map[string]interface{}{
							"name":       svcName,
							"isOrphaned": isOrphaned,
						},
					})

					results = append(results, scanner.ScanResult{
						ResourceID:   svcName,
						ResourceType: "ECS",
						Region:       "regional",
						IsOrphaned:   isOrphaned,
						Metrics:      metrics,
						Nodes:        nodes,
					})
				}
			}
		}
	}

	return results, nil
}
