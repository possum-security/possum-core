package finops

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
)

// ECSScanner scans ECS clusters and services to detect over-utilized, under-utilized, and dormant services.
type ECSScanner struct {
	ecsClient *ecs.Client
	cwClient  *cloudwatch.Client
}

// Ensure ECSScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*ECSScanner)(nil)

func NewECSScanner(cfg aws.Config) *ECSScanner {
	return &ECSScanner{
		ecsClient: ecs.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *ECSScanner) Name() string {
	return "ECS-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *ECSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "ecs-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "ecs",
		CheckIDs:      []string{RuleECSServiceIdle},
	}
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
					svcArn := aws.ToString(svc.ServiceArn)
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

					if runningCount == 0 && desiredCount == 0 {
						isOrphaned = true
						metrics["IssueType"] = "Dormant Service (0 Desired Tasks)"
						recommendation = "Decommission inactive ECS service to reduce configuration overhead."
					} else if maxCPU >= 75.0 || maxMem >= 75.0 {
						metrics["IssueType"] = "Scale Up (High Utilization)"
						recommendation = fmt.Sprintf("Scale Up ECS Service — High utilization detected (Max CPU: %.1f%%, Max Memory: %.1f%%).", maxCPU, maxMem)
					} else if runningCount > 0 && maxCPU < 10.0 && maxMem < 20.0 {
						isOrphaned = true
						metrics["IssueType"] = "Over-Provisioned Service"
						recommendation = fmt.Sprintf("Downsize ECS Service — Low resource utilization (Max CPU: %.1f%%, Max Memory: %.1f%%).", maxCPU, maxMem)
					}

					if recommendation != "" {
						metrics["Recommendation"] = recommendation
					}

					costWaste := 0.0
					if isOrphaned {
						costWaste = monthlyCost
					}

					resID := svcArn
					if resID == "" {
						resID = svcName
					}

					results = append(results, BuildFinOpsResult(FinOpsResultParams{
						ResourceID:   resID,
						ResourceType: "ECS",
						Region:       "regional",
						RuleID:       RuleECSServiceIdle,
						DisplayName:  svcName,
						IsOrphaned:   isOrphaned,
						Cost:         costWaste,
						Title:        "Dormant or Over-Provisioned ECS Service",
						Description:  fmt.Sprintf("ECS Service %s has 0 desired tasks or low utilization.", svcName),
						Remediation:  "Delete unused ECS service via aws ecs delete-service",
						Metrics:      metrics,
						Nodes: []model.Node{
							{
								ID:       resID,
								NodeType: "ECS",
								Data: map[string]interface{}{
									"name":       svcName,
									"isOrphaned": isOrphaned,
								},
							},
						},
					}))
				}
			}
		}
	}

	return results, nil
}
