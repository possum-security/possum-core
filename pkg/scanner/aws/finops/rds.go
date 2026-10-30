package finops

import (
	"context"
	"fmt"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// RDSInstanceAPI defines the RDS API subset needed by RDSScanner.
type RDSInstanceAPI interface {
	rds.DescribeDBInstancesAPIClient
}

// RDSScanner checks for Zombie (no connections) and Over-provisioned RDS databases.
type RDSScanner struct {
	rdsClient RDSInstanceAPI
	cwClient  CloudWatchMetricAPI
	region    string
}

// Ensure RDSScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*RDSScanner)(nil)

var rdsCostMap = map[string]float64{
	"db.t3.micro":  0.017,
	"db.t3.small":  0.034,
	"db.t3.medium": 0.068,
	"db.m5.large":  0.171,
	"db.m5.xlarge": 0.342,
	"db.r5.large":  0.24,
	"db.r5.xlarge": 0.48,
}

func NewRDSScanner(cfg aws.Config) *RDSScanner {
	return &RDSScanner{
		rdsClient: rds.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    cfg.Region,
	}
}

func NewRDSScannerWithClients(rdsClient RDSInstanceAPI, cwClient CloudWatchMetricAPI, region ...string) *RDSScanner {
	r := ""
	if len(region) > 0 {
		r = region[0]
	}
	return &RDSScanner{
		rdsClient: rdsClient,
		cwClient:  cwClient,
		region:    r,
	}
}

func (s *RDSScanner) Name() string {
	return "RDS-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *RDSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "rds-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "rds",
		CheckIDs:      []string{RuleRDSInstanceIdle},
	}
}

func (s *RDSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	paginator := rds.NewDescribeDBInstancesPaginator(s.rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, instance := range page.DBInstances {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++

			instanceID := aws.ToString(instance.DBInstanceIdentifier)
			state := aws.ToString(instance.DBInstanceStatus)

			isOrphaned := false
			costWaste := 0.0

			instanceClass := aws.ToString(instance.DBInstanceClass)
			hourlyRate, hasCost := rdsCostMap[instanceClass]
			monthlyCost := hourlyRate * 730
			if !hasCost {
				monthlyCost = 50.0 // fallback
			}

			metrics := map[string]interface{}{
				"DBInstanceClass":      instanceClass,
				"Engine":               aws.ToString(instance.Engine),
				"State":                state,
				"EstimatedMonthlyCost": monthlyCost,
			}

			if state == "available" {
				// 1. Fetch 30-day Max CPU for right-sizing
				maxCPU, cpuErr := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", instanceID, cwtypes.StatisticMaximum)

				// 2. Fetch Max Database Connections to detect Zombies
				maxConnections, connErr := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", instanceID, cwtypes.StatisticMaximum)

				if metricErr := firstErr(cpuErr, connErr); metricErr != nil {
					metrics["MetricFetchError"] = metricErr.Error()
				} else {
					metrics["MaxCPU_30Days"] = maxCPU
					metrics["MaxConnections_30Days"] = maxConnections

					if !isResourceTooYoung(instance.InstanceCreateTime) {
						// --- Anomaly Detection Logic ---
						if maxConnections == 0 {
							// ZOMBIE DETECT: Literally 0 connections to the database over the last 30 days.
							isOrphaned = true
							costWaste = monthlyCost
							metrics["IssueType"] = "Zombie DB"
							metrics["Recommendation"] = "Take Snapshot & Delete DB (0 connections in 30 days)"
						} else if maxCPU >= 75.0 {
							metrics["IssueType"] = "Scale Up (High Utilization)"
							metrics["Recommendation"] = fmt.Sprintf("Scale Up RDS Instance Class — High CPU load (Max CPU: %.1f%% exceeds 75%% threshold).", maxCPU)
						} else if maxCPU < 15.0 {
							isOrphaned = true // Over-provisioned is flagged for FinOps savings
							costWaste = monthlyCost * 0.5
							metrics["IssueType"] = "Over-Provisioned DB"
							metrics["Recommendation"] = fmt.Sprintf("Downsize DB Instance Class — Max CPU is only %.1f%%.", maxCPU)
						}
					}
				}
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   instanceID,
				ResourceType: "RDS",
				Region:       regionFromAZ(s.region, aws.ToString(instance.AvailabilityZone)),
				RuleID:       RuleRDSInstanceIdle,
				DisplayName:  instanceID,
				IsOrphaned:   isOrphaned,
				Cost:         costWaste,
				Title:        "Idle or Over-Provisioned RDS Instance",
				Description:  "RDS instance has 0 connections or very low CPU utilization over 30 days.",
				Remediation:  "Take a final snapshot and delete unused RDS instance, or downscale instance class.",
				Metrics:      metrics,
			}))
		}
	}

	return results, nil
}
