package finops

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// RDSScanner checks for Zombie (no connections) and Over-provisioned RDS databases.
type RDSScanner struct {
	rdsClient *rds.Client
	cwClient  *cloudwatch.Client
}

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
	}
}

func (s *RDSScanner) Name() string {
	return "RDS-Scanner"
}

func (s *RDSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := rds.NewDescribeDBInstancesPaginator(s.rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, instance := range page.DBInstances {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			instanceID := aws.ToString(instance.DBInstanceIdentifier)
			state := aws.ToString(instance.DBInstanceStatus)

			isOrphaned := false

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
				maxCPU, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", instanceID, cwtypes.StatisticMaximum)
				metrics["MaxCPU_30Days"] = maxCPU

				// 2. Fetch Max Database Connections to detect Zombies
				maxConnections, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/RDS", "DatabaseConnections", "DBInstanceIdentifier", instanceID, cwtypes.StatisticMaximum)
				metrics["MaxConnections_30Days"] = maxConnections

				// --- Anomaly Detection Logic ---
				if maxConnections == 0 {
					// ZOMBIE DETECT: Literally 0 connections to the database over the last 30 days.
					isOrphaned = true
					metrics["IssueType"] = "Zombie DB"
					metrics["Recommendation"] = "Take Snapshot & Delete DB (0 connections in 30 days)"
				} else if maxCPU >= 75.0 {
					// SCALE UP DETECT: CPU >= 75%
					metrics["IssueType"] = "Scale Up (High Utilization)"
					metrics["Recommendation"] = fmt.Sprintf("Scale Up RDS Instance Class — High CPU load (Max CPU: %.1f%% exceeds 75%% threshold). Upgrade %s to a larger instance class or enable Aurora Serverless / Read Replicas to avoid latency spikes.", maxCPU, instanceClass)
				} else if maxCPU < 15.0 {
					// RIGHT-SIZE DOWN DETECT: Max CPU never exceeds 15%
					metrics["IssueType"] = "Over-Provisioned DB"
					metrics["Recommendation"] = fmt.Sprintf("Downsize DB Instance Class — Max CPU is only %.1f%%. Downsize from %s to optimize database cost.", maxCPU, instanceClass)
				}
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   instanceID,
				ResourceType: "RDS",
				Region:       aws.ToString(instance.AvailabilityZone),
				IsOrphaned:   isOrphaned, // True if 0 connections
				Metrics:      metrics,
			})
		}
	}

	return results, nil
}
