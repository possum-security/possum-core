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

// RDSScanner checks for Zombie (no connections) and Over-provisioned RDS databases.
type RDSScanner struct {
	rdsClient *rds.Client
	cwClient  *cloudwatch.Client
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
					metrics["IssueType"] = "Scale Up (High Utilization)"
					metrics["Recommendation"] = fmt.Sprintf("Scale Up RDS Instance Class — High CPU load (Max CPU: %.1f%% exceeds 75%% threshold).", maxCPU)
				} else if maxCPU < 15.0 {
					isOrphaned = true // Over-provisioned is flagged for FinOps savings
					metrics["IssueType"] = "Over-Provisioned DB"
					metrics["Recommendation"] = fmt.Sprintf("Downsize DB Instance Class — Max CPU is only %.1f%%.", maxCPU)
				}
			}

			costWaste := 0.0
			if isOrphaned {
				costWaste = monthlyCost
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   instanceID,
				ResourceType: "RDS",
				Region:       aws.ToString(instance.AvailabilityZone),
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
