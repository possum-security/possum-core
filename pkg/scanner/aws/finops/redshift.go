package finops

import (
	"context"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

type RedshiftScanner struct {
	rsClient *redshift.Client
	cwClient *cloudwatch.Client
}

// Ensure RedshiftScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*RedshiftScanner)(nil)

func NewRedshiftScanner(cfg aws.Config) *RedshiftScanner {
	return &RedshiftScanner{
		rsClient: redshift.NewFromConfig(cfg),
		cwClient: cloudwatch.NewFromConfig(cfg),
	}
}

func (s *RedshiftScanner) Name() string {
	return "Redshift-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *RedshiftScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "redshift-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "redshift",
		CheckIDs:      []string{RuleRedshiftClusterIdle},
	}
}

func (s *RedshiftScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	paginator := redshift.NewDescribeClustersPaginator(s.rsClient, &redshift.DescribeClustersInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, cluster := range page.Clusters {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			clusterID := aws.ToString(cluster.ClusterIdentifier)

			cpu, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/Redshift", "CPUUtilization", "ClusterIdentifier", clusterID, cwtypes.StatisticAverage)
			conns, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/Redshift", "DatabaseConnections", "ClusterIdentifier", clusterID, cwtypes.StatisticMaximum)

			isOrphaned := false
			if cpu < 5.0 && conns == 0 {
				isOrphaned = true
			}

			nodeType := aws.ToString(cluster.NodeType)
			numNodes := float64(aws.ToInt32(cluster.NumberOfNodes))
			if numNodes == 0 {
				numNodes = 1
			}

			hourlyRate := 0.25
			switch nodeType {
			case "dc2.large":
				hourlyRate = 0.25
			case "dc2.8xlarge":
				hourlyRate = 4.80
			case "ra3.xlplus":
				hourlyRate = 1.086
			case "ra3.4xlarge":
				hourlyRate = 3.26
			case "ra3.16xlarge":
				hourlyRate = 13.04
			}
			monthlyCost := hourlyRate * numNodes * 730

			metrics := map[string]interface{}{
				"ClusterIdentifier":    clusterID,
				"EstimatedMonthlyCost": monthlyCost,
				"AverageCPU_7Days":     cpu,
				"MaxConnections_7Days": conns,
			}

			if isOrphaned {
				metrics["Recommendation"] = "Pause or terminate unused Redshift cluster"
			}

			costWaste := 0.0
			if isOrphaned {
				costWaste = monthlyCost
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   clusterID,
				ResourceType: "Redshift",
				Region:       "regional",
				RuleID:       RuleRedshiftClusterIdle,
				DisplayName:  clusterID,
				IsOrphaned:   isOrphaned,
				Cost:         costWaste,
				Title:        "Idle Amazon Redshift Cluster",
				Description:  "Redshift cluster has under 5% average CPU utilization and 0 database connections.",
				Remediation:  "Pause cluster via aws redshift pause-cluster or delete cluster after taking a final snapshot.",
				Metrics:      metrics,
			}))
		}
	}
	return results, nil
}
