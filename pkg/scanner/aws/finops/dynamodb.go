package finops

import (
	"context"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type DynamoDBScanner struct {
	ddbClient *dynamodb.Client
	cwClient  *cloudwatch.Client
}

// Ensure DynamoDBScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*DynamoDBScanner)(nil)

func NewDynamoDBScanner(cfg aws.Config) *DynamoDBScanner {
	return &DynamoDBScanner{
		ddbClient: dynamodb.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *DynamoDBScanner) Name() string {
	return "DynamoDB-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *DynamoDBScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "dynamodb-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostLight,
		Service:       "dynamodb",
		CheckIDs:      []string{RuleDynamoDBProvisionedCapacityUnused},
	}
}

func (s *DynamoDBScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	paginator := dynamodb.NewListTablesPaginator(s.ddbClient, &dynamodb.ListTablesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, tableName := range page.TableNames {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			desc, err := s.ddbClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: aws.String(tableName),
			})
			if err != nil {
				continue
			}

			monthlyCost := 0.0
			isOrphaned := false
			metrics := map[string]interface{}{
				"TableName": tableName,
			}

			if desc.Table.ProvisionedThroughput != nil {
				rcu := aws.ToInt64(desc.Table.ProvisionedThroughput.ReadCapacityUnits)
				wcu := aws.ToInt64(desc.Table.ProvisionedThroughput.WriteCapacityUnits)
				monthlyCost = float64(rcu)*0.09 + float64(wcu)*0.47
				metrics["ProvisionedRCU"] = rcu
				metrics["ProvisionedWCU"] = wcu

				if rcu > 10 || wcu > 10 {
					isOrphaned = true
					metrics["Recommendation"] = "Consider switching to On-Demand capacity for unpredictable workloads"
				}
			}

			metrics["EstimatedMonthlyCost"] = monthlyCost

			costWaste := 0.0
			if isOrphaned {
				costWaste = monthlyCost
			}

			tableArn := aws.ToString(desc.Table.TableArn)
			resID := tableArn
			if resID == "" {
				resID = tableName
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   resID,
				ResourceType: "DynamoDB",
				Region:       "regional",
				RuleID:       RuleDynamoDBProvisionedCapacityUnused,
				DisplayName:  tableName,
				IsOrphaned:   isOrphaned,
				Cost:         costWaste,
				Title:        "DynamoDB Provisioned Capacity Optimization",
				Description:  "DynamoDB table has high fixed provisioned throughput that may be underutilized.",
				Remediation:  "Switch DynamoDB table billing mode to PAY_PER_REQUEST (On-Demand).",
				Metrics:      metrics,
			}))
		}
	}
	return results, nil
}
