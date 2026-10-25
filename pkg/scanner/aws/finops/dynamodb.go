package finops

import (
	"context"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type DynamoDBScanner struct {
	ddbClient *dynamodb.Client
	cwClient  *cloudwatch.Client
}

func NewDynamoDBScanner(cfg aws.Config) *DynamoDBScanner {
	return &DynamoDBScanner{
		ddbClient: dynamodb.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *DynamoDBScanner) Name() string {
	return "DynamoDB-FinOps-Scanner"
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

				if rcu > 0 || wcu > 0 {
					metrics["Recommendation"] = "Consider switching to On-Demand capacity for unpredictable workloads"
				}
			}

			metrics["EstimatedMonthlyCost"] = monthlyCost

			results = append(results, scanner.ScanResult{
				ResourceID:   tableName,
				ResourceType: "DynamoDB",
				Region:       "regional",
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
		}
	}
	return results, nil
}
