package secaas

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoDBScanner struct {
	ddbClient *dynamodb.Client
}

func NewDynamoDBScanner(cfg aws.Config) *DynamoDBScanner {
	return &DynamoDBScanner{
		ddbClient: dynamodb.NewFromConfig(cfg),
	}
}

func (s *DynamoDBScanner) Name() string {
	return "DynamoDB-SecaaS-Scanner"
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

			pitrInput := &dynamodb.DescribeContinuousBackupsInput{
				TableName: aws.String(tableName),
			}
			pitrOutput, err := s.ddbClient.DescribeContinuousBackups(ctx, pitrInput)
			if err != nil {
				return nil, err
			}

			missingPitr := true
			if pitrOutput.ContinuousBackupsDescription != nil && pitrOutput.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
				status := pitrOutput.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus
				if status == types.PointInTimeRecoveryStatusEnabled {
					missingPitr = false
				}
			}

			if missingPitr {
				metrics := map[string]interface{}{
					"TableName":      tableName,
					"StatusExtended": fmt.Sprintf("DynamoDB table %s does not have Point-in-Time Recovery (PITR) enabled.", tableName),
					"SecurityIssues": []string{"Point-in-Time Recovery (PITR) continuous backups are disabled"},
					"SecurityIssue":  "Missing Point-in-Time Recovery (PITR) backups",
					"Recommendation": "Enable Point-in-Time Recovery (PITR) for DynamoDB tables to prevent permanent data loss.",
				}
				results = append(results, scanner.ScanResult{
					ResourceID:   tableName,
					ResourceType: "SecaaS-DynamoDB",
					Region:       "regional",
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "dynamodb_tables_pitr_enabled",
					Severity:     "MEDIUM",
					Metrics:      metrics,
					Nodes: []graph.Node{
						{
							ID:       tableName,
							NodeType: "SecaaS-DynamoDB",
						},
					},
				})
			}
		}
	}
	return results, nil
}
