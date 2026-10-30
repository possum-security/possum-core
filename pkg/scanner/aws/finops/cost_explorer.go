package finops

import (
	"context"
	"strconv"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// CostExplorerClient defines the Cost Explorer API subset needed by CostExplorerScanner.
type CostExplorerClient interface {
	GetCostAndUsage(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
	GetAnomalies(ctx context.Context, params *costexplorer.GetAnomaliesInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetAnomaliesOutput, error)
}

// CostExplorerScanner fetches the AWS bill grouped by service over a given time window.
type CostExplorerScanner struct {
	client CostExplorerClient
	days   int
}

// Ensure CostExplorerScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*CostExplorerScanner)(nil)

func NewCostExplorerScanner(cfg aws.Config, days int) *CostExplorerScanner {
	if days <= 0 {
		days = 30
	}
	return &CostExplorerScanner{
		client: costexplorer.NewFromConfig(cfg),
		days:   days,
	}
}

// NewCostExplorerScannerWithClient allows injecting a custom or mock Cost Explorer client.
func NewCostExplorerScannerWithClient(ceClient CostExplorerClient, region ...string) *CostExplorerScanner {
	return &CostExplorerScanner{
		client: ceClient,
		days:   30,
	}
}

// NewCostExplorerScannerWithClientAndDays allows injecting a custom or mock Cost Explorer client with days specified.
func NewCostExplorerScannerWithClientAndDays(ceClient CostExplorerClient, days int, region ...string) *CostExplorerScanner {
	if days <= 0 {
		days = 30
	}
	return &CostExplorerScanner{
		client: ceClient,
		days:   days,
	}
}

func (s *CostExplorerScanner) Name() string {
	return "CostExplorer-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *CostExplorerScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "costexplorer-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeGlobal,
		ExecutionCost: scanner.CostMedium,
		Service:       "costexplorer",
		CheckIDs:      []string{RuleCostExplorerSpendTracked},
	}
}

func (s *CostExplorerScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	now := time.Now().UTC()
	endDate := now
	startDate := now.AddDate(0, 0, -s.days)

	startStr := startDate.Format("2006-01-02")
	endStr := endDate.Format("2006-01-02")

	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &types.DateInterval{
			Start: aws.String(startStr),
			End:   aws.String(endStr),
		},
		Granularity: types.GranularityDaily,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []types.GroupDefinition{
			{
				Type: types.GroupDefinitionTypeDimension,
				Key:  aws.String("SERVICE"),
			},
		},
	}

	for {
		output, err := s.client.GetCostAndUsage(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, resultByTime := range output.ResultsByTime {
			if limit > 0 && processedCount >= limit {
				break
			}

			dateStr := aws.ToString(resultByTime.TimePeriod.Start)

			for _, group := range resultByTime.Groups {
				if limit > 0 && processedCount >= limit {
					break
				}
				if len(group.Keys) == 0 {
					continue
				}
				processedCount++

				serviceName := group.Keys[0]
				costAmount := aws.ToString(group.Metrics["UnblendedCost"].Amount)
				costVal, _ := strconv.ParseFloat(costAmount, 64)

				metrics := map[string]interface{}{
					"Date":                 dateStr,
					"UnblendedCost":        costAmount,
					"EstimatedMonthlyCost": costVal,
					"Currency":             aws.ToString(group.Metrics["UnblendedCost"].Unit),
				}

				results = append(results, BuildFinOpsResult(FinOpsResultParams{
					ResourceID:   serviceName,
					ResourceType: "BILLING",
					Region:       "global",
					RuleID:       RuleCostExplorerSpendTracked,
					DisplayName:  serviceName,
					IsOrphaned:   false,
					Cost:         0.0,
					Title:        "AWS Daily Spend Tracking",
					Description:  "Daily unblended service spend recorded via Cost Explorer.",
					Metrics:      metrics,
				}))
			}
		}

		if output.NextPageToken == nil {
			break
		}
		input.NextPageToken = output.NextPageToken
	}

	return results, nil
}
