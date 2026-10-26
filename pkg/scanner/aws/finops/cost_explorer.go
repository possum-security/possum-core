package finops

import (
	"context"
	"time"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// CostExplorerScanner fetches the AWS bill grouped by service over a given time window.
type CostExplorerScanner struct {
	client *costexplorer.Client
	days   int
}

func NewCostExplorerScanner(cfg aws.Config, days int) *CostExplorerScanner {
	if days <= 0 {
		days = 30
	}
	return &CostExplorerScanner{
		client: costexplorer.NewFromConfig(cfg),
		days:   days,
	}
}

func (s *CostExplorerScanner) Name() string {
	return "CostExplorer-Scanner"
}

func (s *CostExplorerScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	now := time.Now().UTC()
	// Cost explorer requires the end date to be exclusive.
	// E.g. to get yesterday's full data, End should be today (now) and Start should be yesterday.
	// But because we want a sliding window of `s.days`, we go back `s.days`.
	// For days=30: start is 30 days ago, end is today.
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
			processedCount++

			dateStr := aws.ToString(resultByTime.TimePeriod.Start)

			for _, group := range resultByTime.Groups {
				if len(group.Keys) == 0 {
					continue
				}

				serviceName := group.Keys[0]
				costAmount := aws.ToString(group.Metrics["UnblendedCost"].Amount)

				results = append(results, scanner.ScanResult{
					ResourceID:   serviceName,
					ResourceType: "BILLING",
					Region:       "global",
					IsOrphaned:   false,
					Metrics: map[string]interface{}{
						"Date":          dateStr,
						"UnblendedCost": costAmount,
						"Currency":      aws.ToString(group.Metrics["UnblendedCost"].Unit),
					},
				})
			}
		}

		if output.NextPageToken == nil {
			break
		}
		input.NextPageToken = output.NextPageToken
	}

	return results, nil
}
