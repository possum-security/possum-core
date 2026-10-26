package finops

import (
	"context"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

type CloudFrontScanner struct {
	cfClient *cloudfront.Client
	cwClient *cloudwatch.Client
}

func NewCloudFrontScanner(cfg aws.Config) *CloudFrontScanner {
	return &CloudFrontScanner{
		cfClient: cloudfront.NewFromConfig(cfg),
		cwClient: cloudwatch.NewFromConfig(cfg),
	}
}

func (s *CloudFrontScanner) Name() string {
	return "CloudFront-FinOps-Scanner"
}

func (s *CloudFrontScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	paginator := cloudfront.NewListDistributionsPaginator(s.cfClient, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if page.DistributionList == nil {
			continue
		}

		for _, dist := range page.DistributionList.Items {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			distID := aws.ToString(dist.Id)

			reqs, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/CloudFront", "Requests", "DistributionId", distID, cwtypes.StatisticSum)
			bytesDownloaded, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/CloudFront", "BytesDownloaded", "DistributionId", distID, cwtypes.StatisticSum)

			isOrphaned := false
			if reqs == 0 {
				isOrphaned = true
			}

			dataCost := (bytesDownloaded / (1024.0 * 1024.0 * 1024.0)) * 0.085
			reqCost := (reqs / 10000.0) * 0.01
			monthlyCost := dataCost + reqCost

			metrics := map[string]interface{}{
				"DistributionId":       distID,
				"EstimatedMonthlyCost": monthlyCost,
				"Requests_30Days":      reqs,
			}

			if isOrphaned {
				metrics["Recommendation"] = "Disable or delete unused CloudFront distribution"
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   distID,
				ResourceType: "CloudFront",
				Region:       "global",
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
		}
	}
	return results, nil
}
