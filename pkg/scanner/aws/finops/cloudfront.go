package finops

import (
	"context"
	"fmt"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
)

// CloudFrontListAPI defines the CloudFront API subset needed by CloudFrontScanner.
type CloudFrontListAPI interface {
	cloudfront.ListDistributionsAPIClient
}

type CloudFrontScanner struct {
	cfClient CloudFrontListAPI
	cwClient CloudWatchMetricAPI
}

// Ensure CloudFrontScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*CloudFrontScanner)(nil)

func NewCloudFrontScanner(cfg aws.Config) *CloudFrontScanner {
	cwCfg := cfg.Copy()
	cwCfg.Region = "us-east-1"
	return &CloudFrontScanner{
		cfClient: cloudfront.NewFromConfig(cfg),
		cwClient: cloudwatch.NewFromConfig(cwCfg),
	}
}

func NewCloudFrontScannerWithClients(cfClient CloudFrontListAPI, cwClient CloudWatchMetricAPI) *CloudFrontScanner {
	return &CloudFrontScanner{
		cfClient: cfClient,
		cwClient: cwClient,
	}
}

func (s *CloudFrontScanner) Name() string {
	return "CloudFront-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *CloudFrontScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "cloudfront-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeGlobal,
		ExecutionCost: scanner.CostMedium,
		Service:       "cloudfront",
		CheckIDs:      []string{RuleCloudFrontDistributionUnused},
	}
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
			domainName := aws.ToString(dist.DomainName)

			cfDimensions := []cwtypes.Dimension{
				{
					Name:  aws.String("DistributionId"),
					Value: aws.String(distID),
				},
				{
					Name:  aws.String("Region"),
					Value: aws.String("Global"),
				},
			}

			reqs, reqErr := FetchCloudWatchMetricWithDimensions(ctx, s.cwClient, "AWS/CloudFront", "Requests", cfDimensions, cwtypes.StatisticSum)
			bytesDownloaded, bytesErr := FetchCloudWatchMetricWithDimensions(ctx, s.cwClient, "AWS/CloudFront", "BytesDownloaded", cfDimensions, cwtypes.StatisticSum)

			isOrphaned := false
			monthlyCost := 0.0

			metrics := map[string]interface{}{
				"DistributionId": distID,
				"DomainName":     domainName,
			}

			if metricErr := firstErr(reqErr, bytesErr); metricErr != nil {
				metrics["MetricFetchError"] = metricErr.Error()
			} else {
				dataCost := (bytesDownloaded / (1024.0 * 1024.0 * 1024.0)) * 0.085
				reqCost := (reqs / 10000.0) * 0.01
				monthlyCost = dataCost + reqCost
				metrics["Requests_30Days"] = reqs

				if !isResourceTooYoung(dist.LastModifiedTime) && reqs == 0 {
					isOrphaned = true
				}
			}

			metrics["EstimatedMonthlyCost"] = monthlyCost

			if isOrphaned {
				metrics["Recommendation"] = "Disable or delete unused CloudFront distribution"
			}

			costWaste := 0.0
			if isOrphaned {
				costWaste = monthlyCost
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   distID,
				ResourceType: "CloudFront",
				Region:       "global",
				RuleID:       RuleCloudFrontDistributionUnused,
				DisplayName:  domainName,
				IsOrphaned:   isOrphaned,
				Cost:         costWaste,
				Title:        "Unused CloudFront Distribution",
				Description:  fmt.Sprintf("CloudFront distribution %s (%s) handled zero requests in the last 30 days.", distID, domainName),
				Remediation:  "Disable and delete unused CloudFront distribution via aws cloudfront delete-distribution",
				Metrics:      metrics,
			}))
		}
	}
	return results, nil
}
