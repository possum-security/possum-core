package finops

import (
	"context"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type ENIScanner struct {
	ec2Client *ec2.Client
}

func NewENIScanner(cfg aws.Config) *ENIScanner {
	return &ENIScanner{
		ec2Client: ec2.NewFromConfig(cfg),
	}
}

func (s *ENIScanner) Name() string {
	return "ENI-FinOps-Scanner"
}

func (s *ENIScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(s.ec2Client, &ec2.DescribeNetworkInterfacesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, eni := range page.NetworkInterfaces {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			eniID := aws.ToString(eni.NetworkInterfaceId)

			isOrphaned := false
			if eni.Status == types.NetworkInterfaceStatusAvailable {
				isOrphaned = true
			}

			metrics := map[string]interface{}{
				"NetworkInterfaceId":   eniID,
				"Status":               string(eni.Status),
				"EstimatedMonthlyCost": 0.0,
			}

			if isOrphaned {
				metrics["Recommendation"] = "Delete detached Elastic Network Interface"
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   eniID,
				ResourceType: "ENI",
				Region:       "regional",
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
		}
	}
	return results, nil
}
