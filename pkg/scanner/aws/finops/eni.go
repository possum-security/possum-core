package finops

import (
	"context"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// ENIScanner checks for detached / unattached Elastic Network Interfaces.
type ENIScanner struct {
	ec2Client *ec2.Client
	region    string
}

// Ensure ENIScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*ENIScanner)(nil)

func NewENIScanner(cfg aws.Config) *ENIScanner {
	return &ENIScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		region:    cfg.Region,
	}
}

func (s *ENIScanner) Name() string {
	return "ENI-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *ENIScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "eni-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostLight,
		Service:       "ec2",
		CheckIDs:      []string{RuleENIDetachedUnused},
	}
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
			isOrphaned := eni.Status == types.NetworkInterfaceStatusAvailable

			metrics := map[string]interface{}{
				"NetworkInterfaceId":   eniID,
				"Status":               string(eni.Status),
				"EstimatedMonthlyCost": 0.0,
			}

			if isOrphaned {
				metrics["Recommendation"] = "Delete detached Elastic Network Interface"
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   eniID,
				ResourceType: "ENI",
				Region:       resolveRegion(s.region, "regional"),
				RuleID:       RuleENIDetachedUnused,
				DisplayName:  eniID,
				IsOrphaned:   isOrphaned,
				Cost:         0.0,
				Severity:     model.SeverityLow,
				Title:        "Detached Elastic Network Interface (ENI)",
				Description:  "Network interface is available and unattached to any EC2 instance.",
				Remediation:  "Delete unattached ENI via aws ec2 delete-network-interface",
				Metrics:      metrics,
			}))
		}
	}
	return results, nil
}
