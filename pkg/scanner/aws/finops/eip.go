package finops

import (
	"context"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EIPScanner checks for Elastic IPs that are allocated but not associated with any instance.
type EIPScanner struct {
	client *ec2.Client
}

// Ensure EIPScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*EIPScanner)(nil)

func NewEIPScanner(cfg aws.Config) *EIPScanner {
	return &EIPScanner{
		client: ec2.NewFromConfig(cfg),
	}
}

func (s *EIPScanner) Name() string {
	return "EIP-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *EIPScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "eip-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostLight,
		Service:       "ec2",
		CheckIDs:      []string{RuleEIPUnassigned},
	}
}

func (s *EIPScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// Describe all EIPs
	output, err := s.client.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}

	for _, address := range output.Addresses {
		if limit > 0 && processedCount >= limit {
			break
		}
		processedCount++

		isOrphaned := address.AssociationId == nil
		publicIP := aws.ToString(address.PublicIp)
		allocID := aws.ToString(address.AllocationId)
		if allocID == "" {
			allocID = publicIP
		}

		cost := 0.0
		metrics := map[string]interface{}{
			"PublicIp": publicIP,
		}

		if isOrphaned {
			cost = 3.65 // ~$0.005/hr
			metrics["EstimatedMonthlyCost"] = cost
			metrics["Recommendation"] = "Release Unattached Elastic IP"
		}

		results = append(results, BuildFinOpsResult(FinOpsResultParams{
			ResourceID:   allocID,
			ResourceType: "EIP",
			Region:       "global",
			RuleID:       RuleEIPUnassigned,
			DisplayName:  publicIP,
			IsOrphaned:   isOrphaned,
			Cost:         cost,
			Title:        "Unassigned Elastic IP Address",
			Description:  "Elastic IP is allocated but not associated with any running EC2 instance or ENI.",
			Remediation:  "Release the unattached Elastic IP via aws ec2 release-address",
			Metrics:      metrics,
		}))
	}

	return results, nil
}
