package finops

import (
	"context"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EIPScanner checks for Elastic IPs that are allocated but not associated with any instance.
type EIPScanner struct {
	client *ec2.Client
}

func NewEIPScanner(cfg aws.Config) *EIPScanner {
	return &EIPScanner{
		client: ec2.NewFromConfig(cfg),
	}
}

func (s *EIPScanner) Name() string {
	return "EIP-Scanner"
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

		metrics := map[string]interface{}{
			"PublicIp": aws.ToString(address.PublicIp),
		}

		if isOrphaned {
			metrics["EstimatedMonthlyCost"] = 3.65 // ~$0.005/hr
			metrics["Recommendation"] = "Release Unattached Elastic IP"
		}

		results = append(results, scanner.ScanResult{
			ResourceID:   aws.ToString(address.AllocationId),
			ResourceType: "EIP",
			Region:       aws.ToString(address.NetworkBorderGroup),
			IsOrphaned:   isOrphaned,
			Metrics:      metrics,
		})
	}

	return results, nil
}
