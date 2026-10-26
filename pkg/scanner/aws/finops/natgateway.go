package finops

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// NATGatewayScanner checks for idle NAT Gateways that are wasting money.
type NATGatewayScanner struct {
	ec2Client *ec2.Client
	cwClient  *cloudwatch.Client
}

func NewNATGatewayScanner(cfg aws.Config) *NATGatewayScanner {
	return &NATGatewayScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *NATGatewayScanner) Name() string {
	return "NAT-Gateway-Scanner"
}

func (s *NATGatewayScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := ec2.NewDescribeNatGatewaysPaginator(s.ec2Client, &ec2.DescribeNatGatewaysInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, nat := range page.NatGateways {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			if nat.State != types.NatGatewayStateAvailable {
				continue
			}

			natID := aws.ToString(nat.NatGatewayId)

			// Base NAT Gateway cost is ~$0.045/hr -> ~$32.85/month
			monthlyCost := 32.85

			metrics := map[string]interface{}{
				"VpcId":                aws.ToString(nat.VpcId),
				"SubnetId":             aws.ToString(nat.SubnetId),
				"State":                string(nat.State),
				"EstimatedMonthlyCost": monthlyCost,
			}

			// NAT Gateways publish metrics under AWS/NATGateway namespace
			bytesOut, err := FetchCloudWatchMetric(
				ctx,
				s.cwClient,
				"AWS/NATGateway",
				"BytesOutToDestination",
				"NatGatewayId",
				natID,
				cwtypes.StatisticSum,
			)

			if err == nil {
				metrics["BytesOut_30Days"] = bytesOut
			}

			isIdle := false
			// FinOps check: If a NAT Gateway processes less than 10MB in a month, it's virtually idle.
			// 10MB = 10 * 1024 * 1024 = 10,485,760 bytes
			if err == nil && bytesOut < 10485760 {
				isIdle = true
				metrics["Recommendation"] = fmt.Sprintf("Delete Idle NAT Gateway — estimated waste: $%.2f/month", monthlyCost)
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   natID,
				ResourceType: "NAT_GATEWAY",
				Region:       "regional", // Subnets/NATs are tied to AZs but described regionally
				IsOrphaned:   isIdle,
				Metrics:      metrics,
			})
		}
	}

	return results, nil
}
