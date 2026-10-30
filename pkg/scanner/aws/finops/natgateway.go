package finops

import (
	"context"
	"fmt"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// NATGatewayDescribeAPI defines the EC2 API subset needed by NATGatewayScanner.
type NATGatewayDescribeAPI interface {
	ec2.DescribeNatGatewaysAPIClient
}

// NATGatewayScanner checks for idle NAT Gateways that are wasting money.
type NATGatewayScanner struct {
	ec2Client NATGatewayDescribeAPI
	cwClient  CloudWatchMetricAPI
	region    string
}

// Ensure NATGatewayScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*NATGatewayScanner)(nil)

func NewNATGatewayScanner(cfg aws.Config) *NATGatewayScanner {
	return &NATGatewayScanner{
		ec2Client: ec2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    cfg.Region,
	}
}

func NewNATGatewayScannerWithClients(ec2Client NATGatewayDescribeAPI, cwClient CloudWatchMetricAPI, region ...string) *NATGatewayScanner {
	r := ""
	if len(region) > 0 {
		r = region[0]
	}
	return &NATGatewayScanner{
		ec2Client: ec2Client,
		cwClient:  cwClient,
		region:    r,
	}
}

func (s *NATGatewayScanner) Name() string {
	return "NAT-Gateway-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *NATGatewayScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "natgateway-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "ec2",
		CheckIDs:      []string{RuleNATGatewayIdle},
	}
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
			monthlyCost := 32.85 // Base NAT Gateway cost ~$0.045/hr

			metrics := map[string]interface{}{
				"VpcId":                aws.ToString(nat.VpcId),
				"SubnetId":             aws.ToString(nat.SubnetId),
				"State":                string(nat.State),
				"EstimatedMonthlyCost": monthlyCost,
			}

			bytesOut, err := FetchCloudWatchMetric(
				ctx,
				s.cwClient,
				"AWS/NATGateway",
				"BytesOutToDestination",
				"NatGatewayId",
				natID,
				cwtypes.StatisticSum,
			)

			isIdle := false
			if err != nil {
				metrics["MetricFetchError"] = err.Error()
			} else {
				metrics["BytesOut_30Days"] = bytesOut
				// FinOps check: If a NAT Gateway processes less than 10MB in a month, it's virtually idle.
				if !isResourceTooYoung(nat.CreateTime) && bytesOut < 10485760 {
					isIdle = true
					metrics["Recommendation"] = fmt.Sprintf("Delete Idle NAT Gateway — estimated waste: $%.2f/month", monthlyCost)
				}
			}

			costWaste := 0.0
			if isIdle {
				costWaste = monthlyCost
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   natID,
				ResourceType: "NAT_GATEWAY",
				Region:       resolveRegion(s.region, "regional"),
				RuleID:       RuleNATGatewayIdle,
				DisplayName:  natID,
				IsOrphaned:   isIdle,
				Cost:         costWaste,
				Title:        "Idle NAT Gateway Incurring Monthly Charges",
				Description:  "NAT Gateway processed under 10MB of network traffic over the last 30 days.",
				Remediation:  "Delete unused NAT Gateway via aws ec2 delete-nat-gateway",
				Metrics:      metrics,
			}))
		}
	}

	return results, nil
}
