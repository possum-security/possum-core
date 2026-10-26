package finops

import (
	"context"
	"fmt"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

type ELBScanner struct {
	elbClient *elbv2.Client
	cwClient  *cloudwatch.Client
}

func NewELBScanner(cfg aws.Config) *ELBScanner {
	return &ELBScanner{
		elbClient: elbv2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
	}
}

func (s *ELBScanner) Name() string {
	return "ELB-Scanner"
}

func (s *ELBScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := elbv2.NewDescribeLoadBalancersPaginator(s.elbClient, &elbv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lb := range page.LoadBalancers {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			lbName := aws.ToString(lb.LoadBalancerName)
			lbType := string(lb.Type) // "application", "network", or "gateway"

			// Base monthly cost for an ALB/NLB in us-east-1 is roughly $16.42
			monthlyCost := 16.42

			metrics := map[string]interface{}{
				"Type":                 lbType,
				"Scheme":               string(lb.Scheme),
				"VpcId":                aws.ToString(lb.VpcId),
				"EstimatedMonthlyCost": monthlyCost,
			}

			// We need the LoadBalancer dimension which looks like: app/my-load-balancer/50dc6c495c0c9188
			// We can parse it from the ARN
			arnParts := strings.Split(aws.ToString(lb.LoadBalancerArn), "/")
			var cwDimensionValue string
			if len(arnParts) >= 4 {
				cwDimensionValue = strings.Join(arnParts[1:], "/")
			}

			isOrphaned := false
			recommendation := ""

			if cwDimensionValue != "" {
				namespace := "AWS/ApplicationELB"
				metricName := "RequestCount"

				if lbType == "network" {
					namespace = "AWS/NetworkELB"
					metricName = "ActiveFlowCount"
				}

				if lbType == "application" || lbType == "network" {
					reqCount, err := FetchCloudWatchMetric(
						ctx,
						s.cwClient,
						namespace,
						metricName,
						"LoadBalancer",
						cwDimensionValue,
						cwtypes.StatisticSum,
					)

					if err == nil {
						metrics["Requests_30Days"] = reqCount

						// If zero traffic over 30 days, it is completely idle
						if reqCount == 0 {
							isOrphaned = true
							recommendation = fmt.Sprintf("Delete Idle %s Load Balancer — estimated waste: $%.2f/month", strings.ToUpper(lbType), monthlyCost)
						}
					}
				}
			}

			if isOrphaned {
				metrics["Recommendation"] = recommendation
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   lbName,
				ResourceType: "ELB",
				Region:       "regional",
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
		}
	}

	return results, nil
}
