package finops

import (
	"context"
	"fmt"
	"strings"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// ELBDescribeAPI defines the ELBv2 API subset needed by ELBScanner.
type ELBDescribeAPI interface {
	elbv2.DescribeLoadBalancersAPIClient
}

// ELBClient is an alias for ELBDescribeAPI.
type ELBClient = ELBDescribeAPI

// ELBScanner checks for idle Application/Network Load Balancers that process zero traffic.
type ELBScanner struct {
	elbClient ELBDescribeAPI
	cwClient  CloudWatchMetricAPI
	region    string
}

// Ensure ELBScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*ELBScanner)(nil)

func NewELBScanner(cfg aws.Config) *ELBScanner {
	return &ELBScanner{
		elbClient: elbv2.NewFromConfig(cfg),
		cwClient:  cloudwatch.NewFromConfig(cfg),
		region:    cfg.Region,
	}
}

func NewELBScannerWithClients(elbClient ELBDescribeAPI, cwClient CloudWatchMetricAPI, region ...string) *ELBScanner {
	r := ""
	if len(region) > 0 {
		r = region[0]
	}
	return &ELBScanner{
		elbClient: elbClient,
		cwClient:  cwClient,
		region:    r,
	}
}

func (s *ELBScanner) Name() string {
	return "ELB-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *ELBScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "elb-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "elb",
		CheckIDs:      []string{RuleELBLoadBalancerIdle},
	}
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
			lbType := string(lb.Type)
			lbArn := aws.ToString(lb.LoadBalancerArn)

			monthlyCost := 16.42 // Base monthly cost for ALB/NLB in us-east-1

			metrics := map[string]interface{}{
				"Type":                 lbType,
				"Scheme":               string(lb.Scheme),
				"VpcId":                aws.ToString(lb.VpcId),
				"EstimatedMonthlyCost": monthlyCost,
			}

			arnParts := strings.Split(lbArn, "/")
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

					if err != nil {
						metrics["MetricFetchError"] = err.Error()
					} else {
						metrics["Requests_30Days"] = reqCount
						if !isResourceTooYoung(lb.CreatedTime) && reqCount == 0 {
							isOrphaned = true
							recommendation = fmt.Sprintf("Delete Idle %s Load Balancer — estimated waste: $%.2f/month", strings.ToUpper(lbType), monthlyCost)
						}
					}
				}
			}

			if isOrphaned {
				metrics["Recommendation"] = recommendation
			}

			costWaste := 0.0
			if isOrphaned {
				costWaste = monthlyCost
			}

			resID := lbArn
			if resID == "" {
				resID = lbName
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   resID,
				ResourceType: "ELB",
				Region:       resolveRegion(s.region, "regional"),
				RuleID:       RuleELBLoadBalancerIdle,
				DisplayName:  lbName,
				IsOrphaned:   isOrphaned,
				Cost:         costWaste,
				Title:        "Idle Elastic Load Balancer (ELB)",
				Description:  fmt.Sprintf("Load balancer %s received 0 requests/flows over the past 30 days.", lbName),
				Remediation:  "Delete unused load balancer via aws elbv2 delete-load-balancer",
				Metrics:      metrics,
			}))
		}
	}

	return results, nil
}
