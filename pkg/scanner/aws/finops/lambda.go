package finops

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

type LambdaScanner struct {
	lambdaClient *lambda.Client
	cwClient     *cloudwatch.Client
}

// Ensure LambdaScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*LambdaScanner)(nil)

func NewLambdaScanner(cfg aws.Config) *LambdaScanner {
	return &LambdaScanner{
		lambdaClient: lambda.NewFromConfig(cfg),
		cwClient:     cloudwatch.NewFromConfig(cfg),
	}
}

func (s *LambdaScanner) Name() string {
	return "Lambda-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *LambdaScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "lambda-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "lambda",
		CheckIDs:      []string{RuleLambdaFunctionUnused},
	}
}

func (s *LambdaScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, fn := range page.Functions {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			fnName := aws.ToString(fn.FunctionName)
			fnArn := aws.ToString(fn.FunctionArn)
			allocatedMemory := aws.ToInt32(fn.MemorySize)
			timeoutSec := int(aws.ToInt32(fn.Timeout))
			if timeoutSec == 0 {
				timeoutSec = 3
			}

			isOrphaned := false
			var recommendation string
			issueType := "Optimized"

			invocations, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/Lambda", "Invocations", "FunctionName", fnName, cwtypes.StatisticSum)
			avgDurationMs, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/Lambda", "Duration", "FunctionName", fnName, cwtypes.StatisticAverage)
			maxDurationMs, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/Lambda", "Duration", "FunctionName", fnName, cwtypes.StatisticMaximum)
			throttles, _ := FetchCloudWatchMetric(ctx, s.cwClient, "AWS/Lambda", "Throttles", "FunctionName", fnName, cwtypes.StatisticSum)

			gbSeconds := (invocations * avgDurationMs / 1000.0) * (float64(allocatedMemory) / 1024.0)
			monthlyCost := (gbSeconds * 0.0000166667) + ((invocations / 1000000.0) * 0.20)

			metrics := map[string]interface{}{
				"FunctionName":         fnName,
				"AllocatedMemoryMB":    allocatedMemory,
				"TimeoutSeconds":       timeoutSec,
				"Invocations_30Days":   invocations,
				"AvgDurationMs":        avgDurationMs,
				"MaxDurationMs":        maxDurationMs,
				"Throttles_30Days":     throttles,
				"EstimatedMonthlyCost": monthlyCost,
			}

			timeoutMs := float64(timeoutSec * 1000)
			// Check 1: Dormant/Zombie function
			if invocations == 0 {
				isOrphaned = true
				issueType = "Dormant Function"
				recommendation = "Delete or archive dormant Lambda function (0 invocations in last 30 days)."
			} else if throttles > 0 {
				issueType = "Scale Up (Throttled)"
				recommendation = fmt.Sprintf("Scale Up Lambda Concurrency — Function experienced %.0f throttle events in 30 days.", throttles)
			} else if maxDurationMs >= 0.75*timeoutMs || (avgDurationMs > 0 && avgDurationMs >= 0.75*timeoutMs) {
				issueType = "Scale Up (High Duration/Memory)"
				recommendation = fmt.Sprintf("Scale Up Lambda Memory — Function runtime (Max: %.0fms) exceeds 75%% of configured timeout (%ds).", maxDurationMs, timeoutSec)
			} else if allocatedMemory >= 1024 && avgDurationMs < 200 {
				issueType = "Over-Provisioned Memory"
				recommendation = fmt.Sprintf("Downsize Lambda Memory — Function has %dMB allocated but executes in only %.0fms.", allocatedMemory, avgDurationMs)
			}

			if recommendation != "" {
				metrics["Recommendation"] = recommendation
			}
			metrics["IssueType"] = issueType

			costWaste := 0.0
			if isOrphaned {
				costWaste = monthlyCost
			}

			resID := fnArn
			if resID == "" {
				resID = fnName
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   resID,
				ResourceType: "Lambda",
				Region:       "regional",
				RuleID:       RuleLambdaFunctionUnused,
				DisplayName:  fnName,
				IsOrphaned:   isOrphaned,
				Cost:         costWaste,
				Title:        "Unused or Dormant Lambda Function",
				Description:  fmt.Sprintf("Lambda function %s recorded zero invocations over the last 30 days.", fnName),
				Remediation:  "Delete unused Lambda function via aws lambda delete-function",
				Metrics:      metrics,
			}))
		}
	}
	return results, nil
}
