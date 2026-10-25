package finops

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

type LambdaScanner struct {
	lambdaClient *lambda.Client
	cwClient     *cloudwatch.Client
}

func NewLambdaScanner(cfg aws.Config) *LambdaScanner {
	return &LambdaScanner{
		lambdaClient: lambda.NewFromConfig(cfg),
		cwClient:     cloudwatch.NewFromConfig(cfg),
	}
}

func (s *LambdaScanner) Name() string {
	return "Lambda-FinOps-Scanner"
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
				// Check 2: Scale up due to throttling
				issueType = "Scale Up (Throttled)"
				recommendation = fmt.Sprintf("Scale Up Lambda Concurrency — Function experienced %.0f throttle events in 30 days. Increase reserved concurrency or request an account concurrency increase.", throttles)
			} else if maxDurationMs >= 0.75*timeoutMs || (avgDurationMs > 0 && avgDurationMs >= 0.75*timeoutMs) {
				// Check 3: Scale up memory/CPU due to runtime approaching timeout (>75%)
				issueType = "Scale Up (High Duration/Memory)"
				recommendation = fmt.Sprintf("Scale Up Lambda Memory — Function runtime (Max: %.0fms) exceeds 75%% of configured timeout (%ds). Allocating more memory scales CPU proportionally, reducing duration and eliminating timeout risks.", maxDurationMs, timeoutSec)
			} else if allocatedMemory >= 1024 && avgDurationMs < 200 {
				// Check 4: Over-provisioned memory
				issueType = "Over-Provisioned Memory"
				recommendation = fmt.Sprintf("Downsize Lambda Memory — Function has %dMB allocated but executes in only %.0fms. Reducing memory allocation will save costs.", allocatedMemory, avgDurationMs)
			}

			if recommendation != "" {
				metrics["Recommendation"] = recommendation
			}
			metrics["IssueType"] = issueType

			results = append(results, scanner.ScanResult{
				ResourceID:   fnName,
				ResourceType: "Lambda",
				Region:       "regional",
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
		}
	}
	return results, nil
}
