package finops

import (
	"context"
	"fmt"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// CloudFormationClient defines the CloudFormation API subset needed by CloudFormationScanner.
type CloudFormationClient interface {
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	ListStacks(ctx context.Context, params *cloudformation.ListStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.ListStacksOutput, error)
}

// CloudFormationScanner detects orphaned, failed, and abandoned CloudFormation stacks.
type CloudFormationScanner struct {
	client CloudFormationClient
	region string
}

// Ensure CloudFormationScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*CloudFormationScanner)(nil)

func NewCloudFormationScanner(cfg aws.Config) *CloudFormationScanner {
	return &CloudFormationScanner{
		client: cloudformation.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewCloudFormationScannerWithClient allows injecting a custom or mock CloudFormation client.
func NewCloudFormationScannerWithClient(cfnClient CloudFormationClient, region ...string) *CloudFormationScanner {
	r := ""
	if len(region) > 0 {
		r = region[0]
	}
	return &CloudFormationScanner{
		client: cfnClient,
		region: r,
	}
}

func (s *CloudFormationScanner) Name() string {
	return "CloudFormation-FinOps-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *CloudFormationScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "cloudformation-finops-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostLight,
		Service:       "cloudformation",
		CheckIDs:      []string{RuleCloudFormationStackFailedOrAbandoned},
	}
}

func (s *CloudFormationScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := cloudformation.NewDescribeStacksPaginator(s.client, &cloudformation.DescribeStacksInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, stack := range page.Stacks {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			stackID := aws.ToString(stack.StackId)
			stackName := aws.ToString(stack.StackName)
			status := stack.StackStatus
			statusReason := aws.ToString(stack.StackStatusReason)
			creationTime := stack.CreationTime
			lastUpdatedTime := stack.LastUpdatedTime

			isOrphaned := false
			var recommendation string
			issueType := "Active Stack"

			switch status {
			case types.StackStatusRollbackComplete,
				types.StackStatusRollbackFailed,
				types.StackStatusCreateFailed,
				types.StackStatusDeleteFailed,
				types.StackStatusUpdateRollbackFailed,
				types.StackStatusUpdateRollbackComplete,
				types.StackStatusImportRollbackFailed,
				types.StackStatusImportRollbackComplete:
				isOrphaned = true
				issueType = "Failed/Rollback State"
				recommendation = fmt.Sprintf("Delete orphaned CloudFormation stack in %s state to release resource locks.", status)

			default:
				lastActivity := creationTime
				if lastUpdatedTime != nil && lastUpdatedTime.After(*creationTime) {
					lastActivity = lastUpdatedTime
				}

				if lastActivity != nil && time.Since(*lastActivity) > 180*24*time.Hour {
					daysOld := int(time.Since(*lastActivity).Hours() / 24)
					isEphemeral := false
					for _, tag := range stack.Tags {
						k := aws.ToString(tag.Key)
						v := aws.ToString(tag.Value)
						if (k == "Environment" || k == "env") && (v == "test" || v == "dev" || v == "preview" || v == "staging") {
							isEphemeral = true
							break
						}
					}

					if isEphemeral {
						isOrphaned = true
						issueType = "Abandoned Ephemeral Stack"
						recommendation = fmt.Sprintf("Review and delete stagnant ephemeral stack (inactive for %d days).", daysOld)
					} else {
						issueType = "Stale Stack (>180d)"
						recommendation = fmt.Sprintf("Audit stale CloudFormation stack (last updated %d days ago) for active usage.", daysOld)
					}
				}
			}

			metrics := map[string]interface{}{
				"StackName":            stackName,
				"Status":               string(status),
				"EstimatedMonthlyCost": 0.0,
				"IssueType":            issueType,
			}
			if statusReason != "" {
				metrics["StatusReason"] = statusReason
			}
			if creationTime != nil {
				metrics["CreationDate"] = creationTime.Format("2006-01-02")
			}
			if lastUpdatedTime != nil {
				metrics["LastUpdated"] = lastUpdatedTime.Format("2006-01-02")
			}
			if recommendation != "" {
				metrics["Recommendation"] = recommendation
			}

			resID := stackID
			if resID == "" {
				resID = stackName
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   resID,
				ResourceType: "CloudFormation",
				Region:       resolveRegion(s.region, "regional"),
				RuleID:       RuleCloudFormationStackFailedOrAbandoned,
				DisplayName:  stackName,
				IsOrphaned:   isOrphaned,
				Cost:         0.0,
				Severity:     model.SeverityLow,
				Title:        "Failed or Abandoned CloudFormation Stack",
				Description:  fmt.Sprintf("CloudFormation stack %s is in status %s (%s).", stackName, status, issueType),
				Remediation:  "Delete failed stack via aws cloudformation delete-stack",
				Metrics:      metrics,
				Nodes: []model.Node{
					{
						ID:       resID,
						NodeType: "CloudFormation",
						Data: map[string]interface{}{
							"name":       stackName,
							"status":     string(status),
							"isOrphaned": isOrphaned,
						},
					},
				},
			}))
		}
	}

	return results, nil
}
