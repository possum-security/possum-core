package finops

import (
	"context"
	"fmt"
	"time"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// CloudFormationScanner detects orphaned, failed, and abandoned CloudFormation stacks.
// Although CloudFormation stacks do not incur direct costs, orphaned and failed stacks
// represent stale infrastructure, hold resource locks, and clutter cloud management.
type CloudFormationScanner struct {
	client *cloudformation.Client
}

func NewCloudFormationScanner(cfg aws.Config) *CloudFormationScanner {
	return &CloudFormationScanner{
		client: cloudformation.NewFromConfig(cfg),
	}
}

func (s *CloudFormationScanner) Name() string {
	return "CloudFormation-FinOps-Scanner"
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

			// Check 1: Failed / Rollback States (Zombies / Orphaned Stacks)
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
				recommendation = fmt.Sprintf("Delete orphaned CloudFormation stack in %s state to release resource locks and remove dead infrastructure.", status)

			default:
				// Check 2: Stale / Abandoned Stacks (> 180 days with no updates or test/preview environments)
				lastActivity := creationTime
				if lastUpdatedTime != nil && lastUpdatedTime.After(*creationTime) {
					lastActivity = lastUpdatedTime
				}

				if lastActivity != nil && time.Since(*lastActivity) > 180*24*time.Hour {
					daysOld := int(time.Since(*lastActivity).Hours() / 24)
					// Check if stack is tagged as test/ephemeral/dev
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
						recommendation = fmt.Sprintf("Review and delete stagnant ephemeral stack (inactive for %d days) to clean up unused infrastructure.", daysOld)
					} else {
						issueType = "Stale Stack (>180d)"
						recommendation = fmt.Sprintf("Audit stale CloudFormation stack (last updated %d days ago) for active usage.", daysOld)
					}
				}
			}

			metrics := map[string]interface{}{
				"StackName":            stackName,
				"Status":               string(status),
				"EstimatedMonthlyCost": 0.0, // Stacks don't cost directly
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

			results = append(results, scanner.ScanResult{
				ResourceID:   stackName,
				ResourceType: "CloudFormation",
				Region:       "regional",
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       stackID,
						NodeType: "CloudFormation",
						Data: map[string]interface{}{
							"name":       stackName,
							"status":     string(status),
							"isOrphaned": isOrphaned,
						},
					},
				},
			})
		}
	}

	return results, nil
}
