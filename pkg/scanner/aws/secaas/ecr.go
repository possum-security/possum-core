package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// ECRClient defines the interface for Amazon ECR operations.
type ECRClient interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
	GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
}

// ECRSecScanner evaluates container registry security postures.
type ECRSecScanner struct {
	client ECRClient
	region string
}

// NewECRSecScanner creates an ECRSecScanner with AWS config.
func NewECRSecScanner(cfg aws.Config) *ECRSecScanner {
	return &ECRSecScanner{
		client: ecr.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewECRSecScannerWithClient creates an ECRSecScanner with custom/mock client.
func NewECRSecScannerWithClient(client ECRClient, region string) *ECRSecScanner {
	return &ECRSecScanner{
		client: client,
		region: region,
	}
}

func (s *ECRSecScanner) Name() string {
	return "ECR-SecaaS-Scanner"
}

func (s *ECRSecScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := ecr.NewDescribeRepositoriesPaginator(s.client, &ecr.DescribeRepositoriesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe ECR repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			repoName := aws.ToString(repo.RepositoryName)
			repoArn := aws.ToString(repo.RepositoryArn)

			// 1. Scan on push (ecr_repositories_scan_images_on_push_enabled - MEDIUM)
			scanOnPush := repo.ImageScanningConfiguration != nil && repo.ImageScanningConfiguration.ScanOnPush
			if scanOnPush {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecr_repositories_scan_images_on_push_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s has scan on push enabled.", repoName),
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecr_repositories_scan_images_on_push_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s does not have scan on push enabled.", repoName),
						"SecurityIssues": []string{"Image scanning on push is disabled"},
						"Recommendation": "Enable scan on push for the ECR repository to detect vulnerabilities early.",
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			}

			// 2. Tag Immutability (ecr_repositories_tag_immutability - MEDIUM)
			isImmutable := repo.ImageTagMutability == ecrtypes.ImageTagMutabilityImmutable
			if isImmutable {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecr_repositories_tag_immutability",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s enforces tag immutability.", repoName),
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecr_repositories_tag_immutability",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s allows mutable tags.", repoName),
						"SecurityIssues": []string{"Image tags are mutable, permitting overwrite attacks"},
						"Recommendation": "Set ImageTagMutability to IMMUTABLE to prevent overwriting deployed image tags.",
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			}

			// 3. Public Exposure via Repository Policy (ecr_repositories_not_publicly_accessible - CRITICAL)
			isPublic := false
			policyOut, err := s.client.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
				RepositoryName: aws.String(repoName),
			})
			if err == nil && policyOut.PolicyText != nil {
				pText := aws.ToString(policyOut.PolicyText)
				// Basic check for wildcard principal in allow policy
				if strings.Contains(pText, "\"Principal\":\"*\"") || strings.Contains(pText, "\"Principal\": \"*\"") ||
					strings.Contains(pText, "\"AWS\":\"*\"") || strings.Contains(pText, "\"AWS\": \"*\"") {
					isPublic = true
				}
			}

			if isPublic {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecr_repositories_not_publicly_accessible",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s policy allows public/anonymous access.", repoName),
						"SecurityIssues": []string{"Repository policy allows public access (*)"},
						"Recommendation": "Restrict repository access policy to authorized AWS accounts and IAM principals.",
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecr_repositories_not_publicly_accessible",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s is not publicly accessible.", repoName),
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			}

			// 4. Lifecycle Policy (ecr_repositories_lifecycle_policy_enabled - MEDIUM)
			hasLifecycle := false
			lifecycleOut, err := s.client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
				RepositoryName: aws.String(repoName),
			})
			if err == nil && lifecycleOut.LifecyclePolicyText != nil && aws.ToString(lifecycleOut.LifecyclePolicyText) != "" {
				hasLifecycle = true
			}

			if hasLifecycle {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecr_repositories_lifecycle_policy_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s has an active lifecycle policy.", repoName),
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   repoName,
					ResourceType: "SecaaS-ECRRepository",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecr_repositories_lifecycle_policy_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"RepositoryName": repoName,
						"StatusExtended": fmt.Sprintf("ECR repository %s does not have a lifecycle policy configured.", repoName),
						"SecurityIssues": []string{"Missing lifecycle policy to clean up untagged or expired images"},
						"Recommendation": "Configure an ECR lifecycle policy to automatically expire old images.",
					},
					Nodes: []graph.Node{{ID: repoArn, NodeType: "SecaaS-ECRRepository"}},
				})
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *ECRSecScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "ecr-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "ecr",
		CheckIDs:      []string{"ecr_repositories_lifecycle_policy_enabled", "ecr_repositories_not_publicly_accessible", "ecr_repositories_scan_images_on_push_enabled", "ecr_repositories_tag_immutability"},
	}
}
