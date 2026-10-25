package secaas

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
)

// CodeBuildApi defines the mockable interface for AWS CodeBuild operations.
type CodeBuildApi interface {
	ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

// CodeBuildScanner evaluates AWS CodeBuild project configurations for security risks.
type CodeBuildScanner struct {
	client CodeBuildApi
	region string
}

// NewCodeBuildScanner creates a CodeBuildScanner with the provided AWS config.
func NewCodeBuildScanner(cfg aws.Config) *CodeBuildScanner {
	return &CodeBuildScanner{
		client: codebuild.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewCodeBuildScannerWithClient creates a CodeBuildScanner with a custom/mock client.
func NewCodeBuildScannerWithClient(client CodeBuildApi, region string) *CodeBuildScanner {
	return &CodeBuildScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *CodeBuildScanner) Name() string {
	return "CodeBuild-SecaaS-Scanner"
}

var (
	codeBuildSecretKeywords = []string{
		"password",
		"secret",
		"api_key",
		"token",
		"access_key",
	}
	httpCredsRegex = regexp.MustCompile(`(?i)https?://[^/\s]+@`)
	userPassRegex  = regexp.MustCompile(`:[^/@\s]+@`)
)

func containsCodeBuildSecret(s string) bool {
	if s == "" {
		return false
	}
	upper := strings.ToUpper(s)
	if strings.Contains(upper, "AKIA") || strings.Contains(upper, "BEGIN RSA PRIVATE KEY") {
		return true
	}
	lower := strings.ToLower(s)
	for _, kw := range codeBuildSecretKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func hasSensitiveCredentialsInURL(loc string) bool {
	if loc == "" {
		return false
	}
	if strings.Contains(strings.ToLower(loc), "x-token-auth:") {
		return true
	}
	if httpCredsRegex.MatchString(loc) {
		return true
	}
	if userPassRegex.MatchString(loc) {
		return true
	}
	return false
}

// Scan audits all CodeBuild projects in the configured region against security best practices.
func (s *CodeBuildScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	var nextToken *string
	var projectNames []string

	for {
		if scanner.ShouldStop(ctx, processedCount+len(projectNames), limit) {
			break
		}
		output, err := s.client.ListProjects(ctx, &codebuild.ListProjectsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list CodeBuild projects: %w", err)
		}

		projectNames = append(projectNames, output.Projects...)

		if limit > 0 && len(projectNames) >= limit {
			projectNames = projectNames[:limit]
			break
		}

		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}

	if len(projectNames) == 0 {
		return results, nil
	}

	const batchSize = 100
	for i := 0; i < len(projectNames); i += batchSize {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}

		end := i + batchSize
		if end > len(projectNames) {
			end = len(projectNames)
		}
		chunk := projectNames[i:end]

		batchOutput, err := s.client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: chunk,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to batch get CodeBuild projects: %w", err)
		}

		for _, project := range batchOutput.Projects {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++

			projectName := aws.ToString(project.Name)
			projectArn := aws.ToString(project.Arn)
			if projectName == "" {
				projectName = projectArn
			}
			if projectArn == "" {
				projectArn = fmt.Sprintf("arn:aws:codebuild:%s::project/%s", region, projectName)
			}
			if projectName == "" {
				projectName = "unknown"
			}

			nodes := []graph.Node{{ID: projectArn, NodeType: "SecaaS-CodeBuild"}}

			// Check a: codebuild_project_no_secrets_in_variables (CRITICAL)
			var secretIssues []string
			if project.Environment != nil {
				for _, envVar := range project.Environment.EnvironmentVariables {
					if envVar.Type == codebuildtypes.EnvironmentVariableTypePlaintext || envVar.Type == "" {
						name := aws.ToString(envVar.Name)
						val := aws.ToString(envVar.Value)
						if containsCodeBuildSecret(name) || containsCodeBuildSecret(val) {
							secretIssues = append(secretIssues, fmt.Sprintf("Plaintext environment variable '%s' contains sensitive keyword or secret pattern", name))
						}
					}
				}
			}

			if len(secretIssues) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   projectName,
					ResourceType: "SecaaS-CodeBuild",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "codebuild_project_no_secrets_in_variables",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"ProjectName":    projectName,
						"ProjectArn":     projectArn,
						"StatusExtended": fmt.Sprintf("CodeBuild project %s contains sensitive plaintext environment variables.", projectName),
						"SecurityIssues": secretIssues,
						"Recommendation": "Store sensitive environment variables in AWS Secrets Manager or Parameter Store instead of PLAINTEXT.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   projectName,
					ResourceType: "SecaaS-CodeBuild",
					Region:       region,
					Status:       "PASS",
					RuleID:       "codebuild_project_no_secrets_in_variables",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ProjectName":    projectName,
						"ProjectArn":     projectArn,
						"StatusExtended": fmt.Sprintf("CodeBuild project %s does not contain sensitive plaintext environment variables.", projectName),
					},
					Nodes: nodes,
				})
			}

			// Check b: codebuild_project_source_repo_url_no_sensitive_credentials (CRITICAL)
			var credIssues []string
			if project.Source != nil && project.Source.Location != nil {
				loc := aws.ToString(project.Source.Location)
				if hasSensitiveCredentialsInURL(loc) {
					credIssues = append(credIssues, fmt.Sprintf("Primary source location embeds sensitive credentials: %s", loc))
				}
			}
			for _, sec := range project.SecondarySources {
				if sec.Location != nil {
					loc := aws.ToString(sec.Location)
					if hasSensitiveCredentialsInURL(loc) {
						credIssues = append(credIssues, fmt.Sprintf("Secondary source location embeds sensitive credentials: %s", loc))
					}
				}
			}

			if len(credIssues) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   projectName,
					ResourceType: "SecaaS-CodeBuild",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "codebuild_project_source_repo_url_no_sensitive_credentials",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"ProjectName":    projectName,
						"ProjectArn":     projectArn,
						"StatusExtended": fmt.Sprintf("CodeBuild project %s source repository URL contains sensitive credentials.", projectName),
						"SecurityIssues": credIssues,
						"Recommendation": "Remove sensitive credentials from repository URL; use OAuth or CodeStar connections.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   projectName,
					ResourceType: "SecaaS-CodeBuild",
					Region:       region,
					Status:       "PASS",
					RuleID:       "codebuild_project_source_repo_url_no_sensitive_credentials",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ProjectName":    projectName,
						"ProjectArn":     projectArn,
						"StatusExtended": fmt.Sprintf("CodeBuild project %s source repository URLs do not embed sensitive credentials.", projectName),
					},
					Nodes: nodes,
				})
			}
		}
	}

	return results, nil
}
