package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
)

// CloudFormationApi defines the interface for CloudFormation API operations.
type CloudFormationApi interface {
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

type CloudFormationScanner struct {
	client CloudFormationApi
}

func NewCloudFormationScanner(cfg aws.Config) *CloudFormationScanner {
	return &CloudFormationScanner{
		client: cloudformation.NewFromConfig(cfg),
	}
}

func NewCloudFormationScannerWithClient(client CloudFormationApi) *CloudFormationScanner {
	return &CloudFormationScanner{
		client: client,
	}
}

func (s *CloudFormationScanner) Name() string {
	return "CloudFormation-SecaaS-Scanner"
}

func detectSecretsInOutputs(outputs []cftypes.Output) []string {
	var issues []string
	secretKeywords := []string{
		"password",
		"secret",
		"api_key",
		"token",
		"private_key",
	}

	for _, out := range outputs {
		key := aws.ToString(out.OutputKey)
		val := aws.ToString(out.OutputValue)
		desc := aws.ToString(out.Description)

		fields := []struct {
			name string
			text string
		}{
			{name: fmt.Sprintf("Output '%s' key", key), text: key},
			{name: fmt.Sprintf("Output '%s' value", key), text: val},
			{name: fmt.Sprintf("Output '%s' description", key), text: desc},
		}

		for _, f := range fields {
			if f.text == "" {
				continue
			}
			if strings.Contains(f.text, "AKIA") {
				issues = append(issues, fmt.Sprintf("%s contains AWS Access Key ID (AKIA)", f.name))
			}
			fLower := strings.ToLower(f.text)
			if strings.Contains(fLower, "begin rsa private key") || strings.Contains(fLower, "-----begin") {
				issues = append(issues, fmt.Sprintf("%s contains private key pattern", f.name))
			}
			for _, kw := range secretKeywords {
				if strings.Contains(fLower, kw) {
					issues = append(issues, fmt.Sprintf("%s contains sensitive keyword '%s'", f.name, kw))
				}
			}
		}
	}

	// Deduplicate issues
	seen := make(map[string]bool)
	var deduped []string
	for _, issue := range issues {
		if !seen[issue] {
			seen[issue] = true
			deduped = append(deduped, issue)
		}
	}
	return deduped
}

func (s *CloudFormationScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	if s.client == nil {
		return nil, fmt.Errorf("cloudformation client is not initialized")
	}

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
			roleARN := aws.ToString(stack.RoleARN)

			// 1. cloudformation_stacks_termination_protection_enabled
			var issues []string
			if !aws.ToBool(stack.EnableTerminationProtection) {
				issues = append(issues, "CloudFormation stack termination protection is disabled")
			}
			if roleARN == "" {
				issues = append(issues, "CloudFormation stack missing dedicated RoleARN (executes with caller privileges)")
			}

			isVulnerable := len(issues) > 0

			metrics := map[string]interface{}{
				"StackName": stackName,
				"RoleARN":   roleARN,
			}

			severity := "INFO"
			status := "PASS"
			if isVulnerable {
				severity = "MEDIUM"
				status = "FAIL"
				metrics["SecurityIssues"] = issues
				metrics["StatusExtended"] = fmt.Sprintf("CloudFormation stack %s has termination protection disabled or missing RoleARN.", stackName)
				metrics["Recommendation"] = "Enable termination protection for the CloudFormation stack to prevent accidental deletion."
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("CloudFormation stack %s has termination protection enabled.", stackName)
				metrics["Recommendation"] = "Maintain CloudFormation termination protection."
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   stackID,
				ResourceType: "SecaaS-CloudFormation",
				Region:       "global",
				Status:       status,
				IsOrphaned:   isVulnerable,
				RuleID:       "cloudformation_stacks_termination_protection_enabled",
				Severity:     severity,
				Metrics:      metrics,
				Nodes:        []graph.Node{{ID: stackID, NodeType: "SecaaS-CloudFormation"}},
				Edges:        []graph.Edge{{From: stackID, To: roleARN, Relation: "HAS_ROLE"}},
			})

			// 2. cloudformation_stack_outputs_find_secrets (CRITICAL)
			outputSecretIssues := detectSecretsInOutputs(stack.Outputs)
			outputSeverity := "INFO"
			outputStatus := "PASS"
			outputMetrics := map[string]interface{}{
				"StackName": stackName,
				"RoleARN":   roleARN,
			}

			if len(outputSecretIssues) > 0 {
				outputSeverity = "CRITICAL"
				outputStatus = "FAIL"
				outputMetrics["SecurityIssues"] = outputSecretIssues
				outputMetrics["StatusExtended"] = fmt.Sprintf("CloudFormation stack %s outputs contain potential secrets (%d detected).", stackName, len(outputSecretIssues))
				outputMetrics["Recommendation"] = "Remove secrets from CloudFormation stack outputs; use Secrets Manager dynamic references or NoEcho."
			} else {
				outputMetrics["StatusExtended"] = fmt.Sprintf("CloudFormation stack %s outputs do not contain apparent secrets.", stackName)
				outputMetrics["Recommendation"] = "Maintain secret hygiene and avoid exposing credentials in CloudFormation stack outputs."
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   stackID,
				ResourceType: "SecaaS-CloudFormation",
				Region:       "global",
				Status:       outputStatus,
				IsOrphaned:   len(outputSecretIssues) > 0,
				RuleID:       "cloudformation_stack_outputs_find_secrets",
				Severity:     outputSeverity,
				Metrics:      outputMetrics,
				Nodes:        []graph.Node{{ID: stackID, NodeType: "SecaaS-CloudFormation"}},
				Edges:        []graph.Edge{{From: stackID, To: roleARN, Relation: "HAS_ROLE"}},
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *CloudFormationScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "cloudformation-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "cloudformation",
		CheckIDs:      []string{"cloudformation_stack_outputs_find_secrets", "cloudformation_stacks_termination_protection_enabled"},
	}
}
