package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
)

// BedrockClient defines the interface for Amazon Bedrock API calls.
type BedrockClient interface {
	GetModelInvocationLoggingConfiguration(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error)
	ListGuardrails(ctx context.Context, params *bedrock.ListGuardrailsInput, optFns ...func(*bedrock.Options)) (*bedrock.ListGuardrailsOutput, error)
}

// BedrockScanner evaluates Amazon Bedrock security configurations.
type BedrockScanner struct {
	client BedrockClient
	region string
}

// NewBedrockScanner creates a new BedrockScanner with AWS config.
func NewBedrockScanner(cfg aws.Config) *BedrockScanner {
	return &BedrockScanner{
		client: bedrock.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewBedrockScannerWithClient creates a scanner with custom/mock client.
func NewBedrockScannerWithClient(client BedrockClient, region string) *BedrockScanner {
	return &BedrockScanner{
		client: client,
		region: region,
	}
}

func (s *BedrockScanner) Name() string {
	return "Bedrock-SecaaS-Scanner"
}

func (s *BedrockScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	resourceID := fmt.Sprintf("bedrock-%s", region)
	node := graph.Node{
		ID:       resourceID,
		NodeType: "SecaaS-Bedrock",
	}

	// 1. Model Invocation Logging Enabled (bedrock_model_invocation_logging_enabled - MEDIUM)
	loggingOut, err := s.client.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
	loggingConfigured := err == nil && loggingOut != nil && loggingOut.LoggingConfig != nil &&
		(loggingOut.LoggingConfig.CloudWatchConfig != nil || loggingOut.LoggingConfig.S3Config != nil)

	if loggingConfigured {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Bedrock",
			Region:       region,
			Status:       "PASS",
			RuleID:       "bedrock_model_invocation_logging_enabled",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Amazon Bedrock model invocation logging is enabled in region %s.", region),
			},
			Nodes: []graph.Node{node},
		})
	} else {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Bedrock",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "bedrock_model_invocation_logging_enabled",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Amazon Bedrock model invocation logging is not configured or enabled in region %s.", region),
				"SecurityIssues": []string{"Amazon Bedrock model invocation logging is not enabled"},
				"Recommendation": "Enable model invocation logging and route events to CloudWatch Logs and/or S3.",
			},
			Nodes: []graph.Node{node},
		})
	}

	// 2. Guardrails Configured (bedrock_guardrails_configured - MEDIUM)
	guardrailsOut, err := s.client.ListGuardrails(ctx, &bedrock.ListGuardrailsInput{})
	guardrailsConfigured := err == nil && guardrailsOut != nil && len(guardrailsOut.Guardrails) > 0

	if guardrailsConfigured {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Bedrock",
			Region:       region,
			Status:       "PASS",
			RuleID:       "bedrock_guardrails_configured",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"GuardrailCount": len(guardrailsOut.Guardrails),
				"StatusExtended": fmt.Sprintf("Amazon Bedrock has %d guardrail(s) configured in region %s.", len(guardrailsOut.Guardrails), region),
			},
			Nodes: []graph.Node{node},
		})
	} else {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Bedrock",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "bedrock_guardrails_configured",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Amazon Bedrock has no guardrails configured in region %s.", region),
				"SecurityIssues": []string{"No Amazon Bedrock guardrails configured in this region"},
				"Recommendation": "Create at least one Bedrock guardrail in each region where Bedrock is used to enforce content filtering and safety policies.",
			},
			Nodes: []graph.Node{node},
		})
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *BedrockScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "bedrock-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "bedrock",
		CheckIDs:      []string{"bedrock_guardrails_configured", "bedrock_model_invocation_logging_enabled"},
	}
}
