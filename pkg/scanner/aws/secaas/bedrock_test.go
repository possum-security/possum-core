package secaas

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockBedrockClient struct {
	loggingOutput    *bedrock.GetModelInvocationLoggingConfigurationOutput
	loggingErr       error
	guardrailsOutput *bedrock.ListGuardrailsOutput
	guardrailsErr    error
}

func (m *mockBedrockClient) GetModelInvocationLoggingConfiguration(ctx context.Context, params *bedrock.GetModelInvocationLoggingConfigurationInput, optFns ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error) {
	if m.loggingErr != nil {
		return nil, m.loggingErr
	}
	return m.loggingOutput, nil
}

func (m *mockBedrockClient) ListGuardrails(ctx context.Context, params *bedrock.ListGuardrailsInput, optFns ...func(*bedrock.Options)) (*bedrock.ListGuardrailsOutput, error) {
	if m.guardrailsErr != nil {
		return nil, m.guardrailsErr
	}
	return m.guardrailsOutput, nil
}

func TestBedrockScanner_Compliant(t *testing.T) {
	mock := &mockBedrockClient{
		loggingOutput: &bedrock.GetModelInvocationLoggingConfigurationOutput{
			LoggingConfig: &bedrocktypes.LoggingConfig{
				CloudWatchConfig: &bedrocktypes.CloudWatchConfig{
					LogGroupName: aws.String("/aws/bedrock/invocations"),
				},
				S3Config: &bedrocktypes.S3Config{
					BucketName: aws.String("bedrock-logs-bucket"),
				},
			},
		},
		guardrailsOutput: &bedrock.ListGuardrailsOutput{
			Guardrails: []bedrocktypes.GuardrailSummary{
				{
					Arn:         aws.String("arn:aws:bedrock:us-east-1:123456789012:guardrail/guardrail-1"),
					Id:          aws.String("guardrail-1"),
					Name:        aws.String("SafetyGuardrail"),
					Description: aws.String("Content safety guardrail"),
				},
			},
		},
	}

	scanner := NewBedrockScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Result 0: Model Invocation Logging
	assert.Equal(t, "bedrock-us-east-1", results[0].ResourceID)
	assert.Equal(t, "SecaaS-Bedrock", results[0].ResourceType)
	assert.Equal(t, "us-east-1", results[0].Region)
	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "bedrock_model_invocation_logging_enabled", results[0].RuleID)
	assert.Equal(t, "INFO", results[0].Severity)
	require.Len(t, results[0].Nodes, 1)
	assert.Equal(t, "bedrock-us-east-1", results[0].Nodes[0].ID)
	metrics0, ok := results[0].Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, metrics0["StatusExtended"], "enabled")

	// Result 1: Guardrails Configured
	assert.Equal(t, "bedrock-us-east-1", results[1].ResourceID)
	assert.Equal(t, "SecaaS-Bedrock", results[1].ResourceType)
	assert.Equal(t, "us-east-1", results[1].Region)
	assert.Equal(t, "PASS", results[1].Status)
	assert.Equal(t, "bedrock_guardrails_configured", results[1].RuleID)
	assert.Equal(t, "INFO", results[1].Severity)
	require.Len(t, results[1].Nodes, 1)
	assert.Equal(t, "bedrock-us-east-1", results[1].Nodes[0].ID)
	metrics1, ok := results[1].Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, metrics1["GuardrailCount"])
	assert.Contains(t, metrics1["StatusExtended"], "1 guardrail(s) configured")
}

func TestBedrockScanner_LoggingCloudWatchOnly(t *testing.T) {
	mock := &mockBedrockClient{
		loggingOutput: &bedrock.GetModelInvocationLoggingConfigurationOutput{
			LoggingConfig: &bedrocktypes.LoggingConfig{
				CloudWatchConfig: &bedrocktypes.CloudWatchConfig{
					LogGroupName: aws.String("/aws/bedrock/invocations"),
				},
				S3Config: nil,
			},
		},
		guardrailsOutput: &bedrock.ListGuardrailsOutput{
			Guardrails: []bedrocktypes.GuardrailSummary{},
		},
	}

	scanner := NewBedrockScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "bedrock_model_invocation_logging_enabled", results[0].RuleID)
	assert.Equal(t, "INFO", results[0].Severity)

	assert.Equal(t, "FAIL", results[1].Status)
	assert.Equal(t, "bedrock_guardrails_configured", results[1].RuleID)
	assert.Equal(t, "MEDIUM", results[1].Severity)
}

func TestBedrockScanner_LoggingS3Only(t *testing.T) {
	mock := &mockBedrockClient{
		loggingOutput: &bedrock.GetModelInvocationLoggingConfigurationOutput{
			LoggingConfig: &bedrocktypes.LoggingConfig{
				CloudWatchConfig: nil,
				S3Config: &bedrocktypes.S3Config{
					BucketName: aws.String("bedrock-audit-bucket"),
				},
			},
		},
		guardrailsOutput: &bedrock.ListGuardrailsOutput{
			Guardrails: []bedrocktypes.GuardrailSummary{
				{
					Arn:  aws.String("arn:aws:bedrock:us-west-2:123456789012:guardrail/g2"),
					Id:   aws.String("g2"),
					Name: aws.String("Guardrail2"),
				},
			},
		},
	}

	scanner := NewBedrockScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "bedrock_model_invocation_logging_enabled", results[0].RuleID)

	assert.Equal(t, "PASS", results[1].Status)
	assert.Equal(t, "bedrock_guardrails_configured", results[1].RuleID)
}

func TestBedrockScanner_NonCompliant(t *testing.T) {
	mock := &mockBedrockClient{
		loggingOutput: &bedrock.GetModelInvocationLoggingConfigurationOutput{
			LoggingConfig: nil,
		},
		guardrailsOutput: &bedrock.ListGuardrailsOutput{
			Guardrails: []bedrocktypes.GuardrailSummary{},
		},
	}

	scanner := NewBedrockScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Logging FAIL
	assert.Equal(t, "bedrock-eu-west-1", results[0].ResourceID)
	assert.Equal(t, "SecaaS-Bedrock", results[0].ResourceType)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "bedrock_model_invocation_logging_enabled", results[0].RuleID)
	assert.Equal(t, "MEDIUM", results[0].Severity)
	metrics0, ok := results[0].Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, metrics0["StatusExtended"], "not configured or enabled")
	assert.NotEmpty(t, metrics0["Recommendation"])
	assert.NotEmpty(t, metrics0["SecurityIssues"])

	// Guardrails FAIL
	assert.Equal(t, "bedrock-eu-west-1", results[1].ResourceID)
	assert.Equal(t, "SecaaS-Bedrock", results[1].ResourceType)
	assert.Equal(t, "FAIL", results[1].Status)
	assert.Equal(t, "bedrock_guardrails_configured", results[1].RuleID)
	assert.Equal(t, "MEDIUM", results[1].Severity)
	metrics1, ok := results[1].Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, metrics1["StatusExtended"], "no guardrails configured")
	assert.NotEmpty(t, metrics1["Recommendation"])
	assert.NotEmpty(t, metrics1["SecurityIssues"])
}

func TestBedrockScanner_ApiErrorsHandledGracefully(t *testing.T) {
	mock := &mockBedrockClient{
		loggingErr:    fmt.Errorf("AccessDeniedException: user is not authorized to perform bedrock:GetModelInvocationLoggingConfiguration"),
		guardrailsErr: fmt.Errorf("AccessDeniedException: user is not authorized to perform bedrock:ListGuardrails"),
	}

	scanner := NewBedrockScannerWithClient(mock, "ap-southeast-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "bedrock_model_invocation_logging_enabled", results[0].RuleID)
	assert.Equal(t, "MEDIUM", results[0].Severity)

	assert.Equal(t, "FAIL", results[1].Status)
	assert.Equal(t, "bedrock_guardrails_configured", results[1].RuleID)
	assert.Equal(t, "MEDIUM", results[1].Severity)
}

func TestBedrockScanner_FallbackRegion(t *testing.T) {
	mock := &mockBedrockClient{}
	s2 := NewBedrockScannerWithClient(mock, "")
	require.NotNil(t, s2)

	// If region is empty, it falls back to "global"
	results, err := s2.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "global", results[0].Region)
	assert.Equal(t, "bedrock-global", results[0].ResourceID)
}
