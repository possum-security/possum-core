package secaas

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	analyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/stretchr/testify/assert"
)

type mockAccessAnalyzerClient struct {
	output *accessanalyzer.ListAnalyzersOutput
	err    error
}

func (m *mockAccessAnalyzerClient) ListAnalyzers(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestAccessAnalyzerScanner_Active(t *testing.T) {
	mock := &mockAccessAnalyzerClient{
		output: &accessanalyzer.ListAnalyzersOutput{
			Analyzers: []analyzerTypes.AnalyzerSummary{
				{
					Arn:    aws.String("arn:aws:access-analyzer:us-east-1:123456789012:analyzer/ConsoleAnalyzer"),
					Name:   aws.String("ConsoleAnalyzer"),
					Status: analyzerTypes.AnalyzerStatusActive,
				},
			},
		},
	}

	scanner := NewAccessAnalyzerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "accessanalyzer_enabled", results[0].RuleID)
}

func TestAccessAnalyzerScanner_InactiveOrNone(t *testing.T) {
	mock := &mockAccessAnalyzerClient{
		output: &accessanalyzer.ListAnalyzersOutput{
			Analyzers: []analyzerTypes.AnalyzerSummary{
				{
					Arn:    aws.String("arn:aws:access-analyzer:us-east-1:123456789012:analyzer/DisabledAnalyzer"),
					Name:   aws.String("DisabledAnalyzer"),
					Status: analyzerTypes.AnalyzerStatusDisabled,
				},
			},
		},
	}

	scanner := NewAccessAnalyzerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "accessanalyzer_enabled", results[0].RuleID)
	assert.Equal(t, "LOW", results[0].Severity)
}
