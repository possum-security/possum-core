package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	analyzerTypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
)

// AccessAnalyzerClient defines the interface for IAM Access Analyzer API calls.
type AccessAnalyzerClient interface {
	ListAnalyzers(ctx context.Context, params *accessanalyzer.ListAnalyzersInput, optFns ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error)
}

// AccessAnalyzerScanner evaluates whether IAM Access Analyzer is enabled in the region.
type AccessAnalyzerScanner struct {
	client AccessAnalyzerClient
	region string
}

// NewAccessAnalyzerScanner creates a new AccessAnalyzerScanner with AWS config.
func NewAccessAnalyzerScanner(cfg aws.Config) *AccessAnalyzerScanner {
	return &AccessAnalyzerScanner{
		client: accessanalyzer.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewAccessAnalyzerScannerWithClient creates a scanner with custom/mock client.
func NewAccessAnalyzerScannerWithClient(client AccessAnalyzerClient, region string) *AccessAnalyzerScanner {
	return &AccessAnalyzerScanner{
		client: client,
		region: region,
	}
}

func (s *AccessAnalyzerScanner) Name() string {
	return "AccessAnalyzer-SecaaS-Scanner"
}

func (s *AccessAnalyzerScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	res, err := s.client.ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list access analyzers: %w", err)
	}

	hasActiveAnalyzer := false
	var activeAnalyzers []string

	for _, a := range res.Analyzers {
		if a.Status == analyzerTypes.AnalyzerStatusActive {
			hasActiveAnalyzer = true
			activeAnalyzers = append(activeAnalyzers, aws.ToString(a.Name))
		}
	}

	resourceID := fmt.Sprintf("accessanalyzer-%s", region)

	if hasActiveAnalyzer {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-AccessAnalyzer",
			Region:       region,
			Status:       "PASS",
			RuleID:       "accessanalyzer_enabled",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended":  fmt.Sprintf("IAM Access Analyzer is active in region %s (%d active analyzers: %v).", region, len(activeAnalyzers), activeAnalyzers),
				"ActiveAnalyzers": activeAnalyzers,
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-AccessAnalyzer"}},
		})
	} else {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-AccessAnalyzer",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "accessanalyzer_enabled",
			Severity:     "LOW",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("IAM Access Analyzer is not enabled or active in region %s.", region),
				"SecurityIssues": []string{"No active IAM Access Analyzer in this region"},
				"Recommendation": "Enable IAM Access Analyzer to continuously analyze resource policies and detect external access.",
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-AccessAnalyzer"}},
		})
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *AccessAnalyzerScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "accessanalyzer-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeGlobal,
		ExecutionCost: scanner.CostMedium,
		Service:       "accessanalyzer",
		CheckIDs:      []string{"accessanalyzer_enabled"},
	}
}
