package secaas

import (
	"context"
	"fmt"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
)

// MacieClient defines the interface for Amazon Macie API calls.
type MacieClient interface {
	GetMacieSession(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error)
}

// MacieScanner evaluates whether Amazon Macie is enabled in a region.
type MacieScanner struct {
	client MacieClient
	region string
}

// NewMacieScanner creates a new MacieScanner with AWS config.
func NewMacieScanner(cfg aws.Config) *MacieScanner {
	return &MacieScanner{
		client: macie2.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewMacieScannerWithClient creates a scanner with custom/mock client.
func NewMacieScannerWithClient(client MacieClient, region string) *MacieScanner {
	return &MacieScanner{
		client: client,
		region: region,
	}
}

func (s *MacieScanner) Name() string {
	return "Macie-SecaaS-Scanner"
}

func (s *MacieScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	resourceID := fmt.Sprintf("macie-%s", region)

	session, err := s.client.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
	if err != nil || session.Status != macietypes.MacieStatusEnabled {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Macie",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "macie_is_enabled",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Amazon Macie is not enabled or is paused in region %s.", region),
				"SecurityIssues": []string{"Amazon Macie sensitive data discovery is not operational"},
				"Recommendation": "Enable Amazon Macie in this region to automatically discover and classify sensitive data.",
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-Macie"}},
		})
	} else {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Macie",
			Region:       region,
			Status:       "PASS",
			RuleID:       "macie_is_enabled",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Amazon Macie is enabled and operational in region %s.", region),
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-Macie"}},
		})
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *MacieScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "macie-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "macie",
		CheckIDs:      []string{"macie_is_enabled"},
	}
}
