package secaas

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

// SecurityHubApi defines the interface for AWS Security Hub operations for mocking and testing.
type SecurityHubApi interface {
	DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

// SecurityHubScanner evaluates whether AWS Security Hub is enabled in the region.
type SecurityHubScanner struct {
	client SecurityHubApi
	region string
}

// NewSecurityHubScanner creates a new SecurityHubScanner with AWS config.
func NewSecurityHubScanner(cfg aws.Config) *SecurityHubScanner {
	return &SecurityHubScanner{
		client: securityhub.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewSecurityHubScannerWithClient creates a scanner with custom/mock client.
func NewSecurityHubScannerWithClient(client SecurityHubApi, region string) *SecurityHubScanner {
	return &SecurityHubScanner{
		client: client,
		region: region,
	}
}

func (s *SecurityHubScanner) Name() string {
	return "SecurityHub-SecaaS-Scanner"
}

// Scan checks securityhub_enabled (CIS 4.16).
func (s *SecurityHubScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	resourceID := fmt.Sprintf("securityhub-%s", region)

	out, err := s.client.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil || out == nil {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-SecurityHub",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "securityhub_enabled",
			Severity:     "HIGH",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("AWS Security Hub is not enabled in region %s.", region),
				"SecurityIssues": []string{"AWS Security Hub is not enabled in this region"},
				"Recommendation": "Enable AWS Security Hub in all active regions.",
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-SecurityHub"}},
		})
		return results, nil
	}

	hubArn := aws.ToString(out.HubArn)
	if hubArn != "" {
		resourceID = hubArn
	}

	metrics := map[string]interface{}{
		"StatusExtended": fmt.Sprintf("AWS Security Hub is enabled in region %s.", region),
	}
	if hubArn != "" {
		metrics["HubArn"] = hubArn
	}
	if out.SubscribedAt != nil {
		metrics["SubscribedAt"] = aws.ToString(out.SubscribedAt)
	}
	if out.AutoEnableControls != nil {
		metrics["AutoEnableControls"] = aws.ToBool(out.AutoEnableControls)
	}

	results = append(results, scanner.ScanResult{
		ResourceID:   resourceID,
		ResourceType: "SecaaS-SecurityHub",
		Region:       region,
		Status:       "PASS",
		RuleID:       "securityhub_enabled",
		Severity:     "INFO",
		Metrics:      metrics,
		Nodes:        []graph.Node{{ID: resourceID, NodeType: "SecaaS-SecurityHub"}},
	})

	return results, nil
}
