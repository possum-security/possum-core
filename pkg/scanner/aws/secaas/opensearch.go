package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
)

// OpenSearchClient defines the interface for OpenSearch Service API operations.
type OpenSearchClient interface {
	ListDomainNames(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomain(ctx context.Context, params *opensearch.DescribeDomainInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error)
}

// OpenSearchScanner evaluates OpenSearch domain security postures.
type OpenSearchScanner struct {
	client OpenSearchClient
	region string
}

// NewOpenSearchScanner creates an OpenSearchScanner with AWS config.
func NewOpenSearchScanner(cfg aws.Config) *OpenSearchScanner {
	return &OpenSearchScanner{
		client: opensearch.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewOpenSearchScannerWithClient creates an OpenSearchScanner with custom/mock client.
func NewOpenSearchScannerWithClient(client OpenSearchClient, region string) *OpenSearchScanner {
	return &OpenSearchScanner{
		client: client,
		region: region,
	}
}

func (s *OpenSearchScanner) Name() string {
	return "OpenSearch-SecaaS-Scanner"
}

func (s *OpenSearchScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	domainsOut, err := s.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list OpenSearch domains: %w", err)
	}

	for _, domainInfo := range domainsOut.DomainNames {
		domainName := aws.ToString(domainInfo.DomainName)
		if domainName == "" {
			continue
		}

		descOut, err := s.client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{
			DomainName: aws.String(domainName),
		})
		if err != nil || descOut.DomainStatus == nil {
			continue
		}

		status := descOut.DomainStatus
		domainArn := aws.ToString(status.ARN)
		if domainArn == "" {
			domainArn = fmt.Sprintf("arn:aws:es:%s::domain/%s", region, domainName)
		}

		// 1. Encryption at rest (opensearch_service_domains_encryption_at_rest_enabled - CRITICAL)
		encAtRest := status.EncryptionAtRestOptions != nil && aws.ToBool(status.EncryptionAtRestOptions.Enabled)
		if encAtRest {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "PASS",
				RuleID:       "opensearch_service_domains_encryption_at_rest_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s has encryption at rest enabled.", domainName),
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "opensearch_service_domains_encryption_at_rest_enabled",
				Severity:     "CRITICAL",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s does not have encryption at rest enabled.", domainName),
					"SecurityIssues": []string{"Encryption at rest is disabled"},
					"Recommendation": "Enable encryption at rest using AWS KMS for the OpenSearch domain.",
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		}

		// 2. Node-to-node encryption (opensearch_service_domains_node_to_node_encryption_enabled - MEDIUM)
		nodeToNode := status.NodeToNodeEncryptionOptions != nil && aws.ToBool(status.NodeToNodeEncryptionOptions.Enabled)
		if nodeToNode {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "PASS",
				RuleID:       "opensearch_service_domains_node_to_node_encryption_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s has node-to-node encryption enabled.", domainName),
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "opensearch_service_domains_node_to_node_encryption_enabled",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s does not have node-to-node encryption enabled.", domainName),
					"SecurityIssues": []string{"Node-to-node encryption is disabled"},
					"Recommendation": "Enable node-to-node encryption to protect inter-cluster traffic.",
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		}

		// 3. Enforce HTTPS (opensearch_service_domains_https_communications_enforced - MEDIUM)
		enforceHTTPS := status.DomainEndpointOptions != nil && aws.ToBool(status.DomainEndpointOptions.EnforceHTTPS)
		if enforceHTTPS {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "PASS",
				RuleID:       "opensearch_service_domains_https_communications_enforced",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s enforces HTTPS communication.", domainName),
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "opensearch_service_domains_https_communications_enforced",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s allows plaintext HTTP traffic.", domainName),
					"SecurityIssues": []string{"HTTPS communication is not enforced"},
					"Recommendation": "Enforce HTTPS communication and modern TLS policies on domain endpoint options.",
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		}

		// 4. Inside VPC only / Not Publicly Accessible (opensearch_service_domains_not_publicly_accessible - MEDIUM)
		inVPC := status.VPCOptions != nil && aws.ToString(status.VPCOptions.VPCId) != ""
		if inVPC {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "PASS",
				RuleID:       "opensearch_service_domains_not_publicly_accessible",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"VPCId":          aws.ToString(status.VPCOptions.VPCId),
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s is isolated inside VPC %s.", domainName, aws.ToString(status.VPCOptions.VPCId)),
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "opensearch_service_domains_not_publicly_accessible",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s is deployed outside a VPC and potentially internet-accessible.", domainName),
					"SecurityIssues": []string{"Domain is not configured with VPC access"},
					"Recommendation": "Migrate OpenSearch domain into a private VPC subnet.",
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		}

		// 5. Audit Logging (opensearch_service_domains_audit_logging_enabled - MEDIUM)
		auditLogOption, hasAuditOption := status.LogPublishingOptions[string(opensearchtypes.LogTypeAuditLogs)]
		auditLogsEnabled := hasAuditOption && aws.ToBool(auditLogOption.Enabled)
		if auditLogsEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "PASS",
				RuleID:       "opensearch_service_domains_audit_logging_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s has audit logging enabled.", domainName),
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "opensearch_service_domains_audit_logging_enabled",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s does not publish audit logs to CloudWatch.", domainName),
					"SecurityIssues": []string{"Audit logging is disabled"},
					"Recommendation": "Enable audit logging to publish user activity and query logs to CloudWatch.",
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		}

		// 6. Fine-grained Access Control (opensearch_service_domains_access_control_enabled - HIGH)
		fgacEnabled := status.AdvancedSecurityOptions != nil && aws.ToBool(status.AdvancedSecurityOptions.Enabled)
		if fgacEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "PASS",
				RuleID:       "opensearch_service_domains_access_control_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s has fine-grained access control enabled.", domainName),
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   domainName,
				ResourceType: "SecaaS-OpenSearchDomain",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "opensearch_service_domains_access_control_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DomainName":     domainName,
					"StatusExtended": fmt.Sprintf("OpenSearch domain %s does not have fine-grained access control enabled.", domainName),
					"SecurityIssues": []string{"Fine-grained access control is disabled"},
					"Recommendation": "Enable fine-grained access control with IAM or internal user database authentication.",
				},
				Nodes: []graph.Node{{ID: domainArn, NodeType: "SecaaS-OpenSearchDomain"}},
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *OpenSearchScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "opensearch-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "opensearch",
		CheckIDs:      []string{"opensearch_service_domains_access_control_enabled", "opensearch_service_domains_audit_logging_enabled", "opensearch_service_domains_encryption_at_rest_enabled", "opensearch_service_domains_https_communications_enforced", "opensearch_service_domains_node_to_node_encryption_enabled", "opensearch_service_domains_not_publicly_accessible"},
	}
}
