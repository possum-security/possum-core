package secaas

import (
	"context"
	"fmt"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
)

// RedshiftClient defines the mockable interface for Amazon Redshift API operations.
type RedshiftClient interface {
	DescribeClusters(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
	DescribeLoggingStatus(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error)
}

// RedshiftScanner evaluates Amazon Redshift security postures.
type RedshiftScanner struct {
	client RedshiftClient
	region string
}

// NewRedshiftScanner creates a RedshiftScanner with the provided AWS config.
func NewRedshiftScanner(cfg aws.Config) *RedshiftScanner {
	return &RedshiftScanner{
		client: redshift.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewRedshiftScannerWithClient creates a RedshiftScanner with a custom/mock client.
func NewRedshiftScannerWithClient(client RedshiftClient, region string) *RedshiftScanner {
	return &RedshiftScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *RedshiftScanner) Name() string {
	return "Redshift-SecaaS-Scanner"
}

// Scan audits all Redshift clusters in the configured region against security best practices.
func (s *RedshiftScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := redshift.NewDescribeClustersPaginator(s.client, &redshift.DescribeClustersInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe Redshift clusters: %w", err)
		}

		for _, cluster := range page.Clusters {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			clusterID := aws.ToString(cluster.ClusterIdentifier)
			if clusterID == "" {
				continue
			}

			clusterArn := fmt.Sprintf("arn:aws:redshift:%s::cluster:%s", region, clusterID)

			var edges []graph.Edge
			for _, sg := range cluster.VpcSecurityGroups {
				if sg.VpcSecurityGroupId != nil {
					edges = append(edges, graph.Edge{
						From:     aws.ToString(sg.VpcSecurityGroupId),
						To:       clusterArn,
						Relation: "ATTACHED_TO",
					})
				}
			}

			nodes := []graph.Node{{ID: clusterArn, NodeType: "SecaaS-Redshift"}}

			// 1. Check encryption at rest (redshift_cluster_encrypted_at_rest)
			// PASS if encrypted == true, FAIL (HIGH) if not.
			isEncrypted := aws.ToBool(cluster.Encrypted)
			if isEncrypted {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Redshift",
					Region:       region,
					Status:       "PASS",
					RuleID:       "redshift_cluster_encrypted_at_rest",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ClusterIdentifier": clusterID,
						"Encrypted":         true,
						"StatusExtended":    fmt.Sprintf("Redshift cluster %s is encrypted at rest.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Redshift",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "redshift_cluster_encrypted_at_rest",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"ClusterIdentifier": clusterID,
						"Encrypted":         false,
						"StatusExtended":    fmt.Sprintf("Redshift cluster %s is not encrypted at rest.", clusterID),
						"SecurityIssues":    []string{"Redshift cluster encryption at rest is disabled"},
						"Recommendation":    "Enable encryption at rest for the Redshift cluster using AWS KMS.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 2. Check audit logging (redshift_cluster_audit_logging & redshift_cluster_audit_logging)
			// Call DescribeLoggingStatus. PASS if LoggingEnabled == true, FAIL (MEDIUM) if not.
			loggingOut, logErr := s.client.DescribeLoggingStatus(ctx, &redshift.DescribeLoggingStatusInput{
				ClusterIdentifier: aws.String(clusterID),
			})

			auditLoggingRules := []string{
				"redshift_cluster_audit_logging",
			}

			isLoggingEnabled := logErr == nil && loggingOut != nil && aws.ToBool(loggingOut.LoggingEnabled)
			if isLoggingEnabled {
				for _, ruleID := range auditLoggingRules {
					results = append(results, scanner.ScanResult{
						ResourceID:   clusterID,
						ResourceType: "SecaaS-Redshift",
						Region:       region,
						Status:       "PASS",
						RuleID:       ruleID,
						Severity:     "INFO",
						Metrics: map[string]interface{}{
							"ClusterIdentifier": clusterID,
							"LoggingEnabled":    true,
							"StatusExtended":    fmt.Sprintf("Redshift cluster %s has audit logging enabled.", clusterID),
						},
						Nodes: nodes,
						Edges: edges,
					})
				}
			} else {
				failStatusExtended := fmt.Sprintf("Redshift cluster %s does not have audit logging enabled.", clusterID)
				if logErr != nil {
					failStatusExtended = fmt.Sprintf("Redshift cluster %s audit logging status could not be verified: %v", clusterID, logErr)
				}
				for _, ruleID := range auditLoggingRules {
					results = append(results, scanner.ScanResult{
						ResourceID:   clusterID,
						ResourceType: "SecaaS-Redshift",
						Region:       region,
						Status:       "FAIL",
						RuleID:       ruleID,
						Severity:     "MEDIUM",
						Metrics: map[string]interface{}{
							"ClusterIdentifier": clusterID,
							"LoggingEnabled":    false,
							"StatusExtended":    failStatusExtended,
							"SecurityIssues":    []string{"Redshift cluster audit logging is disabled"},
							"Recommendation":    "Enable audit logging for the Redshift cluster to export logs to Amazon S3 or CloudWatch.",
						},
						Nodes: nodes,
						Edges: edges,
					})
				}
			}

			// 3. Check public accessibility (redshift_cluster_public_access & redshift_cluster_public_access)
			// FAIL (HIGH) if true (public), PASS if false (private).
			publicAccessRules := []string{
				"redshift_cluster_public_access",
			}

			isPublic := aws.ToBool(cluster.PubliclyAccessible)
			if !isPublic {
				for _, ruleID := range publicAccessRules {
					results = append(results, scanner.ScanResult{
						ResourceID:   clusterID,
						ResourceType: "SecaaS-Redshift",
						Region:       region,
						Status:       "PASS",
						RuleID:       ruleID,
						Severity:     "INFO",
						Metrics: map[string]interface{}{
							"ClusterIdentifier":  clusterID,
							"PubliclyAccessible": false,
							"StatusExtended":     fmt.Sprintf("Redshift cluster %s is not publicly accessible.", clusterID),
						},
						Nodes: nodes,
						Edges: edges,
					})
				}
			} else {
				for _, ruleID := range publicAccessRules {
					results = append(results, scanner.ScanResult{
						ResourceID:   clusterID,
						ResourceType: "SecaaS-Redshift",
						Region:       region,
						Status:       "FAIL",
						RuleID:       ruleID,
						Severity:     "HIGH",
						Metrics: map[string]interface{}{
							"ClusterIdentifier":  clusterID,
							"PubliclyAccessible": true,
							"StatusExtended":     fmt.Sprintf("Redshift cluster %s is publicly accessible to the internet.", clusterID),
							"SecurityIssues":     []string{"Redshift cluster endpoint is publicly accessible"},
							"Recommendation":     "Disable public accessibility on the Redshift cluster and restrict access using private VPC subnets and security groups.",
						},
						Nodes: nodes,
						Edges: edges,
					})
				}
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *RedshiftScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "redshift-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "redshift",
		CheckIDs:      []string{"redshift_cluster_encrypted_at_rest"},
	}
}
