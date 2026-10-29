package secaas

import (
	"context"
	"fmt"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
)

// DMSApi defines the mockable interface for AWS DMS operations.
type DMSApi interface {
	DescribeReplicationInstances(ctx context.Context, params *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error)
}

// DMSScanner audits AWS DMS replication instances for security compliance.
type DMSScanner struct {
	client DMSApi
	region string
}

// NewDMSScanner creates a new DMSScanner with the provided AWS config.
func NewDMSScanner(cfg aws.Config) *DMSScanner {
	return &DMSScanner{
		client: databasemigrationservice.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewDMSScannerWithClient creates a DMSScanner with a custom/mock client.
func NewDMSScannerWithClient(client DMSApi, region string) *DMSScanner {
	return &DMSScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *DMSScanner) Name() string {
	return "DMS-SecaaS-Scanner"
}

// Scan audits all DMS replication instances in the configured region.
func (s *DMSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := databasemigrationservice.NewDescribeReplicationInstancesPaginator(s.client, &databasemigrationservice.DescribeReplicationInstancesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DMS replication instances: %w", err)
		}

		for _, instance := range page.ReplicationInstances {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			instanceID := aws.ToString(instance.ReplicationInstanceIdentifier)
			if instanceID == "" {
				continue
			}

			instanceArn := aws.ToString(instance.ReplicationInstanceArn)
			if instanceArn == "" {
				instanceArn = fmt.Sprintf("arn:aws:dms:%s::rep:%s", region, instanceID)
			}

			var edges []graph.Edge
			for _, sg := range instance.VpcSecurityGroups {
				if sg.VpcSecurityGroupId != nil {
					edges = append(edges, graph.Edge{
						From:     aws.ToString(sg.VpcSecurityGroupId),
						To:       instanceArn,
						Relation: "ATTACHED_TO",
					})
				}
			}
			if instance.KmsKeyId != nil && *instance.KmsKeyId != "" {
				edges = append(edges, graph.Edge{
					From:     instanceArn,
					To:       aws.ToString(instance.KmsKeyId),
					Relation: "ENCRYPTED_WITH",
				})
			}

			nodes := []graph.Node{{ID: instanceArn, NodeType: "SecaaS-DMS"}}

			// a) dms_instance_no_public_access (CRITICAL)
			if instance.PubliclyAccessible {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-DMS",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "dms_instance_no_public_access",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"ReplicationInstanceIdentifier": instanceID,
						"PubliclyAccessible":            true,
						"StatusExtended":                fmt.Sprintf("DMS replication instance %s is publicly accessible.", instanceID),
						"SecurityIssues":                []string{"DMS replication instance has public access enabled"},
						"Recommendation":                "Disable public accessibility on DMS replication instances.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-DMS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "dms_instance_no_public_access",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ReplicationInstanceIdentifier": instanceID,
						"PubliclyAccessible":            false,
						"StatusExtended":                fmt.Sprintf("DMS replication instance %s is not publicly accessible.", instanceID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *DMSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "dms-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "dms",
		CheckIDs:      []string{"dms_instance_no_public_access"},
	}
}
