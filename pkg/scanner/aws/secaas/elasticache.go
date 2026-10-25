package secaas

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
)

// ElastiCacheApi defines the mockable interface for Amazon ElastiCache API operations.
type ElastiCacheApi interface {
	DescribeReplicationGroups(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
}

// ElastiCacheScanner evaluates Amazon ElastiCache Redis replication group security postures.
type ElastiCacheScanner struct {
	client ElastiCacheApi
	region string
}

// NewElastiCacheScanner creates an ElastiCacheScanner with the provided AWS config.
func NewElastiCacheScanner(cfg aws.Config) *ElastiCacheScanner {
	return &ElastiCacheScanner{
		client: elasticache.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewElastiCacheScannerWithClient creates an ElastiCacheScanner with a custom/mock client.
func NewElastiCacheScannerWithClient(client ElastiCacheApi, region string) *ElastiCacheScanner {
	return &ElastiCacheScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *ElastiCacheScanner) Name() string {
	return "ElastiCache-SecaaS-Scanner"
}

// Scan audits all ElastiCache Redis replication groups in the configured region against security best practices.
func (s *ElastiCacheScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := elasticache.NewDescribeReplicationGroupsPaginator(s.client, &elasticache.DescribeReplicationGroupsInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe ElastiCache replication groups: %w", err)
		}

		for _, rg := range page.ReplicationGroups {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			rgID := aws.ToString(rg.ReplicationGroupId)
			if rgID == "" {
				continue
			}

			rgArn := aws.ToString(rg.ARN)
			if rgArn == "" {
				rgArn = fmt.Sprintf("arn:aws:elasticache:%s::replicationgroup:%s", region, rgID)
			}

			nodes := []graph.Node{{ID: rgArn, NodeType: "SecaaS-ElastiCache"}}
			var edges []graph.Edge
			for _, mc := range rg.MemberClusters {
				edges = append(edges, graph.Edge{
					From:     mc,
					To:       rgArn,
					Relation: "MEMBER_OF",
				})
			}

			// 1. In-transit encryption (elasticache_redis_cluster_in_transit_encryption_enabled - HIGH)
			// TransitEncryptionEnabled == true -> PASS, else FAIL
			if aws.ToBool(rg.TransitEncryptionEnabled) {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "PASS",
					RuleID:       "elasticache_redis_cluster_in_transit_encryption_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":       rgID,
						"TransitEncryptionEnabled": true,
						"StatusExtended":           fmt.Sprintf("ElastiCache Redis cluster %s has in-transit encryption enabled.", rgID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "elasticache_redis_cluster_in_transit_encryption_enabled",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":       rgID,
						"TransitEncryptionEnabled": false,
						"StatusExtended":           fmt.Sprintf("ElastiCache Redis cluster %s does not have in-transit encryption enabled.", rgID),
						"SecurityIssues":           []string{"ElastiCache Redis cluster in-transit encryption is disabled"},
						"Recommendation":           "Enable in-transit encryption for the ElastiCache Redis replication group.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 2. At-rest encryption (elasticache_redis_cluster_rest_encryption_enabled - HIGH)
			// AtRestEncryptionEnabled == true -> PASS, else FAIL
			if aws.ToBool(rg.AtRestEncryptionEnabled) {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "PASS",
					RuleID:       "elasticache_redis_cluster_rest_encryption_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":      rgID,
						"AtRestEncryptionEnabled": true,
						"StatusExtended":          fmt.Sprintf("ElastiCache Redis cluster %s has encryption at rest enabled.", rgID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "elasticache_redis_cluster_rest_encryption_enabled",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":      rgID,
						"AtRestEncryptionEnabled": false,
						"StatusExtended":          fmt.Sprintf("ElastiCache Redis cluster %s does not have encryption at rest enabled.", rgID),
						"SecurityIssues":          []string{"ElastiCache Redis cluster encryption at rest is disabled"},
						"Recommendation":          "Enable encryption at rest for the ElastiCache Redis replication group.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 3. Automated snapshot backups (elasticache_redis_cluster_backup_enabled - MEDIUM)
			// SnapshotRetentionLimit != nil && *SnapshotRetentionLimit > 0 -> PASS, else FAIL
			hasBackup := rg.SnapshotRetentionLimit != nil && aws.ToInt32(rg.SnapshotRetentionLimit) > 0
			retentionDays := aws.ToInt32(rg.SnapshotRetentionLimit)

			if hasBackup {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "PASS",
					RuleID:       "elasticache_redis_cluster_backup_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":     rgID,
						"SnapshotRetentionLimit": retentionDays,
						"StatusExtended":         fmt.Sprintf("ElastiCache Redis cluster %s has automated backups enabled (%d days retention).", rgID, retentionDays),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				var statusMsg string
				if rg.SnapshotRetentionLimit == nil || retentionDays == 0 {
					statusMsg = fmt.Sprintf("ElastiCache Redis cluster %s does not have automated backups enabled.", rgID)
				} else {
					statusMsg = fmt.Sprintf("ElastiCache Redis cluster %s backup retention limit (%d days) is not enabled.", rgID, retentionDays)
				}
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "elasticache_redis_cluster_backup_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":     rgID,
						"SnapshotRetentionLimit": retentionDays,
						"StatusExtended":         statusMsg,
						"SecurityIssues":         []string{"ElastiCache Redis cluster automated backups are disabled"},
						"Recommendation":         "Enable automated backups by setting snapshot retention limit > 0 for the ElastiCache Redis replication group.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 4. Auto minor version upgrades (elasticache_redis_cluster_auto_minor_version_upgrades - LOW)
			// AutoMinorVersionUpgrade == true -> PASS, else FAIL
			if aws.ToBool(rg.AutoMinorVersionUpgrade) {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "PASS",
					RuleID:       "elasticache_redis_cluster_auto_minor_version_upgrades",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":      rgID,
						"AutoMinorVersionUpgrade": true,
						"StatusExtended":          fmt.Sprintf("ElastiCache Redis cluster %s has auto minor version upgrades enabled.", rgID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   rgID,
					ResourceType: "SecaaS-ElastiCache",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "elasticache_redis_cluster_auto_minor_version_upgrades",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"ReplicationGroupId":      rgID,
						"AutoMinorVersionUpgrade": false,
						"StatusExtended":          fmt.Sprintf("ElastiCache Redis cluster %s does not have auto minor version upgrades enabled.", rgID),
						"SecurityIssues":          []string{"ElastiCache Redis cluster auto minor version upgrades are disabled"},
						"Recommendation":          "Enable auto minor version upgrades for the ElastiCache Redis replication group.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}
		}
	}

	return results, nil
}
