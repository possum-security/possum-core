package secaas

import (
	"context"
	"fmt"
	"strings"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
)

// NeptuneApi defines the mockable interface for Amazon Neptune API operations.
type NeptuneApi interface {
	DescribeDBClusters(ctx context.Context, params *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
	DescribeDBClusterSnapshots(ctx context.Context, params *neptune.DescribeDBClusterSnapshotsInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClusterSnapshotsOutput, error)
	DescribeDBClusterSnapshotAttributes(ctx context.Context, params *neptune.DescribeDBClusterSnapshotAttributesInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClusterSnapshotAttributesOutput, error)
}

// NeptuneClient is an alias for backward compatibility.
type NeptuneClient = NeptuneApi

// NeptuneScanner evaluates Amazon Neptune DB cluster security postures.
type NeptuneScanner struct {
	client NeptuneApi
	region string
}

// NewNeptuneScanner creates a NeptuneScanner with the provided AWS config.
func NewNeptuneScanner(cfg aws.Config) *NeptuneScanner {
	return &NeptuneScanner{
		client: neptune.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewNeptuneScannerWithClient creates a NeptuneScanner with a custom/mock client.
func NewNeptuneScannerWithClient(client NeptuneApi, region string) *NeptuneScanner {
	return &NeptuneScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *NeptuneScanner) Name() string {
	return "Neptune-SecaaS-Scanner"
}

// Scan audits all Neptune DB clusters in the configured region against security best practices.
func (s *NeptuneScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	clusterArns := make(map[string]string)
	paginator := neptune.NewDescribeDBClustersPaginator(s.client, &neptune.DescribeDBClustersInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe Neptune DB clusters: %w", err)
		}

		for _, cluster := range page.DBClusters {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			clusterID := aws.ToString(cluster.DBClusterIdentifier)
			if clusterID == "" {
				continue
			}

			clusterArn := aws.ToString(cluster.DBClusterArn)
			if clusterArn == "" {
				clusterArn = fmt.Sprintf("arn:aws:rds:%s::cluster:%s", region, clusterID)
			}
			clusterArns[clusterID] = clusterArn

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

			nodes := []graph.Node{{ID: clusterArn, NodeType: "SecaaS-Neptune"}}

			// 1. Check storage encryption (neptune_cluster_storage_encrypted)
			// PASS if StorageEncrypted == true, FAIL (HIGH) if false.
			isEncrypted := aws.ToBool(cluster.StorageEncrypted)
			if isEncrypted {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Neptune",
					Region:       region,
					Status:       "PASS",
					RuleID:       "neptune_cluster_storage_encrypted",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"StorageEncrypted":    true,
						"StatusExtended":      fmt.Sprintf("Neptune cluster %s storage is encrypted at rest.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Neptune",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "neptune_cluster_storage_encrypted",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"StorageEncrypted":    false,
						"StatusExtended":      fmt.Sprintf("Neptune cluster %s storage is not encrypted at rest.", clusterID),
						"SecurityIssues":      []string{"Neptune cluster storage encryption is disabled"},
						"Recommendation":      "Enable storage encryption at rest for the Neptune DB cluster using AWS KMS.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 2. Check backup retention period (neptune_cluster_backup_enabled & neptune_cluster_backup_enabled)
			// PASS if BackupRetentionPeriod != nil && *BackupRetentionPeriod >= 7, FAIL (MEDIUM) if < 7 or nil.
			backupRules := []string{
				"neptune_cluster_backup_enabled",
			}

			hasSufficientBackup := cluster.BackupRetentionPeriod != nil && aws.ToInt32(cluster.BackupRetentionPeriod) >= 7
			retentionDays := aws.ToInt32(cluster.BackupRetentionPeriod)

			if hasSufficientBackup {
				for _, ruleID := range backupRules {
					results = append(results, scanner.ScanResult{
						ResourceID:   clusterID,
						ResourceType: "SecaaS-Neptune",
						Region:       region,
						Status:       "PASS",
						RuleID:       ruleID,
						Severity:     "INFO",
						Metrics: map[string]interface{}{
							"DBClusterIdentifier": clusterID,
							"RetentionPeriodDays": retentionDays,
							"StatusExtended":      fmt.Sprintf("Neptune cluster %s has automated backup retention enabled (%d days retention).", clusterID, retentionDays),
						},
						Nodes: nodes,
						Edges: edges,
					})
				}
			} else {
				var statusMsg string
				if cluster.BackupRetentionPeriod == nil || retentionDays == 0 {
					statusMsg = fmt.Sprintf("Neptune cluster %s does not have automated backups enabled.", clusterID)
				} else {
					statusMsg = fmt.Sprintf("Neptune cluster %s backup retention period (%d days) is less than the required minimum of 7 days.", clusterID, retentionDays)
				}

				for _, ruleID := range backupRules {
					results = append(results, scanner.ScanResult{
						ResourceID:   clusterID,
						ResourceType: "SecaaS-Neptune",
						Region:       region,
						Status:       "FAIL",
						RuleID:       ruleID,
						Severity:     "MEDIUM",
						Metrics: map[string]interface{}{
							"DBClusterIdentifier": clusterID,
							"RetentionPeriodDays": retentionDays,
							"StatusExtended":      statusMsg,
							"SecurityIssues":      []string{"Neptune cluster backup retention period is less than 7 days"},
							"Recommendation":      "Set the backup retention period to at least 7 days for the Neptune DB cluster.",
						},
						Nodes: nodes,
						Edges: edges,
					})
				}
			}
		}
	}

	// 3. Audit Neptune Cluster Snapshots for Public Access (neptune_cluster_public_snapshot - CRITICAL)
	snapPaginator := neptune.NewDescribeDBClusterSnapshotsPaginator(s.client, &neptune.DescribeDBClusterSnapshotsInput{})

	for snapPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		snapPage, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe Neptune cluster snapshots: %w", err)
		}

		for _, snap := range snapPage.DBClusterSnapshots {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			snapID := aws.ToString(snap.DBClusterSnapshotIdentifier)
			if snapID == "" {
				continue
			}

			snapArn := aws.ToString(snap.DBClusterSnapshotArn)
			if snapArn == "" {
				snapArn = fmt.Sprintf("arn:aws:rds:%s::snapshot:%s", region, snapID)
			}

			attrOut, err := s.client.DescribeDBClusterSnapshotAttributes(ctx, &neptune.DescribeDBClusterSnapshotAttributesInput{
				DBClusterSnapshotIdentifier: snap.DBClusterSnapshotIdentifier,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to describe attributes for Neptune cluster snapshot %s: %w", snapID, err)
			}

			isPublic := false
			if attrOut != nil && attrOut.DBClusterSnapshotAttributesResult != nil {
				for _, attr := range attrOut.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes {
					if strings.EqualFold(aws.ToString(attr.AttributeName), "restore") {
						for _, val := range attr.AttributeValues {
							if strings.EqualFold(val, "all") {
								isPublic = true
								break
							}
						}
						if isPublic {
							break
						}
					}
				}
			}

			snapNodes := []graph.Node{{ID: snapArn, NodeType: "SecaaS-Neptune-Snapshot"}}
			var snapEdges []graph.Edge
			if snap.DBClusterIdentifier != nil && aws.ToString(snap.DBClusterIdentifier) != "" {
				clusterID := aws.ToString(snap.DBClusterIdentifier)
				clusterArn, ok := clusterArns[clusterID]
				if !ok {
					clusterArn = fmt.Sprintf("arn:aws:rds:%s::cluster:%s", region, clusterID)
				}
				snapEdges = append(snapEdges, graph.Edge{
					From:     snapArn,
					To:       clusterArn,
					Relation: "SNAPSHOT_OF",
				})
			}

			if isPublic {
				results = append(results, scanner.ScanResult{
					ResourceID:   snapID,
					ResourceType: "SecaaS-Neptune-Snapshot",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "neptune_cluster_public_snapshot",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"DBClusterSnapshotIdentifier": snapID,
						"Public":                      true,
						"StatusExtended":              fmt.Sprintf("Neptune cluster snapshot %s is shared publicly.", snapID),
						"SecurityIssues":              []string{"Neptune cluster snapshot allows public access"},
						"Recommendation":              "Remove public restore access from Neptune cluster snapshots.",
					},
					Nodes: snapNodes,
					Edges: snapEdges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   snapID,
					ResourceType: "SecaaS-Neptune-Snapshot",
					Region:       region,
					Status:       "PASS",
					RuleID:       "neptune_cluster_public_snapshot",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBClusterSnapshotIdentifier": snapID,
						"Public":                      false,
						"StatusExtended":              fmt.Sprintf("Neptune cluster snapshot %s is not shared publicly.", snapID),
					},
					Nodes: snapNodes,
					Edges: snapEdges,
				})
			}
		}
	}

	return results, nil
}
