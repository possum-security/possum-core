package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
)

// DocDBApi defines the mockable interface for Amazon DocumentDB API operations.
type DocDBApi interface {
	DescribeDBClusters(ctx context.Context, params *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
	DescribeDBClusterSnapshots(ctx context.Context, params *docdb.DescribeDBClusterSnapshotsInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterSnapshotsOutput, error)
	DescribeDBClusterSnapshotAttributes(ctx context.Context, params *docdb.DescribeDBClusterSnapshotAttributesInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterSnapshotAttributesOutput, error)
}

// DocumentDBScanner evaluates Amazon DocumentDB cluster security postures.
type DocumentDBScanner struct {
	client DocDBApi
	region string
}

// NewDocumentDBScanner creates a DocumentDBScanner with the provided AWS config.
func NewDocumentDBScanner(cfg aws.Config) *DocumentDBScanner {
	return &DocumentDBScanner{
		client: docdb.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewDocumentDBScannerWithClient creates a DocumentDBScanner with a custom/mock client.
func NewDocumentDBScannerWithClient(client DocDBApi, region string) *DocumentDBScanner {
	return &DocumentDBScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *DocumentDBScanner) Name() string {
	return "DocumentDB-SecaaS-Scanner"
}

// Scan audits all DocumentDB clusters and manual snapshots in the configured region against security best practices.
func (s *DocumentDBScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	// 1. Audit DocumentDB Clusters
	paginator := docdb.NewDescribeDBClustersPaginator(s.client, &docdb.DescribeDBClustersInput{})
	clusterArns := make(map[string]string)

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DocumentDB clusters: %w", err)
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

			nodes := []graph.Node{{ID: clusterArn, NodeType: "SecaaS-DocumentDB"}}

			// Check 1: Storage encryption (documentdb_cluster_storage_encrypted - HIGH)
			// StorageEncrypted == true -> PASS, else FAIL
			if aws.ToBool(cluster.StorageEncrypted) {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "PASS",
					RuleID:       "documentdb_cluster_storage_encrypted",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"StorageEncrypted":    true,
						"StatusExtended":      fmt.Sprintf("DocumentDB cluster %s storage is encrypted at rest.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "documentdb_cluster_storage_encrypted",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"StorageEncrypted":    false,
						"StatusExtended":      fmt.Sprintf("DocumentDB cluster %s storage is not encrypted at rest.", clusterID),
						"SecurityIssues":      []string{"DocumentDB cluster storage encryption is disabled"},
						"Recommendation":      "Enable storage encryption at rest for the DocumentDB cluster using AWS KMS.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// Check 2: Automated backup retention (documentdb_cluster_backup_enabled - MEDIUM)
			// BackupRetentionPeriod != nil && *BackupRetentionPeriod >= 7 -> PASS, else FAIL
			hasSufficientBackup := cluster.BackupRetentionPeriod != nil && aws.ToInt32(cluster.BackupRetentionPeriod) >= 7
			retentionDays := aws.ToInt32(cluster.BackupRetentionPeriod)

			if hasSufficientBackup {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "PASS",
					RuleID:       "documentdb_cluster_backup_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"RetentionPeriodDays": retentionDays,
						"StatusExtended":      fmt.Sprintf("DocumentDB cluster %s has automated backup retention enabled (%d days retention).", clusterID, retentionDays),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				var statusMsg string
				if cluster.BackupRetentionPeriod == nil || retentionDays == 0 {
					statusMsg = fmt.Sprintf("DocumentDB cluster %s does not have automated backups enabled.", clusterID)
				} else {
					statusMsg = fmt.Sprintf("DocumentDB cluster %s backup retention period (%d days) is less than the required minimum of 7 days.", clusterID, retentionDays)
				}
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "documentdb_cluster_backup_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"RetentionPeriodDays": retentionDays,
						"StatusExtended":      statusMsg,
						"SecurityIssues":      []string{"DocumentDB cluster backup retention period is less than 7 days"},
						"Recommendation":      "Set the backup retention period to at least 7 days for the DocumentDB cluster.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// Check 3: Deletion protection (documentdb_cluster_deletion_protection - MEDIUM)
			// DeletionProtection == true -> PASS, else FAIL
			if aws.ToBool(cluster.DeletionProtection) {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "PASS",
					RuleID:       "documentdb_cluster_deletion_protection",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"DeletionProtection":  true,
						"StatusExtended":      fmt.Sprintf("DocumentDB cluster %s has deletion protection enabled.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "documentdb_cluster_deletion_protection",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"DBClusterIdentifier": clusterID,
						"DeletionProtection":  false,
						"StatusExtended":      fmt.Sprintf("DocumentDB cluster %s does not have deletion protection enabled.", clusterID),
						"SecurityIssues":      []string{"DocumentDB cluster deletion protection is disabled"},
						"Recommendation":      "Enable deletion protection for the DocumentDB cluster to prevent accidental deletion.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}
		}
	}

	// 2. Audit DocumentDB Manual Snapshots for Public Access (documentdb_cluster_public_snapshot - CRITICAL)
	snapPaginator := docdb.NewDescribeDBClusterSnapshotsPaginator(s.client, &docdb.DescribeDBClusterSnapshotsInput{
		SnapshotType: aws.String("manual"),
	})

	for snapPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		snapPage, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe DocumentDB cluster snapshots: %w", err)
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

			if snap.SnapshotType != nil && !strings.EqualFold(aws.ToString(snap.SnapshotType), "manual") {
				continue
			}

			snapArn := aws.ToString(snap.DBClusterSnapshotArn)
			if snapArn == "" {
				snapArn = fmt.Sprintf("arn:aws:rds:%s::snapshot:%s", region, snapID)
			}

			attrOut, err := s.client.DescribeDBClusterSnapshotAttributes(ctx, &docdb.DescribeDBClusterSnapshotAttributesInput{
				DBClusterSnapshotIdentifier: snap.DBClusterSnapshotIdentifier,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to describe attributes for DocumentDB snapshot %s: %w", snapID, err)
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

			snapNodes := []graph.Node{{ID: snapArn, NodeType: "SecaaS-DocumentDB"}}
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
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "documentdb_cluster_public_snapshot",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"DBClusterSnapshotIdentifier": snapID,
						"Public":                      true,
						"StatusExtended":              fmt.Sprintf("DocumentDB manual cluster snapshot %s is shared publicly.", snapID),
						"SecurityIssues":              []string{"DocumentDB cluster manual snapshot is publicly accessible"},
						"Recommendation":              "Modify the DocumentDB cluster snapshot attributes to remove public restore permissions ('all').",
					},
					Nodes: snapNodes,
					Edges: snapEdges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   snapID,
					ResourceType: "SecaaS-DocumentDB",
					Region:       region,
					Status:       "PASS",
					RuleID:       "documentdb_cluster_public_snapshot",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBClusterSnapshotIdentifier": snapID,
						"Public":                      false,
						"StatusExtended":              fmt.Sprintf("DocumentDB manual cluster snapshot %s is not shared publicly.", snapID),
					},
					Nodes: snapNodes,
					Edges: snapEdges,
				})
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *DocumentDBScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "documentdb-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "documentdb",
		CheckIDs:      []string{"documentdb_cluster_backup_enabled", "documentdb_cluster_deletion_protection", "documentdb_cluster_public_snapshot", "documentdb_cluster_storage_encrypted"},
	}
}
