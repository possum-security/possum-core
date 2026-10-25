package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDocDBClient struct {
	describeDBClustersOutput                  *docdb.DescribeDBClustersOutput
	describeDBClustersErr                     error
	describeDBClusterSnapshotsOutput          *docdb.DescribeDBClusterSnapshotsOutput
	describeDBClusterSnapshotsErr             error
	describeDBClusterSnapshotAttributesOutput *docdb.DescribeDBClusterSnapshotAttributesOutput
	describeDBClusterSnapshotAttributesErr    error
}

func (m *mockDocDBClient) DescribeDBClusters(ctx context.Context, params *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error) {
	if m.describeDBClustersErr != nil {
		return nil, m.describeDBClustersErr
	}
	if m.describeDBClustersOutput == nil {
		return &docdb.DescribeDBClustersOutput{}, nil
	}
	return m.describeDBClustersOutput, nil
}

func (m *mockDocDBClient) DescribeDBClusterSnapshots(ctx context.Context, params *docdb.DescribeDBClusterSnapshotsInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterSnapshotsOutput, error) {
	if m.describeDBClusterSnapshotsErr != nil {
		return nil, m.describeDBClusterSnapshotsErr
	}
	if m.describeDBClusterSnapshotsOutput == nil {
		return &docdb.DescribeDBClusterSnapshotsOutput{}, nil
	}
	return m.describeDBClusterSnapshotsOutput, nil
}

func (m *mockDocDBClient) DescribeDBClusterSnapshotAttributes(ctx context.Context, params *docdb.DescribeDBClusterSnapshotAttributesInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterSnapshotAttributesOutput, error) {
	if m.describeDBClusterSnapshotAttributesErr != nil {
		return nil, m.describeDBClusterSnapshotAttributesErr
	}
	if m.describeDBClusterSnapshotAttributesOutput == nil {
		return &docdb.DescribeDBClusterSnapshotAttributesOutput{}, nil
	}
	return m.describeDBClusterSnapshotAttributesOutput, nil
}

func TestDocumentDBScanner_Compliant(t *testing.T) {
	clusterID := "docdb-prod-cluster"
	clusterArn := "arn:aws:rds:us-east-1:123456789012:cluster:docdb-prod-cluster"
	snapID := "docdb-prod-snapshot"
	snapArn := "arn:aws:rds:us-east-1:123456789012:snapshot:docdb-prod-snapshot"

	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{
			DBClusters: []docdbtypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String(clusterID),
					DBClusterArn:          aws.String(clusterArn),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: aws.Int32(7),
					DeletionProtection:    aws.Bool(true),
					VpcSecurityGroups: []docdbtypes.VpcSecurityGroupMembership{
						{VpcSecurityGroupId: aws.String("sg-docdb-01")},
					},
				},
			},
		},
		describeDBClusterSnapshotsOutput: &docdb.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []docdbtypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String(snapID),
					DBClusterSnapshotArn:        aws.String(snapArn),
					DBClusterIdentifier:         aws.String(clusterID),
					SnapshotType:                aws.String("manual"),
				},
			},
		},
		describeDBClusterSnapshotAttributesOutput: &docdb.DescribeDBClusterSnapshotAttributesOutput{
			DBClusterSnapshotAttributesResult: &docdbtypes.DBClusterSnapshotAttributesResult{
				DBClusterSnapshotIdentifier: aws.String(snapID),
				DBClusterSnapshotAttributes: []docdbtypes.DBClusterSnapshotAttribute{
					{
						AttributeName:   aws.String("restore"),
						AttributeValues: []string{"111222333444"},
					},
				},
			},
		},
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "DocumentDB-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	expectedRules := map[string]bool{
		"documentdb_cluster_storage_encrypted":   false,
		"documentdb_cluster_backup_enabled":      false,
		"documentdb_cluster_deletion_protection": false,
		"documentdb_cluster_public_snapshot":     false,
	}

	for _, r := range results {
		assert.Equal(t, "SecaaS-DocumentDB", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)

		require.Contains(t, expectedRules, r.RuleID)
		expectedRules[r.RuleID] = true

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		if r.RuleID == "documentdb_cluster_public_snapshot" {
			assert.Equal(t, snapID, r.ResourceID)
			require.Len(t, r.Nodes, 1)
			assert.Equal(t, snapArn, r.Nodes[0].ID)
			require.Len(t, r.Edges, 1)
			assert.Equal(t, snapArn, r.Edges[0].From)
			assert.Equal(t, clusterArn, r.Edges[0].To)
			assert.Equal(t, "SNAPSHOT_OF", r.Edges[0].Relation)
		} else {
			assert.Equal(t, clusterID, r.ResourceID)
			require.Len(t, r.Nodes, 1)
			assert.Equal(t, clusterArn, r.Nodes[0].ID)
			require.Len(t, r.Edges, 1)
			assert.Equal(t, "sg-docdb-01", r.Edges[0].From)
			assert.Equal(t, clusterArn, r.Edges[0].To)
			assert.Equal(t, "ATTACHED_TO", r.Edges[0].Relation)
		}
	}

	for ruleID, visited := range expectedRules {
		assert.True(t, visited, "Rule %s was not emitted", ruleID)
	}
}

func TestDocumentDBScanner_NonCompliant(t *testing.T) {
	clusterID := "docdb-insecure-cluster"
	snapID := "docdb-public-snapshot"

	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{
			DBClusters: []docdbtypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String(clusterID),
					StorageEncrypted:      aws.Bool(false),
					BackupRetentionPeriod: aws.Int32(2), // Less than 7
					DeletionProtection:    aws.Bool(false),
				},
			},
		},
		describeDBClusterSnapshotsOutput: &docdb.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []docdbtypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String(snapID),
					DBClusterIdentifier:         aws.String(clusterID),
					SnapshotType:                aws.String("manual"),
				},
			},
		},
		describeDBClusterSnapshotAttributesOutput: &docdb.DescribeDBClusterSnapshotAttributesOutput{
			DBClusterSnapshotAttributesResult: &docdbtypes.DBClusterSnapshotAttributesResult{
				DBClusterSnapshotIdentifier: aws.String(snapID),
				DBClusterSnapshotAttributes: []docdbtypes.DBClusterSnapshotAttribute{
					{
						AttributeName:   aws.String("restore"),
						AttributeValues: []string{"all"},
					},
				},
			},
		},
	}

	scanner := NewDocumentDBScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	expectedSeverities := map[string]string{
		"documentdb_cluster_storage_encrypted":   "HIGH",
		"documentdb_cluster_backup_enabled":      "MEDIUM",
		"documentdb_cluster_deletion_protection": "MEDIUM",
		"documentdb_cluster_public_snapshot":     "CRITICAL",
	}

	for _, r := range results {
		assert.Equal(t, "SecaaS-DocumentDB", r.ResourceType)
		assert.Equal(t, "eu-west-1", r.Region)
		assert.Equal(t, "FAIL", r.Status)

		expectedSev, exists := expectedSeverities[r.RuleID]
		require.True(t, exists, "Unexpected rule: %s", r.RuleID)
		assert.Equal(t, expectedSev, r.Severity, "Severity mismatch for rule %s", r.RuleID)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])

		issues, ok := metrics["SecurityIssues"].([]string)
		require.True(t, ok)
		assert.NotEmpty(t, issues)
	}
}

func TestDocumentDBScanner_NilBackupRetention(t *testing.T) {
	clusterID := "docdb-no-backup"
	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{
			DBClusters: []docdbtypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String(clusterID),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: nil,
					DeletionProtection:    aws.Bool(true),
				},
			},
		},
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	for _, r := range results {
		if r.RuleID == "documentdb_cluster_backup_enabled" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
		} else {
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
		}
	}
}

func TestDocumentDBScanner_DescribeDBClustersError(t *testing.T) {
	mock := &mockDocDBClient{
		describeDBClustersErr: errors.New("DocumentDB service unavailable"),
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestDocumentDBScanner_DescribeDBClusterSnapshotsError(t *testing.T) {
	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{
			DBClusters: []docdbtypes.DBCluster{},
		},
		describeDBClusterSnapshotsErr: errors.New("Snapshot access denied"),
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestDocumentDBScanner_DescribeDBClusterSnapshotAttributesError(t *testing.T) {
	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{
			DBClusters: []docdbtypes.DBCluster{},
		},
		describeDBClusterSnapshotsOutput: &docdb.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []docdbtypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String("snap-01"),
					SnapshotType:                aws.String("manual"),
				},
			},
		},
		describeDBClusterSnapshotAttributesErr: errors.New("Snapshot attribute error"),
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestDocumentDBScanner_Empty(t *testing.T) {
	mock := &mockDocDBClient{
		describeDBClustersOutput:         &docdb.DescribeDBClustersOutput{DBClusters: []docdbtypes.DBCluster{}},
		describeDBClusterSnapshotsOutput: &docdb.DescribeDBClusterSnapshotsOutput{DBClusterSnapshots: []docdbtypes.DBClusterSnapshot{}},
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestDocumentDBScanner_ResourceLimit(t *testing.T) {
	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{
			DBClusters: []docdbtypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String("docdb-1"),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: aws.Int32(7),
					DeletionProtection:    aws.Bool(true),
				},
				{
					DBClusterIdentifier:   aws.String("docdb-2"),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: aws.Int32(7),
					DeletionProtection:    aws.Bool(true),
				},
			},
		},
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	// Only 1 cluster processed -> 3 rules emitted
	assert.Len(t, results, 3)
}

func TestDocumentDBScanner_SkipsNonManualSnapshots(t *testing.T) {
	mock := &mockDocDBClient{
		describeDBClustersOutput: &docdb.DescribeDBClustersOutput{},
		describeDBClusterSnapshotsOutput: &docdb.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []docdbtypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String("auto-snap"),
					SnapshotType:                aws.String("automated"),
				},
			},
		},
	}

	scanner := NewDocumentDBScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}
