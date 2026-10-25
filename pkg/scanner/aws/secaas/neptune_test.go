package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNeptuneClient struct {
	describeDBClustersOutput                  *neptune.DescribeDBClustersOutput
	describeDBClusterSnapshotsOutput          *neptune.DescribeDBClusterSnapshotsOutput
	describeDBClusterSnapshotAttributesOutput *neptune.DescribeDBClusterSnapshotAttributesOutput
	err                                       error
	snapshotsErr                              error
	attributesErr                             error
}

func (m *mockNeptuneClient) DescribeDBClusters(ctx context.Context, params *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.describeDBClustersOutput != nil {
		return m.describeDBClustersOutput, nil
	}
	return &neptune.DescribeDBClustersOutput{}, nil
}

func (m *mockNeptuneClient) DescribeDBClusterSnapshots(ctx context.Context, params *neptune.DescribeDBClusterSnapshotsInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClusterSnapshotsOutput, error) {
	if m.snapshotsErr != nil {
		return nil, m.snapshotsErr
	}
	if m.describeDBClusterSnapshotsOutput != nil {
		return m.describeDBClusterSnapshotsOutput, nil
	}
	return &neptune.DescribeDBClusterSnapshotsOutput{}, nil
}

func (m *mockNeptuneClient) DescribeDBClusterSnapshotAttributes(ctx context.Context, params *neptune.DescribeDBClusterSnapshotAttributesInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClusterSnapshotAttributesOutput, error) {
	if m.attributesErr != nil {
		return nil, m.attributesErr
	}
	if m.describeDBClusterSnapshotAttributesOutput != nil {
		return m.describeDBClusterSnapshotAttributesOutput, nil
	}
	return &neptune.DescribeDBClusterSnapshotAttributesOutput{}, nil
}

func TestNeptuneScanner_Compliant(t *testing.T) {
	clusterID := "neptune-graph-prod"
	clusterArn := "arn:aws:rds:us-east-1:123456789012:cluster:neptune-graph-prod"
	mock := &mockNeptuneClient{
		describeDBClustersOutput: &neptune.DescribeDBClustersOutput{
			DBClusters: []neptunetypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String(clusterID),
					DBClusterArn:          aws.String(clusterArn),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: aws.Int32(7),
					VpcSecurityGroups: []neptunetypes.VpcSecurityGroupMembership{
						{VpcSecurityGroupId: aws.String("sg-neptune-001")},
					},
				},
			},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "Neptune-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	expectedRules := map[string]bool{
		"neptune_cluster_storage_encrypted": false,
		"neptune_cluster_backup_enabled":    false,
	}

	for _, r := range results {
		assert.Equal(t, clusterID, r.ResourceID)
		assert.Equal(t, "SecaaS-Neptune", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)

		require.Contains(t, expectedRules, r.RuleID)
		expectedRules[r.RuleID] = true

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, clusterArn, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-Neptune", r.Nodes[0].NodeType)

		require.Len(t, r.Edges, 1)
		assert.Equal(t, "sg-neptune-001", r.Edges[0].From)
		assert.Equal(t, clusterArn, r.Edges[0].To)
		assert.Equal(t, "ATTACHED_TO", r.Edges[0].Relation)
	}

	for ruleID, visited := range expectedRules {
		assert.True(t, visited, "Rule %s was not emitted", ruleID)
	}
}

func TestNeptuneScanner_NonCompliant(t *testing.T) {
	clusterID := "neptune-dev-insecure"
	mock := &mockNeptuneClient{
		describeDBClustersOutput: &neptune.DescribeDBClustersOutput{
			DBClusters: []neptunetypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String(clusterID),
					StorageEncrypted:      aws.Bool(false),
					BackupRetentionPeriod: aws.Int32(3), // Less than 7 days
				},
			},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "ap-southeast-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	ruleSeverities := map[string]string{
		"neptune_cluster_storage_encrypted": "HIGH",
		"neptune_cluster_backup_enabled":    "MEDIUM",
	}

	for _, r := range results {
		assert.Equal(t, clusterID, r.ResourceID)
		assert.Equal(t, "SecaaS-Neptune", r.ResourceType)
		assert.Equal(t, "ap-southeast-1", r.Region)
		assert.Equal(t, "FAIL", r.Status)

		expectedSev, exists := ruleSeverities[r.RuleID]
		require.True(t, exists, "Unexpected rule: %s", r.RuleID)
		assert.Equal(t, expectedSev, r.Severity, "Severity mismatch for rule %s", r.RuleID)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])

		issues, ok := metrics["SecurityIssues"].([]string)
		require.True(t, ok)
		assert.NotEmpty(t, issues)

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, "arn:aws:rds:ap-southeast-1::cluster:neptune-dev-insecure", r.Nodes[0].ID)
	}
}

func TestNeptuneScanner_NilBackupRetention(t *testing.T) {
	clusterID := "neptune-no-backup"
	mock := &mockNeptuneClient{
		describeDBClustersOutput: &neptune.DescribeDBClustersOutput{
			DBClusters: []neptunetypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String(clusterID),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: nil,
				},
			},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	for _, r := range results {
		if r.RuleID == "neptune_cluster_storage_encrypted" {
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
		} else {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
		}
	}
}

func TestNeptuneScanner_DescribeDBClustersError(t *testing.T) {
	mock := &mockNeptuneClient{
		err: errors.New("Neptune service unavailable"),
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestNeptuneScanner_Empty(t *testing.T) {
	mock := &mockNeptuneClient{
		describeDBClustersOutput: &neptune.DescribeDBClustersOutput{
			DBClusters: []neptunetypes.DBCluster{},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestNeptuneScanner_ResourceLimit(t *testing.T) {
	mock := &mockNeptuneClient{
		describeDBClustersOutput: &neptune.DescribeDBClustersOutput{
			DBClusters: []neptunetypes.DBCluster{
				{
					DBClusterIdentifier:   aws.String("neptune-1"),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: aws.Int32(7),
				},
				{
					DBClusterIdentifier:   aws.String("neptune-2"),
					StorageEncrypted:      aws.Bool(true),
					BackupRetentionPeriod: aws.Int32(7),
				},
			},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)

	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	// 2 checks for 1 cluster
	assert.Len(t, results, 2)
	assert.Equal(t, "neptune-1", results[0].ResourceID)
}

func TestNeptuneScanner_Constructor(t *testing.T) {
	cfg := aws.Config{Region: "eu-central-1"}
	s := NewNeptuneScanner(cfg)
	assert.NotNil(t, s)
	assert.Equal(t, "Neptune-SecaaS-Scanner", s.Name())
	assert.Equal(t, "eu-central-1", s.region)
}

func TestNeptuneScanner_ClusterSnapshot_Public_FAIL(t *testing.T) {
	snapID := "neptune-snap-public-01"
	snapArn := "arn:aws:rds:us-east-1:123456789012:snapshot:neptune-snap-public-01"
	clusterID := "neptune-cluster-1"

	mock := &mockNeptuneClient{
		describeDBClusterSnapshotsOutput: &neptune.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []neptunetypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String(snapID),
					DBClusterSnapshotArn:        aws.String(snapArn),
					DBClusterIdentifier:         aws.String(clusterID),
				},
			},
		},
		describeDBClusterSnapshotAttributesOutput: &neptune.DescribeDBClusterSnapshotAttributesOutput{
			DBClusterSnapshotAttributesResult: &neptunetypes.DBClusterSnapshotAttributesResult{
				DBClusterSnapshotIdentifier: aws.String(snapID),
				DBClusterSnapshotAttributes: []neptunetypes.DBClusterSnapshotAttribute{
					{
						AttributeName:   aws.String("restore"),
						AttributeValues: []string{"all"},
					},
				},
			},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, snapID, r.ResourceID)
	assert.Equal(t, "SecaaS-Neptune-Snapshot", r.ResourceType)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "FAIL", r.Status)
	assert.Equal(t, "CRITICAL", r.Severity)
	assert.Equal(t, "neptune_cluster_public_snapshot", r.RuleID)

	metrics, ok := r.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, metrics["Public"])
	assert.Equal(t, "Remove public restore access from Neptune cluster snapshots.", metrics["Recommendation"])
}

func TestNeptuneScanner_ClusterSnapshot_Private_PASS(t *testing.T) {
	snapID := "neptune-snap-private-01"
	snapArn := "arn:aws:rds:us-east-1:123456789012:snapshot:neptune-snap-private-01"
	clusterID := "neptune-cluster-1"

	mock := &mockNeptuneClient{
		describeDBClusterSnapshotsOutput: &neptune.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []neptunetypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String(snapID),
					DBClusterSnapshotArn:        aws.String(snapArn),
					DBClusterIdentifier:         aws.String(clusterID),
				},
			},
		},
		describeDBClusterSnapshotAttributesOutput: &neptune.DescribeDBClusterSnapshotAttributesOutput{
			DBClusterSnapshotAttributesResult: &neptunetypes.DBClusterSnapshotAttributesResult{
				DBClusterSnapshotIdentifier: aws.String(snapID),
				DBClusterSnapshotAttributes: []neptunetypes.DBClusterSnapshotAttribute{
					{
						AttributeName:   aws.String("restore"),
						AttributeValues: []string{"123456789012"},
					},
				},
			},
		},
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, snapID, r.ResourceID)
	assert.Equal(t, "SecaaS-Neptune-Snapshot", r.ResourceType)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "PASS", r.Status)
	assert.Equal(t, "INFO", r.Severity)
	assert.Equal(t, "neptune_cluster_public_snapshot", r.RuleID)

	metrics, ok := r.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, metrics["Public"])
}

func TestNeptuneScanner_ClusterSnapshot_SnapshotsError(t *testing.T) {
	mock := &mockNeptuneClient{
		snapshotsErr: errors.New("failed to describe cluster snapshots"),
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestNeptuneScanner_ClusterSnapshot_AttributesError(t *testing.T) {
	mock := &mockNeptuneClient{
		describeDBClusterSnapshotsOutput: &neptune.DescribeDBClusterSnapshotsOutput{
			DBClusterSnapshots: []neptunetypes.DBClusterSnapshot{
				{
					DBClusterSnapshotIdentifier: aws.String("snap-01"),
				},
			},
		},
		attributesErr: errors.New("failed to describe attributes"),
	}

	scanner := NewNeptuneScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}
