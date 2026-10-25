package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockElastiCacheClient struct {
	describeReplicationGroupsOutput *elasticache.DescribeReplicationGroupsOutput
	err                             error
}

func (m *mockElastiCacheClient) DescribeReplicationGroups(ctx context.Context, params *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.describeReplicationGroupsOutput == nil {
		return &elasticache.DescribeReplicationGroupsOutput{}, nil
	}
	return m.describeReplicationGroupsOutput, nil
}

func TestElastiCacheScanner_Compliant(t *testing.T) {
	rgID := "redis-prod-cluster"
	rgArn := "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:redis-prod-cluster"

	mock := &mockElastiCacheClient{
		describeReplicationGroupsOutput: &elasticache.DescribeReplicationGroupsOutput{
			ReplicationGroups: []elasticachetypes.ReplicationGroup{
				{
					ReplicationGroupId:       aws.String(rgID),
					ARN:                      aws.String(rgArn),
					TransitEncryptionEnabled: aws.Bool(true),
					AtRestEncryptionEnabled:  aws.Bool(true),
					SnapshotRetentionLimit:   aws.Int32(7),
					AutoMinorVersionUpgrade:  aws.Bool(true),
					MemberClusters:           []string{"redis-prod-001", "redis-prod-002"},
				},
			},
		},
	}

	scanner := NewElastiCacheScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "ElastiCache-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	expectedRules := map[string]bool{
		"elasticache_redis_cluster_in_transit_encryption_enabled": false,
		"elasticache_redis_cluster_rest_encryption_enabled":       false,
		"elasticache_redis_cluster_backup_enabled":                false,
		"elasticache_redis_cluster_auto_minor_version_upgrades":   false,
	}

	for _, r := range results {
		assert.Equal(t, rgID, r.ResourceID)
		assert.Equal(t, "SecaaS-ElastiCache", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)

		require.Contains(t, expectedRules, r.RuleID)
		expectedRules[r.RuleID] = true

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, rgArn, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-ElastiCache", r.Nodes[0].NodeType)

		require.Len(t, r.Edges, 2)
		assert.Equal(t, "redis-prod-001", r.Edges[0].From)
		assert.Equal(t, rgArn, r.Edges[0].To)
		assert.Equal(t, "MEMBER_OF", r.Edges[0].Relation)
	}

	for ruleID, visited := range expectedRules {
		assert.True(t, visited, "Rule %s was not emitted", ruleID)
	}
}

func TestElastiCacheScanner_NonCompliant(t *testing.T) {
	rgID := "redis-dev-insecure"

	mock := &mockElastiCacheClient{
		describeReplicationGroupsOutput: &elasticache.DescribeReplicationGroupsOutput{
			ReplicationGroups: []elasticachetypes.ReplicationGroup{
				{
					ReplicationGroupId:       aws.String(rgID),
					TransitEncryptionEnabled: aws.Bool(false),
					AtRestEncryptionEnabled:  aws.Bool(false),
					SnapshotRetentionLimit:   aws.Int32(0),
					AutoMinorVersionUpgrade:  aws.Bool(false),
				},
			},
		},
	}

	scanner := NewElastiCacheScannerWithClient(mock, "ap-southeast-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	expectedSeverities := map[string]string{
		"elasticache_redis_cluster_in_transit_encryption_enabled": "HIGH",
		"elasticache_redis_cluster_rest_encryption_enabled":       "HIGH",
		"elasticache_redis_cluster_backup_enabled":                "MEDIUM",
		"elasticache_redis_cluster_auto_minor_version_upgrades":   "LOW",
	}

	for _, r := range results {
		assert.Equal(t, rgID, r.ResourceID)
		assert.Equal(t, "SecaaS-ElastiCache", r.ResourceType)
		assert.Equal(t, "ap-southeast-1", r.Region)
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

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, "arn:aws:elasticache:ap-southeast-1::replicationgroup:redis-dev-insecure", r.Nodes[0].ID)
	}
}

func TestElastiCacheScanner_NilSnapshotRetention(t *testing.T) {
	rgID := "redis-nil-backup"

	mock := &mockElastiCacheClient{
		describeReplicationGroupsOutput: &elasticache.DescribeReplicationGroupsOutput{
			ReplicationGroups: []elasticachetypes.ReplicationGroup{
				{
					ReplicationGroupId:       aws.String(rgID),
					TransitEncryptionEnabled: aws.Bool(true),
					AtRestEncryptionEnabled:  aws.Bool(true),
					SnapshotRetentionLimit:   nil,
					AutoMinorVersionUpgrade:  aws.Bool(true),
				},
			},
		},
	}

	scanner := NewElastiCacheScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	for _, r := range results {
		if r.RuleID == "elasticache_redis_cluster_backup_enabled" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
		} else {
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
		}
	}
}

func TestElastiCacheScanner_DescribeReplicationGroupsError(t *testing.T) {
	mock := &mockElastiCacheClient{
		err: errors.New("ElastiCache service unavailable"),
	}

	scanner := NewElastiCacheScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestElastiCacheScanner_Empty(t *testing.T) {
	mock := &mockElastiCacheClient{
		describeReplicationGroupsOutput: &elasticache.DescribeReplicationGroupsOutput{
			ReplicationGroups: []elasticachetypes.ReplicationGroup{},
		},
	}

	scanner := NewElastiCacheScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestElastiCacheScanner_ResourceLimit(t *testing.T) {
	mock := &mockElastiCacheClient{
		describeReplicationGroupsOutput: &elasticache.DescribeReplicationGroupsOutput{
			ReplicationGroups: []elasticachetypes.ReplicationGroup{
				{
					ReplicationGroupId:       aws.String("redis-1"),
					TransitEncryptionEnabled: aws.Bool(true),
					AtRestEncryptionEnabled:  aws.Bool(true),
					SnapshotRetentionLimit:   aws.Int32(7),
					AutoMinorVersionUpgrade:  aws.Bool(true),
				},
				{
					ReplicationGroupId:       aws.String("redis-2"),
					TransitEncryptionEnabled: aws.Bool(true),
					AtRestEncryptionEnabled:  aws.Bool(true),
					SnapshotRetentionLimit:   aws.Int32(7),
					AutoMinorVersionUpgrade:  aws.Bool(true),
				},
			},
		},
	}

	scanner := NewElastiCacheScannerWithClient(mock, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	// Only 1 replication group processed -> 4 rules emitted
	assert.Len(t, results, 4)
}
