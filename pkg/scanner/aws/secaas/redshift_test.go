package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRedshiftClient struct {
	describeClustersOutput      *redshift.DescribeClustersOutput
	describeLoggingStatusOutput *redshift.DescribeLoggingStatusOutput
	describeLoggingStatusMap    map[string]*redshift.DescribeLoggingStatusOutput
	describeClustersErr         error
	describeLoggingStatusErr    error
}

func (m *mockRedshiftClient) DescribeClusters(ctx context.Context, params *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	if m.describeClustersErr != nil {
		return nil, m.describeClustersErr
	}
	return m.describeClustersOutput, nil
}

func (m *mockRedshiftClient) DescribeLoggingStatus(ctx context.Context, params *redshift.DescribeLoggingStatusInput, optFns ...func(*redshift.Options)) (*redshift.DescribeLoggingStatusOutput, error) {
	if m.describeLoggingStatusErr != nil {
		return nil, m.describeLoggingStatusErr
	}
	if m.describeLoggingStatusMap != nil && params != nil && params.ClusterIdentifier != nil {
		if out, ok := m.describeLoggingStatusMap[*params.ClusterIdentifier]; ok {
			return out, nil
		}
	}
	return m.describeLoggingStatusOutput, nil
}

func TestRedshiftScanner_Compliant(t *testing.T) {
	clusterID := "analytics-prod-cluster"
	mock := &mockRedshiftClient{
		describeClustersOutput: &redshift.DescribeClustersOutput{
			Clusters: []redshifttypes.Cluster{
				{
					ClusterIdentifier:  aws.String(clusterID),
					Encrypted:          aws.Bool(true),
					PubliclyAccessible: aws.Bool(false),
					VpcSecurityGroups: []redshifttypes.VpcSecurityGroupMembership{
						{VpcSecurityGroupId: aws.String("sg-0123456789abcdef0")},
					},
				},
			},
		},
		describeLoggingStatusOutput: &redshift.DescribeLoggingStatusOutput{
			LoggingEnabled: aws.Bool(true),
			BucketName:     aws.String("my-redshift-audit-bucket"),
		},
	}

	scanner := NewRedshiftScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "Redshift-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	expectedRuleIDs := map[string]bool{
		"redshift_cluster_encrypted_at_rest": false,
		"redshift_cluster_audit_logging":     false,
		"redshift_cluster_public_access":     false,
	}

	for _, r := range results {
		assert.Equal(t, clusterID, r.ResourceID)
		assert.Equal(t, "SecaaS-Redshift", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)

		require.Contains(t, expectedRuleIDs, r.RuleID)
		expectedRuleIDs[r.RuleID] = true

		// Check Metrics
		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		// Check Nodes & Edges
		require.Len(t, r.Nodes, 1)
		assert.Equal(t, "arn:aws:redshift:us-east-1::cluster:analytics-prod-cluster", r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-Redshift", r.Nodes[0].NodeType)

		require.Len(t, r.Edges, 1)
		assert.Equal(t, "sg-0123456789abcdef0", r.Edges[0].From)
		assert.Equal(t, "arn:aws:redshift:us-east-1::cluster:analytics-prod-cluster", r.Edges[0].To)
		assert.Equal(t, "ATTACHED_TO", r.Edges[0].Relation)
	}

	for ruleID, visited := range expectedRuleIDs {
		assert.True(t, visited, "Rule %s was not emitted", ruleID)
	}
}

func TestRedshiftScanner_NonCompliant(t *testing.T) {
	clusterID := "dev-insecure-cluster"
	mock := &mockRedshiftClient{
		describeClustersOutput: &redshift.DescribeClustersOutput{
			Clusters: []redshifttypes.Cluster{
				{
					ClusterIdentifier:  aws.String(clusterID),
					Encrypted:          aws.Bool(false),
					PubliclyAccessible: aws.Bool(true),
				},
			},
		},
		describeLoggingStatusOutput: &redshift.DescribeLoggingStatusOutput{
			LoggingEnabled: aws.Bool(false),
		},
	}

	scanner := NewRedshiftScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	ruleSeverities := map[string]string{
		"redshift_cluster_encrypted_at_rest": "HIGH",
		"redshift_cluster_audit_logging":     "MEDIUM",
		"redshift_cluster_public_access":     "HIGH",
	}

	for _, r := range results {
		assert.Equal(t, clusterID, r.ResourceID)
		assert.Equal(t, "SecaaS-Redshift", r.ResourceType)
		assert.Equal(t, "eu-west-1", r.Region)
		assert.Equal(t, "FAIL", r.Status)

		expectedSev, exists := ruleSeverities[r.RuleID]
		require.True(t, exists, "Unexpected RuleID: %s", r.RuleID)
		assert.Equal(t, expectedSev, r.Severity, "Severity mismatch for rule: %s", r.RuleID)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])

		issues, ok := metrics["SecurityIssues"].([]string)
		require.True(t, ok)
		assert.NotEmpty(t, issues)

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, "arn:aws:redshift:eu-west-1::cluster:dev-insecure-cluster", r.Nodes[0].ID)
	}
}

func TestRedshiftScanner_LoggingError(t *testing.T) {
	clusterID := "cluster-with-log-err"
	mock := &mockRedshiftClient{
		describeClustersOutput: &redshift.DescribeClustersOutput{
			Clusters: []redshifttypes.Cluster{
				{
					ClusterIdentifier:  aws.String(clusterID),
					Encrypted:          aws.Bool(true),
					PubliclyAccessible: aws.Bool(false),
				},
			},
		},
		describeLoggingStatusErr: errors.New("access denied for DescribeLoggingStatus"),
	}

	scanner := NewRedshiftScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 3)

	for _, r := range results {
		if r.RuleID == "redshift_cluster_audit_logging" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
		} else {
			assert.Equal(t, "PASS", r.Status)
		}
	}
}

func TestRedshiftScanner_DescribeClustersError(t *testing.T) {
	mock := &mockRedshiftClient{
		describeClustersErr: errors.New("AWS API rate exceeded"),
	}

	scanner := NewRedshiftScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestRedshiftScanner_Empty(t *testing.T) {
	mock := &mockRedshiftClient{
		describeClustersOutput: &redshift.DescribeClustersOutput{
			Clusters: []redshifttypes.Cluster{},
		},
	}

	scanner := NewRedshiftScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestRedshiftScanner_ResourceLimit(t *testing.T) {
	mock := &mockRedshiftClient{
		describeClustersOutput: &redshift.DescribeClustersOutput{
			Clusters: []redshifttypes.Cluster{
				{
					ClusterIdentifier:  aws.String("cluster-1"),
					Encrypted:          aws.Bool(true),
					PubliclyAccessible: aws.Bool(false),
				},
				{
					ClusterIdentifier:  aws.String("cluster-2"),
					Encrypted:          aws.Bool(true),
					PubliclyAccessible: aws.Bool(false),
				},
			},
		},
		describeLoggingStatusOutput: &redshift.DescribeLoggingStatusOutput{
			LoggingEnabled: aws.Bool(true),
		},
	}

	scanner := NewRedshiftScannerWithClient(mock, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)

	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	// 3 checks for 1 cluster because limit is 1
	assert.Len(t, results, 3)
	assert.Equal(t, "cluster-1", results[0].ResourceID)
}


