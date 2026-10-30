package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockKafkaApi struct {
	listClustersFn    func(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error)
	describeClusterFn func(ctx context.Context, params *kafka.DescribeClusterInput, optFns ...func(*kafka.Options)) (*kafka.DescribeClusterOutput, error)
}

func (m *mockKafkaApi) ListClusters(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error) {
	if m.listClustersFn != nil {
		return m.listClustersFn(ctx, params, optFns...)
	}
	return &kafka.ListClustersOutput{}, nil
}

func (m *mockKafkaApi) DescribeCluster(ctx context.Context, params *kafka.DescribeClusterInput, optFns ...func(*kafka.Options)) (*kafka.DescribeClusterOutput, error) {
	if m.describeClusterFn != nil {
		return m.describeClusterFn(ctx, params, optFns...)
	}
	return &kafka.DescribeClusterOutput{}, nil
}

func TestKafkaScanner_Compliant(t *testing.T) {
	clusterName := "msk-prod-cluster"
	clusterArn := "arn:aws:kafka:us-east-1:123456789012:cluster/msk-prod-cluster/abc-123"

	mock := &mockKafkaApi{
		listClustersFn: func(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error) {
			return &kafka.ListClustersOutput{
				ClusterInfoList: []kafkatypes.ClusterInfo{
					{
						ClusterName: aws.String(clusterName),
						ClusterArn:  aws.String(clusterArn),
						BrokerNodeGroupInfo: &kafkatypes.BrokerNodeGroupInfo{
							SecurityGroups: []string{"sg-kafka-001"},
							ConnectivityInfo: &kafkatypes.ConnectivityInfo{
								PublicAccess: &kafkatypes.PublicAccess{
									Type: aws.String("DISABLED"),
								},
							},
						},
						ClientAuthentication: &kafkatypes.ClientAuthentication{
							Tls: &kafkatypes.Tls{
								CertificateAuthorityArnList: []string{"arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/xyz"},
							},
							Unauthenticated: &kafkatypes.Unauthenticated{
								Enabled: aws.Bool(false),
							},
						},
						EncryptionInfo: &kafkatypes.EncryptionInfo{
							EncryptionInTransit: &kafkatypes.EncryptionInTransit{
								ClientBroker: kafkatypes.ClientBrokerTls,
								InCluster:    aws.Bool(true),
							},
							EncryptionAtRest: &kafkatypes.EncryptionAtRest{
								DataVolumeKMSKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"),
							},
						},
					},
				},
			}, nil
		},
	}

	scanner := NewKafkaScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "Kafka-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	expectedRules := map[string]string{
		"kafka_cluster_is_public":                     "PASS",
		"kafka_cluster_unrestricted_access_disabled":  "PASS",
		"kafka_cluster_in_transit_encryption_enabled": "PASS",
		"kafka_cluster_encryption_at_rest_uses_cmk":   "PASS",
	}

	visited := make(map[string]bool)
	for _, r := range results {
		assert.Equal(t, clusterName, r.ResourceID)
		assert.Equal(t, "SecaaS-Kafka", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "INFO", r.Severity)

		expectedStatus, exists := expectedRules[r.RuleID]
		require.True(t, exists, "Unexpected rule %s", r.RuleID)
		assert.Equal(t, expectedStatus, r.Status)
		visited[r.RuleID] = true

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, clusterArn, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-Kafka", r.Nodes[0].NodeType)

		require.Len(t, r.Edges, 1)
		assert.Equal(t, "sg-kafka-001", r.Edges[0].From)
		assert.Equal(t, clusterArn, r.Edges[0].To)
		assert.Equal(t, "ATTACHED_TO", r.Edges[0].Relation)
	}

	assert.Len(t, visited, 4)
}

func TestKafkaScanner_NonCompliant(t *testing.T) {
	clusterName := "msk-insecure-cluster"
	clusterArn := "arn:aws:kafka:us-west-2:123456789012:cluster/msk-insecure-cluster/def-456"

	mock := &mockKafkaApi{
		listClustersFn: func(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error) {
			return &kafka.ListClustersOutput{
				ClusterInfoList: []kafkatypes.ClusterInfo{
					{
						ClusterName: aws.String(clusterName),
						ClusterArn:  aws.String(clusterArn),
						BrokerNodeGroupInfo: &kafkatypes.BrokerNodeGroupInfo{
							ConnectivityInfo: &kafkatypes.ConnectivityInfo{
								PublicAccess: &kafkatypes.PublicAccess{
									Type: aws.String("SERVICE_PROVIDED_EIPS"),
								},
							},
						},
						ClientAuthentication: &kafkatypes.ClientAuthentication{
							Unauthenticated: &kafkatypes.Unauthenticated{
								Enabled: aws.Bool(true),
							},
						},
						EncryptionInfo: &kafkatypes.EncryptionInfo{
							EncryptionInTransit: &kafkatypes.EncryptionInTransit{
								ClientBroker: kafkatypes.ClientBrokerPlaintext,
								InCluster:    aws.Bool(false),
							},
							EncryptionAtRest: &kafkatypes.EncryptionAtRest{
								DataVolumeKMSKeyId: aws.String("arn:aws:kms:us-west-2:123456789012:alias/aws/kafka"),
							},
						},
					},
				},
			}, nil
		},
	}

	scanner := NewKafkaScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	expectedSeverities := map[string]string{
		"kafka_cluster_is_public":                     "CRITICAL",
		"kafka_cluster_unrestricted_access_disabled":  "CRITICAL",
		"kafka_cluster_in_transit_encryption_enabled": "HIGH",
		"kafka_cluster_encryption_at_rest_uses_cmk":   "MEDIUM",
	}

	for _, r := range results {
		assert.Equal(t, clusterName, r.ResourceID)
		assert.Equal(t, "SecaaS-Kafka", r.ResourceType)
		assert.Equal(t, "FAIL", r.Status)

		expectedSev, exists := expectedSeverities[r.RuleID]
		require.True(t, exists)
		assert.Equal(t, expectedSev, r.Severity)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["SecurityIssues"])
		assert.NotEmpty(t, metrics["Recommendation"])
	}
}

func TestKafkaScanner_SaslCompliant(t *testing.T) {
	clusterName := "msk-sasl-cluster"
	clusterArn := "arn:aws:kafka:eu-west-1:123456789012:cluster/msk-sasl-cluster/ghi-789"

	mock := &mockKafkaApi{
		listClustersFn: func(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error) {
			return &kafka.ListClustersOutput{
				ClusterInfoList: []kafkatypes.ClusterInfo{
					{
						ClusterName: aws.String(clusterName),
						ClusterArn:  aws.String(clusterArn),
						ClientAuthentication: &kafkatypes.ClientAuthentication{
							Sasl: &kafkatypes.Sasl{
								Scram: &kafkatypes.Scram{
									Enabled: aws.Bool(true),
								},
							},
							Unauthenticated: nil,
						},
						EncryptionInfo: &kafkatypes.EncryptionInfo{
							EncryptionInTransit: &kafkatypes.EncryptionInTransit{
								ClientBroker: kafkatypes.ClientBrokerTlsPlaintext,
								InCluster:    aws.Bool(true),
							},
							EncryptionAtRest: &kafkatypes.EncryptionAtRest{
								DataVolumeKMSKeyId: aws.String("arn:aws:kms:eu-west-1:123456789012:key/cmk-key"),
							},
						},
					},
				},
			}, nil
		},
	}

	scanner := NewKafkaScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	for _, r := range results {
		if r.RuleID == "kafka_cluster_unrestricted_access_disabled" {
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
		}
		if r.RuleID == "kafka_cluster_in_transit_encryption_enabled" {
			assert.Equal(t, "PASS", r.Status)
		}
		if r.RuleID == "kafka_cluster_encryption_at_rest_uses_cmk" {
			assert.Equal(t, "PASS", r.Status)
		}
	}
}

func TestKafkaScanner_DescribeClusterOverride(t *testing.T) {
	clusterName := "msk-describe-cluster"
	clusterArn := "arn:aws:kafka:us-east-1:123456789012:cluster/msk-describe-cluster/jkl-012"

	mock := &mockKafkaApi{
		listClustersFn: func(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error) {
			return &kafka.ListClustersOutput{
				ClusterInfoList: []kafkatypes.ClusterInfo{
					{
						ClusterName: aws.String(clusterName),
						ClusterArn:  aws.String(clusterArn),
					},
				},
			}, nil
		},
		describeClusterFn: func(ctx context.Context, params *kafka.DescribeClusterInput, optFns ...func(*kafka.Options)) (*kafka.DescribeClusterOutput, error) {
			return &kafka.DescribeClusterOutput{
				ClusterInfo: &kafkatypes.ClusterInfo{
					ClusterName: aws.String(clusterName),
					ClusterArn:  aws.String(clusterArn),
					EncryptionInfo: &kafkatypes.EncryptionInfo{
						EncryptionInTransit: &kafkatypes.EncryptionInTransit{
							ClientBroker: kafkatypes.ClientBrokerTls,
							InCluster:    aws.Bool(true),
						},
						EncryptionAtRest: &kafkatypes.EncryptionAtRest{
							DataVolumeKMSKeyId: aws.String("arn:aws:kms:us-east-1:123456789012:key/custom-key"),
						},
					},
					ClientAuthentication: &kafkatypes.ClientAuthentication{
						Tls: &kafkatypes.Tls{},
					},
				},
			}, nil
		},
	}

	scanner := NewKafkaScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 4)

	for _, r := range results {
		if r.RuleID == "kafka_cluster_in_transit_encryption_enabled" {
			assert.Equal(t, "PASS", r.Status)
		}
		if r.RuleID == "kafka_cluster_unrestricted_access_disabled" {
			assert.Equal(t, "PASS", r.Status)
		}
		if r.RuleID == "kafka_cluster_encryption_at_rest_uses_cmk" {
			assert.Equal(t, "PASS", r.Status)
		}
	}
}

func TestKafkaScanner_ListError(t *testing.T) {
	mock := &mockKafkaApi{
		listClustersFn: func(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error) {
			return nil, errors.New("AWS API throttling error")
		},
	}

	scanner := NewKafkaScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "failed to list MSK clusters")
}


