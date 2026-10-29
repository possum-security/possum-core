package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kafka/types"
)

// KafkaApi defines the mockable interface for Amazon MSK API operations.
type KafkaApi interface {
	ListClusters(ctx context.Context, params *kafka.ListClustersInput, optFns ...func(*kafka.Options)) (*kafka.ListClustersOutput, error)
	DescribeCluster(ctx context.Context, params *kafka.DescribeClusterInput, optFns ...func(*kafka.Options)) (*kafka.DescribeClusterOutput, error)
}

// KafkaScanner evaluates Amazon Managed Streaming for Apache Kafka (MSK) cluster security postures.
type KafkaScanner struct {
	client KafkaApi
	region string
}

// NewKafkaScanner creates a KafkaScanner with the provided AWS config.
func NewKafkaScanner(cfg aws.Config) *KafkaScanner {
	return &KafkaScanner{
		client: kafka.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewKafkaScannerWithClient creates a KafkaScanner with a custom/mock client.
func NewKafkaScannerWithClient(client KafkaApi, region string) *KafkaScanner {
	return &KafkaScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *KafkaScanner) Name() string {
	return "Kafka-SecaaS-Scanner"
}

// Scan audits all MSK clusters in the configured region against security best practices.
func (s *KafkaScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := kafka.NewListClustersPaginator(s.client, &kafka.ListClustersInput{})

	for paginator.HasMorePages() {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list MSK clusters: %w", err)
		}

		for _, cluster := range page.ClusterInfoList {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++

			clusterInfo := &cluster
			if cluster.ClusterArn != nil {
				desc, err := s.client.DescribeCluster(ctx, &kafka.DescribeClusterInput{
					ClusterArn: cluster.ClusterArn,
				})
				if err == nil && desc != nil && desc.ClusterInfo != nil {
					clusterInfo = desc.ClusterInfo
				}
			}

			clusterID := aws.ToString(clusterInfo.ClusterName)
			if clusterID == "" {
				clusterID = aws.ToString(clusterInfo.ClusterArn)
			}
			clusterArn := aws.ToString(clusterInfo.ClusterArn)
			if clusterArn == "" {
				clusterArn = fmt.Sprintf("arn:aws:kafka:%s::cluster/%s", region, clusterID)
			}
			if clusterID == "" {
				clusterID = clusterArn
			}

			var edges []graph.Edge
			if clusterInfo.BrokerNodeGroupInfo != nil {
				for _, sgID := range clusterInfo.BrokerNodeGroupInfo.SecurityGroups {
					if sgID != "" {
						edges = append(edges, graph.Edge{
							From:     sgID,
							To:       clusterArn,
							Relation: "ATTACHED_TO",
						})
					}
				}
			}

			nodes := []graph.Node{{ID: clusterArn, NodeType: "SecaaS-Kafka"}}

			// 1. Check public access (kafka_cluster_is_public - CRITICAL)
			// If PublicAccess.Type == "SERVICE_PROVIDED_EIPS": FAIL, else PASS
			isPublic := false
			var publicAccessType string
			if clusterInfo.BrokerNodeGroupInfo != nil &&
				clusterInfo.BrokerNodeGroupInfo.ConnectivityInfo != nil &&
				clusterInfo.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess != nil {
				publicAccessType = aws.ToString(clusterInfo.BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type)
				if publicAccessType == "SERVICE_PROVIDED_EIPS" {
					isPublic = true
				}
			}

			if isPublic {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "kafka_cluster_is_public",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"ClusterName":      clusterID,
						"PublicAccessType": publicAccessType,
						"StatusExtended":   fmt.Sprintf("MSK cluster %s is publicly accessible via service-provided Elastic IPs.", clusterID),
						"SecurityIssues":   []string{"MSK cluster is configured with public access"},
						"Recommendation":   "Disable public access for the MSK cluster to restrict access to VPC internal subnets.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "PASS",
					RuleID:       "kafka_cluster_is_public",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ClusterName":      clusterID,
						"PublicAccessType": publicAccessType,
						"StatusExtended":   fmt.Sprintf("MSK cluster %s is not publicly accessible.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 2. Check unrestricted access (kafka_cluster_unrestricted_access_disabled - CRITICAL)
			// If ClientAuthentication != nil && (Sasl != nil || Tls != nil) && (Unauthenticated == nil || !*Unauthenticated.Enabled): PASS, else FAIL
			unrestrictedAccessDisabled := false
			ca := clusterInfo.ClientAuthentication
			if ca != nil {
				hasSaslOrTls := ca.Sasl != nil || ca.Tls != nil
				unauthenticatedDisabled := ca.Unauthenticated == nil || !aws.ToBool(ca.Unauthenticated.Enabled)
				if hasSaslOrTls && unauthenticatedDisabled {
					unrestrictedAccessDisabled = true
				}
			}

			if unrestrictedAccessDisabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "PASS",
					RuleID:       "kafka_cluster_unrestricted_access_disabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ClusterName":    clusterID,
						"StatusExtended": fmt.Sprintf("MSK cluster %s enforces authentication (SASL or TLS) and disables unauthenticated access.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "kafka_cluster_unrestricted_access_disabled",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"ClusterName":    clusterID,
						"StatusExtended": fmt.Sprintf("MSK cluster %s allows unauthenticated access or lacks SASL/TLS authentication.", clusterID),
						"SecurityIssues": []string{"MSK cluster allows unauthenticated client access or lacks authentication"},
						"Recommendation": "Configure SASL (SCRAM or IAM) or mutual TLS client authentication and disable unauthenticated access.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 3. Check in-transit encryption (kafka_cluster_in_transit_encryption_enabled - HIGH)
			// If EncryptionInfo.EncryptionInTransit.ClientBroker != "PLAINTEXT" && InCluster == true: PASS, else FAIL
			inTransitEncrypted := false
			var clientBroker types.ClientBroker
			var inCluster bool
			if clusterInfo.EncryptionInfo != nil && clusterInfo.EncryptionInfo.EncryptionInTransit != nil {
				eit := clusterInfo.EncryptionInfo.EncryptionInTransit
				clientBroker = eit.ClientBroker
				inCluster = aws.ToBool(eit.InCluster)
				if string(clientBroker) != "PLAINTEXT" && inCluster {
					inTransitEncrypted = true
				}
			}

			if inTransitEncrypted {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "PASS",
					RuleID:       "kafka_cluster_in_transit_encryption_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ClusterName":    clusterID,
						"ClientBroker":   string(clientBroker),
						"InCluster":      inCluster,
						"StatusExtended": fmt.Sprintf("MSK cluster %s has encryption in transit enabled.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "kafka_cluster_in_transit_encryption_enabled",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"ClusterName":    clusterID,
						"ClientBroker":   string(clientBroker),
						"InCluster":      inCluster,
						"StatusExtended": fmt.Sprintf("MSK cluster %s does not enforce encryption in transit for client-broker or in-cluster communication.", clusterID),
						"SecurityIssues": []string{"In-transit encryption is disabled or set to PLAINTEXT"},
						"Recommendation": "Configure client-broker encryption to TLS and enable in-cluster encryption.",
					},
					Nodes: nodes,
					Edges: edges,
				})
			}

			// 4. Check encryption at rest uses CMK (kafka_cluster_encryption_at_rest_uses_cmk - MEDIUM)
			// If EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId != "" && !strings.Contains(DataVolumeKMSKeyId, "alias/aws/"): PASS, else FAIL
			usesCMK := false
			var keyID string
			if clusterInfo.EncryptionInfo != nil && clusterInfo.EncryptionInfo.EncryptionAtRest != nil {
				keyID = aws.ToString(clusterInfo.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId)
				if keyID != "" && !strings.Contains(keyID, "alias/aws/") {
					usesCMK = true
				}
			}

			if usesCMK {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "PASS",
					RuleID:       "kafka_cluster_encryption_at_rest_uses_cmk",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"ClusterName":        clusterID,
						"DataVolumeKMSKeyId": keyID,
						"StatusExtended":     fmt.Sprintf("MSK cluster %s uses a customer managed KMS key for data volume encryption at rest.", clusterID),
					},
					Nodes: nodes,
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   clusterID,
					ResourceType: "SecaaS-Kafka",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "kafka_cluster_encryption_at_rest_uses_cmk",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"ClusterName":        clusterID,
						"DataVolumeKMSKeyId": keyID,
						"StatusExtended":     fmt.Sprintf("MSK cluster %s does not use a customer managed KMS key for data volume encryption at rest.", clusterID),
						"SecurityIssues":     []string{"MSK cluster data volume is not encrypted with a customer managed KMS key"},
						"Recommendation":     "Encrypt MSK cluster data volumes using a customer managed KMS key instead of AWS managed keys.",
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
func (s *KafkaScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "kafka-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "kafka",
		CheckIDs:      []string{"kafka_cluster_encryption_at_rest_uses_cmk", "kafka_cluster_in_transit_encryption_enabled", "kafka_cluster_is_public", "kafka_cluster_unrestricted_access_disabled"},
	}
}
