package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
)

type EKSScanner struct {
	client *eks.Client
}

func NewEKSScanner(cfg aws.Config) *EKSScanner {
	return &EKSScanner{
		client: eks.NewFromConfig(cfg),
	}
}

func (s *EKSScanner) Name() string {
	return "EKS-SecaaS-Scanner"
}

func (s *EKSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := eks.NewListClustersPaginator(s.client, &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, clusterName := range page.Clusters {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			descOutput, err := s.client.DescribeCluster(ctx, &eks.DescribeClusterInput{
				Name: aws.String(clusterName),
			})
			if err != nil {
				return nil, err
			}

			if descOutput.Cluster == nil {
				continue
			}
			cluster := descOutput.Cluster

			isVulnerable := false
			if cluster.ResourcesVpcConfig != nil && cluster.ResourcesVpcConfig.EndpointPublicAccess {
				isVulnerable = true
			}

			metrics := map[string]interface{}{
				"ClusterName":  clusterName,
				"IsVulnerable": isVulnerable,
			}

			severity := "INFO"
			status := "PASS"
			if isVulnerable {
				metrics["SecurityIssues"] = []string{"EKS cluster endpoint has public access enabled without private-only access restrictions"}
				metrics["StatusExtended"] = fmt.Sprintf("EKS cluster %s endpoint has public access enabled without private-only restrictions.", clusterName)
				metrics["Recommendation"] = "Disable public endpoint access for the EKS cluster or restrict access using specific CIDR blocks."
				severity = "HIGH"
				status = "FAIL"
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("EKS cluster %s endpoint does not have public access enabled.", clusterName)
				metrics["Recommendation"] = "Maintain private-only endpoint access for the EKS cluster."
			}

			// Some clusters might not have an ARN string directly as a string type, but AWS Go SDK v2 typically uses *string
			arn := clusterName
			if cluster.Arn != nil {
				arn = aws.ToString(cluster.Arn)
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   arn,
				ResourceType: "SecaaS-EKS",
				Region:       "global", // Matching existing pattern
				Status:       status,
				IsOrphaned:   isVulnerable,
				RuleID:       "eks_cluster_not_publicly_accessible",
				Severity:     severity,
				Metrics:      metrics,
				Nodes:        []graph.Node{{ID: arn, NodeType: "SecaaS-EKS"}},
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *EKSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "eks-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "eks",
		CheckIDs:      []string{"eks_cluster_not_publicly_accessible"},
	}
}
