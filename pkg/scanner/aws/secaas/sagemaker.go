package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
)

// SageMakerClient defines the interface for SageMaker API operations.
type SageMakerClient interface {
	ListNotebookInstances(ctx context.Context, params *sagemaker.ListNotebookInstancesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error)
	DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error)
}

// SageMakerScanner evaluates SageMaker notebook instance security posture.
type SageMakerScanner struct {
	client SageMakerClient
	region string
}

// NewSageMakerScanner creates a new SageMakerScanner with AWS config.
func NewSageMakerScanner(cfg aws.Config) *SageMakerScanner {
	return &SageMakerScanner{
		client: sagemaker.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewSageMakerScannerWithClient creates a scanner with custom/mock client.
func NewSageMakerScannerWithClient(client SageMakerClient, region string) *SageMakerScanner {
	return &SageMakerScanner{
		client: client,
		region: region,
	}
}

func (s *SageMakerScanner) Name() string {
	return "SageMaker-SecaaS-Scanner"
}

func (s *SageMakerScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := sagemaker.NewListNotebookInstancesPaginator(s.client, &sagemaker.ListNotebookInstancesInput{})
	for paginator.HasMorePages() {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list SageMaker notebook instances: %w", err)
		}

		for _, instance := range page.NotebookInstances {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++

			desc, err := s.client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
				NotebookInstanceName: instance.NotebookInstanceName,
			})
			if err != nil || desc == nil {
				continue
			}

			notebookName := aws.ToString(desc.NotebookInstanceName)
			if notebookName == "" {
				notebookName = aws.ToString(instance.NotebookInstanceName)
			}
			notebookArn := aws.ToString(desc.NotebookInstanceArn)
			if notebookArn == "" {
				notebookArn = aws.ToString(instance.NotebookInstanceArn)
			}
			resourceID := notebookArn
			if resourceID == "" {
				resourceID = notebookName
			}

			node := graph.Node{
				ID:       resourceID,
				NodeType: "SecaaS-SageMakerNotebookInstance",
			}

			// 1. VPC Settings Configured (sagemaker_notebook_instance_vpc_settings_configured & sagemaker_notebook_instance_vpc_settings_configured - HIGH)
			insideVPC := desc.SubnetId != nil && *desc.SubnetId != ""
			vpcRuleIDs := []string{
				"sagemaker_notebook_instance_vpc_settings_configured",
				"sagemaker_notebook_instance_vpc_settings_configured",
			}
			for _, ruleID := range vpcRuleIDs {
				if insideVPC {
					results = append(results, scanner.ScanResult{
						ResourceID:   resourceID,
						ResourceType: "SecaaS-SageMakerNotebookInstance",
						Region:       region,
						Status:       "PASS",
						RuleID:       ruleID,
						Severity:     "INFO",
						Metrics: map[string]interface{}{
							"NotebookInstanceName": notebookName,
							"SubnetId":             *desc.SubnetId,
							"StatusExtended":       fmt.Sprintf("SageMaker notebook instance %s is configured inside VPC with Subnet %s.", notebookName, *desc.SubnetId),
						},
						Nodes: []graph.Node{node},
					})
				} else {
					results = append(results, scanner.ScanResult{
						ResourceID:   resourceID,
						ResourceType: "SecaaS-SageMakerNotebookInstance",
						Region:       region,
						Status:       "FAIL",
						RuleID:       ruleID,
						Severity:     "HIGH",
						Metrics: map[string]interface{}{
							"NotebookInstanceName": notebookName,
							"StatusExtended":       fmt.Sprintf("SageMaker notebook instance %s is not configured inside a VPC.", notebookName),
							"SecurityIssues":       []string{"SageMaker notebook instance is not configured inside a VPC"},
							"Recommendation":       "Configure VPC settings (SubnetId and SecurityGroups) for the SageMaker notebook instance to ensure network isolation.",
						},
						Nodes: []graph.Node{node},
					})
				}
			}

			// 2. Encryption Enabled (sagemaker_notebook_instance_encryption_enabled & sagemaker_notebook_instance_encryption_enabled - HIGH)
			kmsEncrypted := desc.KmsKeyId != nil && *desc.KmsKeyId != ""
			kmsRuleIDs := []string{
				"sagemaker_notebook_instance_encryption_enabled",
				"sagemaker_notebook_instance_encryption_enabled",
			}
			for _, ruleID := range kmsRuleIDs {
				if kmsEncrypted {
					results = append(results, scanner.ScanResult{
						ResourceID:   resourceID,
						ResourceType: "SecaaS-SageMakerNotebookInstance",
						Region:       region,
						Status:       "PASS",
						RuleID:       ruleID,
						Severity:     "INFO",
						Metrics: map[string]interface{}{
							"NotebookInstanceName": notebookName,
							"KmsKeyId":             *desc.KmsKeyId,
							"StatusExtended":       fmt.Sprintf("SageMaker notebook instance %s is encrypted with KMS key %s.", notebookName, *desc.KmsKeyId),
						},
						Nodes: []graph.Node{node},
					})
				} else {
					results = append(results, scanner.ScanResult{
						ResourceID:   resourceID,
						ResourceType: "SecaaS-SageMakerNotebookInstance",
						Region:       region,
						Status:       "FAIL",
						RuleID:       ruleID,
						Severity:     "HIGH",
						Metrics: map[string]interface{}{
							"NotebookInstanceName": notebookName,
							"StatusExtended":       fmt.Sprintf("SageMaker notebook instance %s is not encrypted with a KMS key.", notebookName),
							"SecurityIssues":       []string{"SageMaker notebook instance storage is not encrypted with a KMS key"},
							"Recommendation":       "Configure a customer-managed KMS key (KmsKeyId) to encrypt data at rest on SageMaker notebook instance storage.",
						},
						Nodes: []graph.Node{node},
					})
				}
			}

			// 3. Root Access Disabled (sagemaker_notebook_instance_root_access_disabled - MEDIUM)
			rootAccessDisabled := desc.RootAccess == sagemakertypes.RootAccessDisabled
			if rootAccessDisabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-SageMakerNotebookInstance",
					Region:       region,
					Status:       "PASS",
					RuleID:       "sagemaker_notebook_instance_root_access_disabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"NotebookInstanceName": notebookName,
						"StatusExtended":       fmt.Sprintf("SageMaker notebook instance %s has root access disabled.", notebookName),
					},
					Nodes: []graph.Node{node},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-SageMakerNotebookInstance",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "sagemaker_notebook_instance_root_access_disabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"NotebookInstanceName": notebookName,
						"StatusExtended":       fmt.Sprintf("SageMaker notebook instance %s does not have root access disabled.", notebookName),
						"SecurityIssues":       []string{"SageMaker notebook instance has root access enabled"},
						"Recommendation":       "Disable root access on the SageMaker notebook instance to prevent users from obtaining root privileges.",
					},
					Nodes: []graph.Node{node},
				})
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *SageMakerScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "sagemaker-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "sagemaker",
		CheckIDs:      []string{"sagemaker_notebook_instance_root_access_disabled"},
	}
}
