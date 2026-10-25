package secaas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSClient defines the interface for AWS KMS operations.
type KMSClient interface {
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyPolicy(ctx context.Context, params *kms.GetKeyPolicyInput, optFns ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

type KMSScanner struct {
	client KMSClient
	region string
}

func NewKMSScanner(cfg aws.Config) *KMSScanner {
	return &KMSScanner{
		client: kms.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

func NewKMSScannerWithClient(client KMSClient, region string) *KMSScanner {
	return &KMSScanner{
		client: client,
		region: region,
	}
}

func (s *KMSScanner) Name() string {
	return "KMS-SecaaS-Scanner"
}

func (s *KMSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	paginator := kms.NewListKeysPaginator(s.client, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range page.Keys {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			keyId := aws.ToString(key.KeyId)
			keyArn := aws.ToString(key.KeyArn)

			// Describe Key to check KeyManager (AWS vs CUSTOMER)
			descOut, err := s.client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: aws.String(keyId),
			})
			if err != nil || descOut.KeyMetadata == nil {
				continue
			}

			meta := descOut.KeyMetadata
			// Skip AWS managed keys (aws/s3, aws/ebs, etc.) - CIS only applies to Customer Managed Keys (CMKs)
			if meta.KeyManager == kmstypes.KeyManagerTypeAws {
				continue
			}

			// 1. Key Rotation Status (kms_cmk_rotation_enabled - CIS 2.8 / SOC 2 - MEDIUM)
			rotOut, err := s.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: aws.String(keyId),
			})
			rotationEnabled := err == nil && rotOut.KeyRotationEnabled
			if rotationEnabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   keyId,
					ResourceType: "SecaaS-KMSKey",
					Region:       region,
					Status:       "PASS",
					RuleID:       "kms_cmk_rotation_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"KeyId":          keyId,
						"StatusExtended": fmt.Sprintf("KMS customer-managed key %s has annual automatic rotation enabled.", keyId),
					},
					Nodes: []graph.Node{{ID: keyArn, NodeType: "SecaaS-KMSKey"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   keyId,
					ResourceType: "SecaaS-KMSKey",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "kms_cmk_rotation_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"KeyId":          keyId,
						"StatusExtended": fmt.Sprintf("KMS customer-managed key %s does not have automatic key rotation enabled.", keyId),
						"SecurityIssues": []string{"Key rotation is disabled for customer-managed CMK"},
						"Recommendation": "Enable automatic annual key rotation for customer managed KMS keys.",
					},
					Nodes: []graph.Node{{ID: keyArn, NodeType: "SecaaS-KMSKey"}},
				})
			}

			// 2. Overly Permissive / Public Policy (kms_key_not_publicly_accessible - CRITICAL)
			policyOut, err := s.client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
				KeyId:      aws.String(keyId),
				PolicyName: aws.String("default"),
			})
			if err != nil {
				continue
			}

			policyStr := aws.ToString(policyOut.Policy)
			isPublic := false

			var policyDoc map[string]interface{}
			if err := json.Unmarshal([]byte(policyStr), &policyDoc); err == nil {
				if statements, ok := policyDoc["Statement"].([]interface{}); ok {
					for _, stmtIntf := range statements {
						if stmt, ok := stmtIntf.(map[string]interface{}); ok {
							if effect, ok := stmt["Effect"].(string); ok && effect == "Allow" {
								if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
									if awsPrincipal, ok := principal["AWS"]; ok {
										if awsStr, ok := awsPrincipal.(string); ok && awsStr == "*" {
											if _, hasCondition := stmt["Condition"]; !hasCondition {
												isPublic = true
											}
										}
									}
								} else if principalStr, ok := stmt["Principal"].(string); ok && principalStr == "*" {
									if _, hasCondition := stmt["Condition"]; !hasCondition {
										isPublic = true
									}
								}
							}
						}
					}
				}
			} else {
				if strings.Contains(policyStr, `"Principal": "*"`) || strings.Contains(policyStr, `"AWS": "*"`) {
					isPublic = true
				}
			}

			if isPublic {
				results = append(results, scanner.ScanResult{
					ResourceID:   keyId,
					ResourceType: "SecaaS-KMSKey",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "kms_key_not_publicly_accessible",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"KeyId":          keyId,
						"StatusExtended": fmt.Sprintf("KMS Key %s policy allows wildcard (*) public principal access without conditions.", keyId),
						"SecurityIssues": []string{"KMS Key policy exposes key publicly (*)"},
						"Recommendation": "Restrict KMS Key policy to specific IAM principals within your AWS account.",
					},
					Nodes: []graph.Node{{ID: keyArn, NodeType: "SecaaS-KMSKey"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   keyId,
					ResourceType: "SecaaS-KMSKey",
					Region:       region,
					Status:       "PASS",
					RuleID:       "kms_key_not_publicly_accessible",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"KeyId":          keyId,
						"StatusExtended": fmt.Sprintf("KMS Key %s policy is restricted and not exposed publicly.", keyId),
					},
					Nodes: []graph.Node{{ID: keyArn, NodeType: "SecaaS-KMSKey"}},
				})
			}
		}
	}

	return results, nil
}
