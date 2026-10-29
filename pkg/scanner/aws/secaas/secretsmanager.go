package secaas

import (
	"context"
	"fmt"
	"strings"
	"time"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// SecretsManagerClient defines the interface for AWS Secrets Manager operations.
type SecretsManagerClient interface {
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetResourcePolicy(ctx context.Context, params *secretsmanager.GetResourcePolicyInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
}

// SecretsManagerScanner evaluates Secrets Manager secret rotation and exposure.
type SecretsManagerScanner struct {
	client SecretsManagerClient
	region string
}

// NewSecretsManagerScanner creates a SecretsManagerScanner with AWS config.
func NewSecretsManagerScanner(cfg aws.Config) *SecretsManagerScanner {
	return &SecretsManagerScanner{
		client: secretsmanager.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewSecretsManagerScannerWithClient creates a scanner with custom/mock client.
func NewSecretsManagerScannerWithClient(client SecretsManagerClient, region string) *SecretsManagerScanner {
	return &SecretsManagerScanner{
		client: client,
		region: region,
	}
}

func (s *SecretsManagerScanner) Name() string {
	return "SecretsManager-SecaaS-Scanner"
}

func (s *SecretsManagerScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
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

	paginator := secretsmanager.NewListSecretsPaginator(s.client, &secretsmanager.ListSecretsInput{})

	now := time.Now()
	ninetyDaysAgo := now.AddDate(0, 0, -90)

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}

		for _, secret := range page.SecretList {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			secretName := aws.ToString(secret.Name)
			secretArn := aws.ToString(secret.ARN)

			// 1. Automatic rotation (secretsmanager_automatic_rotation_enabled - MEDIUM)
			rotationEnabled := aws.ToBool(secret.RotationEnabled)
			if rotationEnabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   secretName,
					ResourceType: "SecaaS-Secret",
					Region:       region,
					Status:       "PASS",
					RuleID:       "secretsmanager_automatic_rotation_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"SecretName":     secretName,
						"StatusExtended": fmt.Sprintf("Secrets Manager secret %s has automatic rotation enabled.", secretName),
					},
					Nodes: []graph.Node{{ID: secretArn, NodeType: "SecaaS-Secret"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   secretName,
					ResourceType: "SecaaS-Secret",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "secretsmanager_automatic_rotation_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"SecretName":     secretName,
						"StatusExtended": fmt.Sprintf("Secrets Manager secret %s does not have automatic rotation enabled.", secretName),
						"SecurityIssues": []string{"Secret automatic rotation is disabled"},
						"Recommendation": "Enable automatic secret rotation using an AWS Lambda rotation function.",
					},
					Nodes: []graph.Node{{ID: secretArn, NodeType: "SecaaS-Secret"}},
				})
			}

			// 2. Rotated within 90 days (secretsmanager_secret_rotated_periodically - MEDIUM)
			lastRotated := secret.LastRotatedDate
			if lastRotated == nil {
				lastRotated = secret.CreatedDate
			}

			isRecentlyRotated := lastRotated != nil && lastRotated.After(ninetyDaysAgo)
			if isRecentlyRotated {
				results = append(results, scanner.ScanResult{
					ResourceID:   secretName,
					ResourceType: "SecaaS-Secret",
					Region:       region,
					Status:       "PASS",
					RuleID:       "secretsmanager_secret_rotated_periodically",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"SecretName":     secretName,
						"LastRotated":    lastRotated.Format(time.RFC3339),
						"StatusExtended": fmt.Sprintf("Secrets Manager secret %s was rotated within the last 90 days.", secretName),
					},
					Nodes: []graph.Node{{ID: secretArn, NodeType: "SecaaS-Secret"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   secretName,
					ResourceType: "SecaaS-Secret",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "secretsmanager_secret_rotated_periodically",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"SecretName":     secretName,
						"StatusExtended": fmt.Sprintf("Secrets Manager secret %s has not been rotated within the last 90 days.", secretName),
						"SecurityIssues": []string{"Secret not rotated in over 90 days"},
						"Recommendation": "Rotate this secret immediately and configure a rotation schedule.",
					},
					Nodes: []graph.Node{{ID: secretArn, NodeType: "SecaaS-Secret"}},
				})
			}

			// 3. Not publicly accessible (secretsmanager_not_publicly_accessible - CRITICAL)
			isPublic := false
			policyOut, err := s.client.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{
				SecretId: aws.String(secretName),
			})
			if err == nil && policyOut.ResourcePolicy != nil {
				pText := aws.ToString(policyOut.ResourcePolicy)
				if (strings.Contains(pText, `"Principal":"*"`) || strings.Contains(pText, `"Principal": "*"`) ||
					strings.Contains(pText, `"AWS":"*"`) || strings.Contains(pText, `"AWS": "*"`)) &&
					!strings.Contains(pText, `"Condition"`) {
					isPublic = true
				}
			}

			if isPublic {
				results = append(results, scanner.ScanResult{
					ResourceID:   secretName,
					ResourceType: "SecaaS-Secret",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "secretsmanager_not_publicly_accessible",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"SecretName":     secretName,
						"StatusExtended": fmt.Sprintf("Secrets Manager secret %s resource policy allows public access (*).", secretName),
						"SecurityIssues": []string{"Secret policy allows unrestricted public access"},
						"Recommendation": "Remove wildcard (*) principals from the secret resource policy.",
					},
					Nodes: []graph.Node{{ID: secretArn, NodeType: "SecaaS-Secret"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   secretName,
					ResourceType: "SecaaS-Secret",
					Region:       region,
					Status:       "PASS",
					RuleID:       "secretsmanager_not_publicly_accessible",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"SecretName":     secretName,
						"StatusExtended": fmt.Sprintf("Secrets Manager secret %s is not publicly accessible.", secretName),
					},
					Nodes: []graph.Node{{ID: secretArn, NodeType: "SecaaS-Secret"}},
				})
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *SecretsManagerScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "secretsmanager-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "secretsmanager",
		CheckIDs:      []string{"secretsmanager_automatic_rotation_enabled", "secretsmanager_not_publicly_accessible", "secretsmanager_secret_rotated_periodically"},
	}
}
