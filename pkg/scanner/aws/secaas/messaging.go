package secaas

import (
	"context"
	"encoding/json"
	"fmt"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type MessagingScanner struct {
	snsClient *sns.Client
	sqsClient *sqs.Client
	region    string
}

func NewMessagingScanner(cfg aws.Config) *MessagingScanner {
	return &MessagingScanner{
		snsClient: sns.NewFromConfig(cfg),
		sqsClient: sqs.NewFromConfig(cfg),
		region:    cfg.Region,
	}
}

func (s *MessagingScanner) Name() string {
	return "Messaging-SecaaS-Scanner"
}

func (s *MessagingScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult

	sqsResults, err := s.scanSQS(ctx)
	if err != nil {
		return nil, err
	}
	results = append(results, sqsResults...)

	snsResults, err := s.scanSNS(ctx)
	if err != nil {
		return nil, err
	}
	results = append(results, snsResults...)

	return results, nil
}

func (s *MessagingScanner) scanSQS(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := sqs.NewListQueuesPaginator(s.sqsClient, &sqs.ListQueuesInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, queueUrl := range page.QueueUrls {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			// We need a local variable to take the address if we weren't in Go 1.22+, but let's just use aws.String() if needed, wait page.QueueUrls is []string in v2?
			// In aws-sdk-go-v2, QueueUrls is []string
			urlStr := queueUrl

			attrs, err := s.sqsClient.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: aws.String(urlStr),
				AttributeNames: []types.QueueAttributeName{
					types.QueueAttributeNameAll,
				},
			})
			if err != nil {
				continue
			}

			attributes := attrs.Attributes

			// Check SSE
			kmsMasterKeyId := attributes[string(types.QueueAttributeNameKmsMasterKeyId)]
			sqsManagedSseEnabled := attributes["SqsManagedSseEnabled"]
			hasSSE := kmsMasterKeyId != "" || sqsManagedSseEnabled == "true"

			// Check Policy
			policyStr := attributes[string(types.QueueAttributeNamePolicy)]
			hasPublicAccess := hasPublicAccessInPolicy(policyStr)

			// Check DLQ
			redrivePolicy := attributes["RedrivePolicy"]
			hasDLQ := redrivePolicy != ""

			isVulnerable := !hasSSE || hasPublicAccess || !hasDLQ

			var sqsIssues []string
			if !hasSSE {
				sqsIssues = append(sqsIssues, "Server-Side Encryption (SSE) is disabled")
			}
			if hasPublicAccess {
				sqsIssues = append(sqsIssues, "Queue policy grants public or wildcard (*) access")
			}
			if !hasDLQ {
				sqsIssues = append(sqsIssues, "Dead Letter Queue (DLQ) redrive policy is missing")
			}

			metrics := map[string]interface{}{
				"QueueUrl":        urlStr,
				"HasSSE":          hasSSE,
				"HasPublicAccess": hasPublicAccess,
				"HasDLQ":          hasDLQ,
				"IsVulnerable":    isVulnerable,
				"Service":         "SQS",
			}

			severity := "INFO"
			status := "PASS"
			if isVulnerable {
				metrics["SecurityIssues"] = sqsIssues
				metrics["StatusExtended"] = fmt.Sprintf("SQS queue %s does not have server-side encryption enabled or allows unrestricted public access.", urlStr)
				metrics["Recommendation"] = "Enable SSE, remove public/cross-account '*' access in the resource policy, and configure a Dead Letter Queue (DLQ)."
				severity = "HIGH"
				status = "FAIL"
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("SQS queue %s has server-side encryption enabled and restricted access.", urlStr)
				metrics["Recommendation"] = "Maintain SQS encryption and least-privilege access policies."
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   urlStr,
				ResourceType: "SecaaS-Messaging",
				Region:       s.region,
				Status:       status,
				IsOrphaned:   isVulnerable,
				RuleID:       "sqs_queues_server_side_encryption_enabled",
				Severity:     severity,
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       urlStr,
						NodeType: "SecaaS-SQS",
					},
				},
			})
		}
	}
	return results, nil
}

func (s *MessagingScanner) scanSNS(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := sns.NewListTopicsPaginator(s.snsClient, &sns.ListTopicsInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, topic := range page.Topics {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			topicArn := aws.ToString(topic.TopicArn)

			attrs, err := s.snsClient.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{
				TopicArn: topic.TopicArn,
			})
			if err != nil {
				continue
			}

			attributes := attrs.Attributes

			// Check SSE
			kmsMasterKeyId := attributes["KmsMasterKeyId"]
			hasSSE := kmsMasterKeyId != ""

			// Check Policy
			policyStr := attributes["Policy"]
			hasPublicAccess := hasPublicAccessInPolicy(policyStr)
			hasForcedHTTPS := hasForcedHTTPSInPolicy(policyStr)

			isVulnerable := !hasSSE || hasPublicAccess || !hasForcedHTTPS

			var snsIssues []string
			if !hasSSE {
				snsIssues = append(snsIssues, "Server-Side Encryption (SSE) is disabled")
			}
			if hasPublicAccess {
				snsIssues = append(snsIssues, "Topic policy grants public or wildcard (*) access")
			}
			if !hasForcedHTTPS {
				snsIssues = append(snsIssues, "HTTPS-only transport is not enforced in topic policy")
			}

			metrics := map[string]interface{}{
				"TopicArn":        topicArn,
				"HasSSE":          hasSSE,
				"HasPublicAccess": hasPublicAccess,
				"HasForcedHTTPS":  hasForcedHTTPS,
				"IsVulnerable":    isVulnerable,
				"Service":         "SNS",
			}
			severity := "INFO"
			status := "PASS"
			if isVulnerable {
				metrics["SecurityIssues"] = snsIssues
				metrics["StatusExtended"] = fmt.Sprintf("SNS topic %s does not have KMS encryption at rest enabled or allows unrestricted public access.", topicArn)
				metrics["Recommendation"] = "Enable SSE, remove public/cross-account '*' access in the resource policy, and enforce HTTPS delivery."
				severity = "HIGH"
				status = "FAIL"
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("SNS topic %s has KMS encryption at rest enabled and restricted access.", topicArn)
				metrics["Recommendation"] = "Maintain SNS KMS encryption and least-privilege access policies."
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   topicArn,
				ResourceType: "SecaaS-Messaging",
				Region:       s.region,
				Status:       status,
				IsOrphaned:   isVulnerable,
				RuleID:       "sns_topics_kms_encryption_at_rest_enabled",
				Severity:     severity,
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       topicArn,
						NodeType: "SecaaS-SNS",
					},
				},
			})
		}
	}
	return results, nil
}

func hasPublicAccessInPolicy(policyStr string) bool {
	if policyStr == "" {
		return false
	}
	var policy struct {
		Statement []struct {
			Effect    string      `json:"Effect"`
			Principal interface{} `json:"Principal"`
		} `json:"Statement"`
	}
	err := json.Unmarshal([]byte(policyStr), &policy)
	if err != nil {
		return false
	}
	for _, stmt := range policy.Statement {
		if stmt.Effect == "Allow" {
			switch p := stmt.Principal.(type) {
			case string:
				if p == "*" {
					return true
				}
			case map[string]interface{}:
				for _, v := range p {
					switch vStr := v.(type) {
					case string:
						if vStr == "*" {
							return true
						}
					case []interface{}:
						for _, item := range vStr {
							if s, ok := item.(string); ok && s == "*" {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func hasForcedHTTPSInPolicy(policyStr string) bool {
	if policyStr == "" {
		return false
	}
	var policy struct {
		Statement []struct {
			Effect    string                            `json:"Effect"`
			Condition map[string]map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}
	err := json.Unmarshal([]byte(policyStr), &policy)
	if err != nil {
		return false
	}
	for _, stmt := range policy.Statement {
		if stmt.Effect == "Deny" {
			if boolConds, ok := stmt.Condition["Bool"]; ok {
				if val, ok := boolConds["aws:SecureTransport"]; ok {
					if vStr, isStr := val.(string); isStr && (vStr == "false" || vStr == "False") {
						return true
					}
					if vBool, isBool := val.(bool); isBool && !vBool {
						return true
					}
				}
			}
		}
	}
	return false
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *MessagingScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "messaging-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "messaging",
		CheckIDs:      []string{"sns_topics_kms_encryption_at_rest_enabled", "sqs_queues_server_side_encryption_enabled"},
	}
}
