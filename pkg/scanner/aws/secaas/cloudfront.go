package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// CloudFrontClient defines the mockable interface for AWS CloudFront operations.
type CloudFrontClient interface {
	ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	GetDistributionConfig(ctx context.Context, params *cloudfront.GetDistributionConfigInput, optFns ...func(*cloudfront.Options)) (*cloudfront.GetDistributionConfigOutput, error)
}

type CloudFrontScanner struct {
	client CloudFrontClient
}

func NewCloudFrontScanner(cfg aws.Config) *CloudFrontScanner {
	return &CloudFrontScanner{
		client: cloudfront.NewFromConfig(cfg),
	}
}

func NewCloudFrontScannerWithClient(client CloudFrontClient) *CloudFrontScanner {
	return &CloudFrontScanner{
		client: client,
	}
}

func (s *CloudFrontScanner) Name() string {
	return "CloudFront-SecaaS-Scanner"
}

func (s *CloudFrontScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	paginator := cloudfront.NewListDistributionsPaginator(s.client, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if page.DistributionList == nil {
			continue
		}

		for _, dist := range page.DistributionList.Items {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			distID := aws.ToString(dist.Id)
			distArn := aws.ToString(dist.ARN)
			if distArn == "" {
				distArn = fmt.Sprintf("arn:aws:cloudfront:::distribution/%s", distID)
			}
			nodes := []graph.Node{{ID: distArn, NodeType: "SecaaS-CloudFront"}}

			// 1. cloudfront_distributions_https_enabled
			allowsHTTP := false
			if dist.DefaultCacheBehavior != nil {
				if dist.DefaultCacheBehavior.ViewerProtocolPolicy == types.ViewerProtocolPolicyAllowAll {
					allowsHTTP = true
				}
			}
			if dist.CacheBehaviors != nil {
				for _, cb := range dist.CacheBehaviors.Items {
					if cb.ViewerProtocolPolicy == types.ViewerProtocolPolicyAllowAll {
						allowsHTTP = true
						break
					}
				}
			}

			if allowsHTTP {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_https_enabled",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s allows HTTP traffic without redirecting or enforcing HTTPS.", distID),
						"SecurityIssues": []string{"CloudFront distribution allows unencrypted HTTP viewer traffic"},
						"Recommendation": "Configure ViewerProtocolPolicy to 'redirect-to-https' or 'https-only' for all cache behaviors.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_https_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s enforces HTTPS on all cache behaviors.", distID),
					},
					Nodes: nodes,
				})
			}

			// 2. cloudfront_distributions_using_deprecated_ssl_protocols & cloudfront_distributions_using_deprecated_ssl_protocols
			var minProto string
			if dist.ViewerCertificate != nil {
				minProto = string(dist.ViewerCertificate.MinimumProtocolVersion)
			}

			deprecatedTLS := false
			switch minProto {
			case string(types.MinimumProtocolVersionSSLv3),
				string(types.MinimumProtocolVersionTLSv1),
				string(types.MinimumProtocolVersionTLSv12016),
				string(types.MinimumProtocolVersionTLSv112016),
				"":
				deprecatedTLS = true
			default:
				if !strings.HasPrefix(minProto, "TLSv1.2") && !strings.HasPrefix(minProto, "TLSv1.3") {
					deprecatedTLS = true
				}
			}

			if deprecatedTLS {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_using_deprecated_ssl_protocols",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s is using deprecated SSL/TLS protocol version (%s) instead of TLS 1.2 or higher.", distID, minProto),
						"SecurityIssues": []string{fmt.Sprintf("CloudFront distribution uses deprecated SSL/TLS protocol: %s", minProto)},
						"Recommendation": "Update ViewerCertificate MinimumProtocolVersion to TLSv1.2_2021 or higher.",
					},
					Nodes: nodes,
				})
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_using_deprecated_ssl_protocols",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s is using deprecated SSL/TLS protocol (%s).", distID, minProto),
						"SecurityIssues": []string{fmt.Sprintf("Deprecated SSL/TLS protocol in use: %s", minProto)},
						"Recommendation": "Upgrade SSL/TLS protocol version to at least TLSv1.2.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_using_deprecated_ssl_protocols",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s enforces TLS 1.2 or higher (protocol: %s).", distID, minProto),
					},
					Nodes: nodes,
				})
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_using_deprecated_ssl_protocols",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s is not using deprecated SSL/TLS protocols (protocol: %s).", distID, minProto),
					},
					Nodes: nodes,
				})
			}

			// 3. cloudfront_distributions_geo_restrictions_enabled
			geoConfigured := dist.Restrictions != nil &&
				dist.Restrictions.GeoRestriction != nil &&
				dist.Restrictions.GeoRestriction.RestrictionType != types.GeoRestrictionTypeNone

			if geoConfigured {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_geo_restrictions_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId":  distID,
						"RestrictionType": string(dist.Restrictions.GeoRestriction.RestrictionType),
						"StatusExtended":  fmt.Sprintf("CloudFront distribution %s has geo-restrictions enabled (type: %s).", distID, dist.Restrictions.GeoRestriction.RestrictionType),
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_geo_restrictions_enabled",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s does not have geo-restrictions configured.", distID),
						"SecurityIssues": []string{"Geo-restrictions are not configured on CloudFront distribution"},
						"Recommendation": "Configure geo-restrictions (whitelist or blacklist) to restrict viewer locations.",
					},
					Nodes: nodes,
				})
			}

			// 4. cloudfront_distributions_custom_ssl_certificate
			customSSLEnabled := false
			if dist.ViewerCertificate != nil {
				hasCert := (dist.ViewerCertificate.ACMCertificateArn != nil && *dist.ViewerCertificate.ACMCertificateArn != "") ||
					(dist.ViewerCertificate.IAMCertificateId != nil && *dist.ViewerCertificate.IAMCertificateId != "")
				notDefault := dist.ViewerCertificate.CloudFrontDefaultCertificate == nil || !*dist.ViewerCertificate.CloudFrontDefaultCertificate
				if hasCert && notDefault {
					customSSLEnabled = true
				}
			}

			if customSSLEnabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_custom_ssl_certificate",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s uses a custom SSL certificate.", distID),
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_custom_ssl_certificate",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s is using the default CloudFront SSL certificate instead of a custom SSL certificate.", distID),
						"SecurityIssues": []string{"CloudFront distribution does not use a custom SSL certificate"},
						"Recommendation": "Associate an ACM or IAM custom SSL certificate with the CloudFront distribution.",
					},
					Nodes: nodes,
				})
			}

			// 5. cloudfront_distributions_multiple_origin_failover_configured & cloudfront_distributions_multiple_origin_failover_configured
			originFailoverConfigured := dist.OriginGroups != nil &&
				dist.OriginGroups.Quantity != nil &&
				*dist.OriginGroups.Quantity > 0

			if originFailoverConfigured {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_multiple_origin_failover_configured",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s has origin failover configured with %d origin group(s).", distID, *dist.OriginGroups.Quantity),
					},
					Nodes: nodes,
				})
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_multiple_origin_failover_configured",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s has multiple origin failover configured with %d origin group(s).", distID, *dist.OriginGroups.Quantity),
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_multiple_origin_failover_configured",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s does not have origin failover configured.", distID),
						"SecurityIssues": []string{"Origin failover is not configured on CloudFront distribution"},
						"Recommendation": "Configure origin failover using Origin Groups to improve availability and resilience.",
					},
					Nodes: nodes,
				})
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_multiple_origin_failover_configured",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s does not have multiple origin failover configured.", distID),
						"SecurityIssues": []string{"Multiple origin failover is not configured on CloudFront distribution"},
						"Recommendation": "Configure origin failover using Origin Groups to improve availability and resilience.",
					},
					Nodes: nodes,
				})
			}

			// 6. cloudfront_distributions_using_waf
			wafAttached := dist.WebACLId != nil && *dist.WebACLId != ""

			if wafAttached {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_using_waf",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"WebACLId":       *dist.WebACLId,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s is protected by AWS WAF web ACL (%s).", distID, *dist.WebACLId),
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_using_waf",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s does not have an AWS WAF web ACL associated.", distID),
						"SecurityIssues": []string{"AWS WAF web ACL is not attached to CloudFront distribution"},
						"Recommendation": "Associate an AWS WAF web ACL with the CloudFront distribution to protect against layer-7 attacks.",
					},
					Nodes: nodes,
				})
			}

			// 7. cloudfront_distributions_logging_enabled
			loggingEnabled := false
			configOutput, err := s.client.GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{
				Id: aws.String(distID),
			})
			if err != nil {
				return nil, err
			}
			if configOutput != nil && configOutput.DistributionConfig != nil {
				logging := configOutput.DistributionConfig.Logging
				if logging != nil && logging.Enabled != nil && *logging.Enabled {
					loggingEnabled = true
				}
			}

			if loggingEnabled {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "PASS",
					RuleID:       "cloudfront_distributions_logging_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s has access logging enabled.", distID),
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   distID,
					ResourceType: "SecaaS-CloudFront",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "cloudfront_distributions_logging_enabled",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"DistributionId": distID,
						"StatusExtended": fmt.Sprintf("CloudFront distribution %s does not have access logging enabled.", distID),
						"SecurityIssues": []string{"Access logging is disabled on CloudFront distribution"},
						"Recommendation": "Enable CloudFront access logging to deliver traffic logs to an Amazon S3 bucket for auditing.",
					},
					Nodes: nodes,
				})
			}
		}
	}
	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *CloudFrontScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "cloudfront-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeGlobal,
		ExecutionCost: scanner.CostMedium,
		Service:       "cloudfront",
		CheckIDs:      []string{"cloudfront_distributions_custom_ssl_certificate", "cloudfront_distributions_geo_restrictions_enabled", "cloudfront_distributions_https_enabled", "cloudfront_distributions_logging_enabled", "cloudfront_distributions_multiple_origin_failover_configured", "cloudfront_distributions_using_deprecated_ssl_protocols", "cloudfront_distributions_using_waf"},
	}
}
