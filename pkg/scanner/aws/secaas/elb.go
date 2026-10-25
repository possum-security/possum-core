package secaas

import (
	"context"
	"fmt"
	"strings"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
)

// ELBv2API defines the interface for Elastic Load Balancing v2 operations.
type ELBv2API interface {
	DescribeLoadBalancers(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error)
	DescribeLoadBalancerAttributes(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error)
}

// WAFv2API defines the interface for AWS WAFv2 operations.
type WAFv2API interface {
	GetWebACLForResource(ctx context.Context, params *wafv2.GetWebACLForResourceInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLForResourceOutput, error)
}

// Type aliases for flexible client naming
type ELBv2Client = ELBv2API
type WAFv2Client = WAFv2API

// ELBScanner audits Application Load Balancers for security controls including
// HTTPS listeners, modern TLS ciphers, dropping invalid header fields, access logging, and WAF attachment.
type ELBScanner struct {
	elbv2Client ELBv2API
	wafv2Client WAFv2API
	region      string
}

// NewELBScanner creates an ELBScanner with standard AWS SDK clients from config.
func NewELBScanner(cfg aws.Config) *ELBScanner {
	return &ELBScanner{
		elbv2Client: elasticloadbalancingv2.NewFromConfig(cfg),
		wafv2Client: wafv2.NewFromConfig(cfg),
		region:      cfg.Region,
	}
}

// NewELBScannerWithClient creates an ELBScanner with custom/mock ELBv2 and WAFv2 clients.
func NewELBScannerWithClient(elbv2Client ELBv2API, wafv2Client WAFv2API, optRegion ...string) *ELBScanner {
	region := ""
	if len(optRegion) > 0 {
		region = optRegion[0]
	}
	return &ELBScanner{
		elbv2Client: elbv2Client,
		wafv2Client: wafv2Client,
		region:      region,
	}
}

// NewELBScannerWithClients is an alias for NewELBScannerWithClient.
func NewELBScannerWithClients(elbv2Client ELBv2API, wafv2Client WAFv2API, optRegion ...string) *ELBScanner {
	return NewELBScannerWithClient(elbv2Client, wafv2Client, optRegion...)
}

func (s *ELBScanner) Name() string {
	return "ELB-SecaaS-Scanner"
}

func (s *ELBScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	if s.elbv2Client == nil {
		return nil, nil
	}

	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(s.elbv2Client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, lb := range page.LoadBalancers {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			lbArn := aws.ToString(lb.LoadBalancerArn)
			lbName := aws.ToString(lb.LoadBalancerName)
			lbType := lb.Type

			if lbType != elbv2Types.LoadBalancerTypeEnumApplication {
				continue
			}

			region := s.region
			if region == "" {
				parts := strings.Split(lbArn, ":")
				if len(parts) >= 4 && parts[3] != "" {
					region = parts[3]
				} else {
					region = "global"
				}
			}

			// 1. Check Listeners (elbv2_ssl_listeners and elbv2_insecure_ssl_ciphers)
			hasHTTPS := false
			weakSSLPolicies := false

			listenersPaginator := elasticloadbalancingv2.NewDescribeListenersPaginator(s.elbv2Client, &elasticloadbalancingv2.DescribeListenersInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})

			for listenersPaginator.HasMorePages() {
				listenerPage, err := listenersPaginator.NextPage(ctx)
				if err != nil {
					break
				}
				for _, listener := range listenerPage.Listeners {
					if listener.Protocol == elbv2Types.ProtocolEnumHttps {
						hasHTTPS = true
						policy := aws.ToString(listener.SslPolicy)
						if strings.Contains(policy, "2016-08") || strings.Contains(policy, "2015-05") || strings.Contains(policy, "TLS-1-0") || strings.Contains(policy, "TLS-1-1") {
							weakSSLPolicies = true
						}
					}
				}
			}

			// 2. Check Attributes (elbv2_alb_drop_invalid_header_fields_enabled and elbv2_logging_enabled)
			dropInvalidHeadersEnabled := false
			accessLogsEnabled := false
			attrOutput, err := s.elbv2Client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			if err == nil && attrOutput != nil {
				for _, attr := range attrOutput.Attributes {
					if aws.ToString(attr.Key) == "routing.http.drop_invalid_header_fields.enabled" {
						if aws.ToString(attr.Value) == "true" {
							dropInvalidHeadersEnabled = true
						}
					}
					if aws.ToString(attr.Key) == "access_logs.s3.enabled" {
						if aws.ToString(attr.Value) == "true" {
							accessLogsEnabled = true
						}
					}
				}
			}

			// 3. Check WAF attachment (elbv2_waf_acl_attached)
			wafAttached := false
			if s.wafv2Client != nil {
				wafOutput, err := s.wafv2Client.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{
					ResourceArn: lb.LoadBalancerArn,
				})
				if err == nil && wafOutput != nil && wafOutput.WebACL != nil {
					wafAttached = true
				}
			}

			// Build graph topology
			var nodes []graph.Node
			var edges []graph.Edge
			nodes = append(nodes, graph.Node{ID: lbArn, NodeType: "SecaaS-ELB"})
			if lb.VpcId != nil {
				edges = append(edges, graph.Edge{From: lbArn, To: aws.ToString(lb.VpcId), Relation: "IN_VPC"})
			}
			for _, sg := range lb.SecurityGroups {
				edges = append(edges, graph.Edge{From: sg, To: lbArn, Relation: "ATTACHED_TO"})
			}

			// Control 1: elbv2_ssl_listeners
			// FAIL if missing HTTPS listener
			// PASS if HTTPS listener is configured
			sslStatus := "FAIL"
			sslSeverity := "HIGH"
			sslMetrics := map[string]interface{}{
				"LoadBalancerName": lbName,
				"LoadBalancerType": string(lbType),
			}
			if hasHTTPS {
				sslStatus = "PASS"
				sslSeverity = "INFO"
				sslMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s has HTTPS listener configured.", lbName)
			} else {
				sslMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s does not have an HTTPS listener configured.", lbName)
				sslMetrics["SecurityIssues"] = []string{"No HTTPS listener found"}
				sslMetrics["Recommendation"] = "Configure an HTTPS listener on the Application Load Balancer to secure traffic in transit."
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lbArn,
				ResourceType: "SecaaS-ELB",
				Region:       region,
				Status:       sslStatus,
				IsOrphaned:   false,
				RuleID:       "elbv2_ssl_listeners",
				Severity:     sslSeverity,
				Metrics:      sslMetrics,
				Nodes:        nodes,
				Edges:        edges,
			})

			// Control 2: elbv2_insecure_ssl_ciphers
			// FAIL if any HTTPS listener uses weak/outdated SSL policy (e.g. contains '2016-08', '2015-05', 'TLS-1-0', 'TLS-1-1')
			// PASS if all HTTPS listeners use modern secure TLS policies
			cipherStatus := "PASS"
			cipherSeverity := "INFO"
			cipherMetrics := map[string]interface{}{
				"LoadBalancerName": lbName,
				"LoadBalancerType": string(lbType),
			}
			if weakSSLPolicies {
				cipherStatus = "FAIL"
				cipherSeverity = "HIGH"
				cipherMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s has HTTPS listeners using weak or outdated SSL/TLS policies.", lbName)
				cipherMetrics["SecurityIssues"] = []string{"Weak or outdated SSL/TLS policy in use (e.g., TLS 1.0/1.1)"}
				cipherMetrics["Recommendation"] = "Update HTTPS listener SSL policies to use modern TLS 1.2/1.3 policies (e.g. ELBSecurityPolicy-TLS13-1-2-2021-06)."
			} else {
				if hasHTTPS {
					cipherMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s uses modern secure TLS policies on all HTTPS listeners.", lbName)
				} else {
					cipherMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s has no HTTPS listeners using weak SSL policies.", lbName)
				}
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lbArn,
				ResourceType: "SecaaS-ELB",
				Region:       region,
				Status:       cipherStatus,
				IsOrphaned:   false,
				RuleID:       "elbv2_insecure_ssl_ciphers",
				Severity:     cipherSeverity,
				Metrics:      cipherMetrics,
				Nodes:        nodes,
				Edges:        edges,
			})

			// Control 3: elbv2_alb_drop_invalid_header_fields_enabled
			// PASS if attribute 'routing.http.drop_invalid_header_fields.enabled' == 'true'
			// FAIL otherwise
			dropHeadersStatus := "FAIL"
			dropHeadersSeverity := "MEDIUM"
			dropHeadersMetrics := map[string]interface{}{
				"LoadBalancerName": lbName,
				"LoadBalancerType": string(lbType),
			}
			if dropInvalidHeadersEnabled {
				dropHeadersStatus = "PASS"
				dropHeadersSeverity = "INFO"
				dropHeadersMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s has drop invalid header fields enabled.", lbName)
			} else {
				dropHeadersMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s does not have drop invalid header fields enabled.", lbName)
				dropHeadersMetrics["SecurityIssues"] = []string{"Dropping invalid HTTP headers is disabled"}
				dropHeadersMetrics["Recommendation"] = "Enable 'routing.http.drop_invalid_header_fields.enabled' on the Application Load Balancer to prevent HTTP request smuggling."
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lbArn,
				ResourceType: "SecaaS-ELB",
				Region:       region,
				Status:       dropHeadersStatus,
				IsOrphaned:   false,
				RuleID:       "elbv2_alb_drop_invalid_header_fields_enabled",
				Severity:     dropHeadersSeverity,
				Metrics:      dropHeadersMetrics,
				Nodes:        nodes,
				Edges:        edges,
			})

			// Control 4: elbv2_logging_enabled
			// PASS if attribute 'access_logs.s3.enabled' == 'true'
			// FAIL otherwise
			loggingStatus := "FAIL"
			loggingSeverity := "MEDIUM"
			loggingMetrics := map[string]interface{}{
				"LoadBalancerName": lbName,
				"LoadBalancerType": string(lbType),
			}
			if accessLogsEnabled {
				loggingStatus = "PASS"
				loggingSeverity = "INFO"
				loggingMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s has access logging to S3 enabled.", lbName)
			} else {
				loggingMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s does not have access logging to S3 enabled.", lbName)
				loggingMetrics["SecurityIssues"] = []string{"Access logging is disabled"}
				loggingMetrics["Recommendation"] = "Enable 'access_logs.s3.enabled' on the Application Load Balancer to capture request logs."
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lbArn,
				ResourceType: "SecaaS-ELB",
				Region:       region,
				Status:       loggingStatus,
				IsOrphaned:   false,
				RuleID:       "elbv2_logging_enabled",
				Severity:     loggingSeverity,
				Metrics:      loggingMetrics,
				Nodes:        nodes,
				Edges:        edges,
			})

			// Control 5: elbv2_waf_acl_attached
			// PASS if WAF WebACL is attached
			// FAIL otherwise
			wafStatus := "FAIL"
			wafSeverity := "HIGH"
			wafMetrics := map[string]interface{}{
				"LoadBalancerName": lbName,
				"LoadBalancerType": string(lbType),
			}
			if wafAttached {
				wafStatus = "PASS"
				wafSeverity = "INFO"
				wafMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s has a WAF Web ACL attached.", lbName)
			} else {
				wafMetrics["StatusExtended"] = fmt.Sprintf("Application Load Balancer %s does not have a WAF Web ACL attached.", lbName)
				wafMetrics["SecurityIssues"] = []string{"No WAF attached"}
				wafMetrics["Recommendation"] = "Associate an AWS WAF Web ACL with the Application Load Balancer to protect against web vulnerabilities."
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lbArn,
				ResourceType: "SecaaS-ELB",
				Region:       region,
				Status:       wafStatus,
				IsOrphaned:   false,
				RuleID:       "elbv2_waf_acl_attached",
				Severity:     wafSeverity,
				Metrics:      wafMetrics,
				Nodes:        nodes,
				Edges:        edges,
			})
		}
	}
	return results, nil
}
