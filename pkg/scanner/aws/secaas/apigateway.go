package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
)

// APIGatewayClient defines the mockable interface for API Gateway v1 (REST APIs).
type APIGatewayClient interface {
	GetRestApis(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
	GetStages(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error)
	GetResources(ctx context.Context, params *apigateway.GetResourcesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error)
}

// APIGatewayV2Client defines the mockable interface for API Gateway v2 (HTTP & WebSocket APIs).
type APIGatewayV2Client interface {
	GetApis(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error)
	GetStages(ctx context.Context, params *apigatewayv2.GetStagesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error)
	GetAuthorizers(ctx context.Context, params *apigatewayv2.GetAuthorizersInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetAuthorizersOutput, error)
}

// APIGatewayScanner evaluates security posture for API Gateway v1 (REST) and v2 (HTTP/WebSocket) APIs.
type APIGatewayScanner struct {
	v1Client APIGatewayClient
	v2Client APIGatewayV2Client
	region   string
}

// NewAPIGatewayScanner creates a scanner with default AWS clients.
func NewAPIGatewayScanner(cfg aws.Config) *APIGatewayScanner {
	return &APIGatewayScanner{
		v1Client: apigateway.NewFromConfig(cfg),
		v2Client: apigatewayv2.NewFromConfig(cfg),
		region:   cfg.Region,
	}
}

// NewAPIGatewayScannerWithClients creates a scanner with custom or mock v1 and v2 clients.
func NewAPIGatewayScannerWithClients(v1Client APIGatewayClient, v2Client APIGatewayV2Client, region string) *APIGatewayScanner {
	return &APIGatewayScanner{
		v1Client: v1Client,
		v2Client: v2Client,
		region:   region,
	}
}

// NewAPIGatewayScannerWithClient creates a scanner with custom or mock v1 client (for single client compatibility).
func NewAPIGatewayScannerWithClient(v1Client APIGatewayClient, region string) *APIGatewayScanner {
	return &APIGatewayScanner{
		v1Client: v1Client,
		region:   region,
	}
}

// Name returns the scanner name.
func (s *APIGatewayScanner) Name() string {
	return "APIGateway-SecaaS-Scanner"
}

// Scan executes security posture evaluations against API Gateway v1 and v2 resources.
func (s *APIGatewayScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
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

	// 1. Scan REST APIs (API Gateway v1)
	if s.v1Client != nil {
		paginator := apigateway.NewGetRestApisPaginator(s.v1Client, &apigateway.GetRestApisInput{})
		for paginator.HasMorePages() {
			if limit > 0 && processedCount >= limit {
				break
			}
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, api := range page.Items {
				if limit > 0 && processedCount >= limit {
					break
				}
				processedCount++

				apiId := aws.ToString(api.Id)
				apiName := aws.ToString(api.Name)

				// Check REST API Resources for Authorization (apigateway_restapi_authorizers_enabled)
				resources, err := s.v1Client.GetResources(ctx, &apigateway.GetResourcesInput{
					RestApiId: api.Id,
				})
				hasUnauthorizedMethod := false
				var unauthorizedMethods []string
				if err == nil && resources != nil {
					for _, res := range resources.Items {
						for httpMethod, method := range res.ResourceMethods {
							verb := strings.ToUpper(httpMethod)
							if method.HttpMethod != nil && *method.HttpMethod != "" {
								verb = strings.ToUpper(*method.HttpMethod)
							}
							if verb == "OPTIONS" {
								continue
							}
							authType := strings.ToUpper(aws.ToString(method.AuthorizationType))
							if authType == "NONE" || authType == "" {
								hasUnauthorizedMethod = true
								path := aws.ToString(res.Path)
								if path == "" {
									path = aws.ToString(res.Id)
								}
								unauthorizedMethods = append(unauthorizedMethods, fmt.Sprintf("%s %s", verb, path))
							}
						}
					}
				}

				authStatus := "PASS"
				authSeverity := "INFO"
				authMetrics := map[string]interface{}{
					"APIName": apiName,
				}
				if hasUnauthorizedMethod {
					authStatus = "FAIL"
					authSeverity = "HIGH"
					authMetrics["StatusExtended"] = fmt.Sprintf("API Gateway REST API %s has one or more methods without authorization.", apiId)
					authMetrics["Recommendation"] = fmt.Sprintf("Configure authorization (Cognito, Lambda authorizer, or IAM) for all non-OPTIONS methods in REST API %s.", apiId)
					authMetrics["SecurityIssues"] = unauthorizedMethods
				} else {
					authMetrics["StatusExtended"] = fmt.Sprintf("API Gateway REST API %s has authorization configured on all methods.", apiId)
					authMetrics["Recommendation"] = "Maintain authorization on all REST API methods."
				}

				results = append(results, scanner.ScanResult{
					ResourceID:   apiId,
					ResourceType: "SecaaS-APIGateway",
					Region:       region,
					Status:       authStatus,
					IsOrphaned:   false,
					RuleID:       "apigateway_restapi_authorizers_enabled",
					Severity:     authSeverity,
					Metrics:      authMetrics,
					Nodes:        []graph.Node{{ID: apiId, NodeType: "SecaaS-APIGateway"}},
					Edges:        nil,
				})

				// Check REST API Stages
				stages, err := s.v1Client.GetStages(ctx, &apigateway.GetStagesInput{
					RestApiId: api.Id,
				})
				if err == nil && stages != nil {
					for _, stage := range stages.Item {
						stageName := aws.ToString(stage.StageName)
						stageResourceID := fmt.Sprintf("%s/%s", apiId, stageName)
						stageNode := []graph.Node{{ID: stageResourceID, NodeType: "SecaaS-APIGateway"}}

						// Rule: apigateway_restapi_waf_acl_attached & apigateway_restapi_waf_acl_attached
						hasWaf := stage.WebAclArn != nil && aws.ToString(stage.WebAclArn) != ""
						wafStatus := "PASS"
						wafSeverity := "INFO"
						var wafEdges []graph.Edge
						if hasWaf {
							wafEdges = append(wafEdges, graph.Edge{
								From:     stageResourceID,
								To:       aws.ToString(stage.WebAclArn),
								Relation: "PROTECTED_BY",
							})
						} else {
							wafStatus = "FAIL"
							wafSeverity = "HIGH"
						}

						wafRules := []string{"apigateway_restapi_waf_acl_attached", "apigateway_restapi_waf_acl_attached"}
						for _, ruleID := range wafRules {
							m := map[string]interface{}{
								"APIName":   apiName,
								"StageName": stageName,
							}
							if hasWaf {
								m["WebAclArn"] = aws.ToString(stage.WebAclArn)
								m["StatusExtended"] = fmt.Sprintf("API Gateway REST API stage %s on API %s is protected by WAF web ACL %s.", stageName, apiId, aws.ToString(stage.WebAclArn))
								m["Recommendation"] = "Maintain AWS WAF association for API Gateway stages."
							} else {
								m["StatusExtended"] = fmt.Sprintf("API Gateway REST API stage %s on API %s is not protected by AWS WAF.", stageName, apiId)
								m["Recommendation"] = "Associate an AWS WAF web ACL with the API Gateway stage to protect against web attacks."
								m["SecurityIssues"] = []string{fmt.Sprintf("REST API stage %s missing AWS WAF protection", stageName)}
							}
							results = append(results, scanner.ScanResult{
								ResourceID:   stageResourceID,
								ResourceType: "SecaaS-APIGateway",
								Region:       region,
								Status:       wafStatus,
								IsOrphaned:   false,
								RuleID:       ruleID,
								Severity:     wafSeverity,
								Metrics:      m,
								Nodes:        stageNode,
								Edges:        wafEdges,
							})
						}

						// Rule: apigateway_restapi_logging_enabled
						hasLogging := false
						for _, setting := range stage.MethodSettings {
							lvl := strings.ToUpper(aws.ToString(setting.LoggingLevel))
							if lvl != "" && lvl != "OFF" {
								hasLogging = true
								break
							}
						}
						logStatus := "PASS"
						logSeverity := "INFO"
						logMetrics := map[string]interface{}{
							"APIName":   apiName,
							"StageName": stageName,
						}
						if hasLogging {
							logMetrics["StatusExtended"] = fmt.Sprintf("API Gateway REST API stage %s on API %s has execution logging enabled.", stageName, apiId)
							logMetrics["Recommendation"] = "Maintain execution logging for API Gateway REST API stages."
						} else {
							logStatus = "FAIL"
							logSeverity = "MEDIUM"
							logMetrics["StatusExtended"] = fmt.Sprintf("API Gateway REST API stage %s on API %s does not have execution logging enabled.", stageName, apiId)
							logMetrics["Recommendation"] = "Enable CloudWatch execution logging with logging level ERROR or INFO for REST API stages."
							logMetrics["SecurityIssues"] = []string{fmt.Sprintf("REST API stage %s missing execution logging", stageName)}
						}
						results = append(results, scanner.ScanResult{
							ResourceID:   stageResourceID,
							ResourceType: "SecaaS-APIGateway",
							Region:       region,
							Status:       logStatus,
							IsOrphaned:   false,
							RuleID:       "apigateway_restapi_logging_enabled",
							Severity:     logSeverity,
							Metrics:      logMetrics,
							Nodes:        stageNode,
							Edges:        nil,
						})

						// Rule: apigateway_restapi_tracing_enabled
						traceStatus := "PASS"
						traceSeverity := "INFO"
						traceMetrics := map[string]interface{}{
							"APIName":   apiName,
							"StageName": stageName,
						}
						if stage.TracingEnabled {
							traceMetrics["StatusExtended"] = fmt.Sprintf("API Gateway REST API stage %s on API %s has X-Ray tracing enabled.", stageName, apiId)
							traceMetrics["Recommendation"] = "Maintain X-Ray tracing for API Gateway REST API stages."
						} else {
							traceStatus = "FAIL"
							traceSeverity = "LOW"
							traceMetrics["StatusExtended"] = fmt.Sprintf("API Gateway REST API stage %s on API %s does not have X-Ray tracing enabled.", stageName, apiId)
							traceMetrics["Recommendation"] = "Enable AWS X-Ray active tracing on API Gateway REST API stages."
							traceMetrics["SecurityIssues"] = []string{fmt.Sprintf("REST API stage %s missing X-Ray tracing", stageName)}
						}
						results = append(results, scanner.ScanResult{
							ResourceID:   stageResourceID,
							ResourceType: "SecaaS-APIGateway",
							Region:       region,
							Status:       traceStatus,
							IsOrphaned:   false,
							RuleID:       "apigateway_restapi_tracing_enabled",
							Severity:     traceSeverity,
							Metrics:      traceMetrics,
							Nodes:        stageNode,
							Edges:        nil,
						})
					}
				}
			}
		}
	}

	// 2. Scan HTTP / WebSocket APIs (API Gateway v2)
	if s.v2Client != nil {
		var nextToken *string
		for {
			if limit > 0 && processedCount >= limit {
				break
			}
			apisOut, err := s.v2Client.GetApis(ctx, &apigatewayv2.GetApisInput{
				NextToken: nextToken,
			})
			if err != nil {
				return nil, err
			}

			for _, api := range apisOut.Items {
				if limit > 0 && processedCount >= limit {
					break
				}
				processedCount++

				apiId := aws.ToString(api.ApiId)
				apiName := aws.ToString(api.Name)
				apiNode := []graph.Node{{ID: apiId, NodeType: "SecaaS-APIGatewayV2"}}

				// Rule: apigatewayv2_api_authorizers_enabled
				authOut, err := s.v2Client.GetAuthorizers(ctx, &apigatewayv2.GetAuthorizersInput{
					ApiId: api.ApiId,
				})
				hasAuthorizers := err == nil && authOut != nil && len(authOut.Items) > 0

				authStatus := "PASS"
				authSeverity := "INFO"
				authMetrics := map[string]interface{}{
					"APIName": apiName,
				}
				if hasAuthorizers {
					authMetrics["StatusExtended"] = fmt.Sprintf("API Gateway V2 API %s has authorizers configured.", apiId)
					authMetrics["Recommendation"] = "Maintain authorizers for API Gateway V2 APIs."
				} else {
					authStatus = "FAIL"
					authSeverity = "HIGH"
					authMetrics["StatusExtended"] = fmt.Sprintf("API Gateway V2 API %s does not have any authorizers configured.", apiId)
					authMetrics["Recommendation"] = "Configure an authorizer (JWT/Cognito or Lambda) for API Gateway V2 API routes."
					authMetrics["SecurityIssues"] = []string{fmt.Sprintf("API Gateway V2 API %s has no authorizers configured", apiId)}
				}

				results = append(results, scanner.ScanResult{
					ResourceID:   apiId,
					ResourceType: "SecaaS-APIGatewayV2",
					Region:       region,
					Status:       authStatus,
					IsOrphaned:   false,
					RuleID:       "apigatewayv2_api_authorizers_enabled",
					Severity:     authSeverity,
					Metrics:      authMetrics,
					Nodes:        apiNode,
					Edges:        nil,
				})

				// Rule: apigatewayv2_api_access_logging_enabled
				var stageNextToken *string
				for {
					stagesOut, err := s.v2Client.GetStages(ctx, &apigatewayv2.GetStagesInput{
						ApiId:     api.ApiId,
						NextToken: stageNextToken,
					})
					if err != nil {
						break
					}
					for _, stage := range stagesOut.Items {
						stageName := aws.ToString(stage.StageName)
						stageResourceID := fmt.Sprintf("%s/%s", apiId, stageName)
						stageNode := []graph.Node{{ID: stageResourceID, NodeType: "SecaaS-APIGatewayV2"}}

						hasAccessLogging := stage.AccessLogSettings != nil &&
							stage.AccessLogSettings.DestinationArn != nil &&
							aws.ToString(stage.AccessLogSettings.DestinationArn) != ""

						logStatus := "PASS"
						logSeverity := "INFO"
						var logEdges []graph.Edge
						stageMetrics := map[string]interface{}{
							"APIName":   apiName,
							"StageName": stageName,
						}
						if hasAccessLogging {
							destArn := aws.ToString(stage.AccessLogSettings.DestinationArn)
							stageMetrics["DestinationArn"] = destArn
							stageMetrics["StatusExtended"] = fmt.Sprintf("API Gateway V2 stage %s on API %s has access logging enabled.", stageName, apiId)
							stageMetrics["Recommendation"] = "Maintain access logging configuration for API Gateway V2 stages."
							logEdges = append(logEdges, graph.Edge{
								From:     stageResourceID,
								To:       destArn,
								Relation: "LOGS_TO",
							})
						} else {
							logStatus = "FAIL"
							logSeverity = "MEDIUM"
							stageMetrics["StatusExtended"] = fmt.Sprintf("API Gateway V2 stage %s on API %s does not have access logging enabled.", stageName, apiId)
							stageMetrics["Recommendation"] = "Enable access logging to CloudWatch Logs or Amazon Kinesis Data Firehose for API Gateway V2 stages."
							stageMetrics["SecurityIssues"] = []string{fmt.Sprintf("API Gateway V2 stage %s missing access logging", stageName)}
						}

						results = append(results, scanner.ScanResult{
							ResourceID:   stageResourceID,
							ResourceType: "SecaaS-APIGatewayV2",
							Region:       region,
							Status:       logStatus,
							IsOrphaned:   false,
							RuleID:       "apigatewayv2_api_access_logging_enabled",
							Severity:     logSeverity,
							Metrics:      stageMetrics,
							Nodes:        stageNode,
							Edges:        logEdges,
						})
					}
					if stagesOut.NextToken == nil || *stagesOut.NextToken == "" {
						break
					}
					stageNextToken = stagesOut.NextToken
				}
			}

			if apisOut.NextToken == nil || *apisOut.NextToken == "" {
				break
			}
			nextToken = apisOut.NextToken
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *APIGatewayScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "apigateway-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "apigateway",
		CheckIDs:      []string{"apigateway_restapi_authorizers_enabled", "apigateway_restapi_logging_enabled", "apigateway_restapi_tracing_enabled", "apigatewayv2_api_access_logging_enabled", "apigatewayv2_api_authorizers_enabled"},
	}
}
