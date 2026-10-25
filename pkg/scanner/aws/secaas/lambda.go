package secaas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// LambdaClient defines the interface for Lambda API operations.
type LambdaClient interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetFunctionUrlConfig(ctx context.Context, params *lambda.GetFunctionUrlConfigInput, optFns ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error)
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// IAMClient defines the interface for IAM API operations used by LambdaScanner.
type IAMClient interface {
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
}

// LambdaScanner evaluates AWS Lambda functions against security best practices and compliance posture.
type LambdaScanner struct {
	lambdaClient LambdaClient
	iamClient    IAMClient
	region       string
}

// NewLambdaScanner creates a new LambdaScanner using standard AWS Config.
func NewLambdaScanner(cfg aws.Config) *LambdaScanner {
	return &LambdaScanner{
		lambdaClient: lambda.NewFromConfig(cfg),
		iamClient:    iam.NewFromConfig(cfg),
		region:       cfg.Region,
	}
}

// NewLambdaScannerWithClient creates a LambdaScanner with custom/mock clients.
func NewLambdaScannerWithClient(client LambdaClient, iamClient IAMClient, region string) *LambdaScanner {
	return &LambdaScanner{
		lambdaClient: client,
		iamClient:    iamClient,
		region:       region,
	}
}

func (s *LambdaScanner) Name() string {
	return "Lambda-SecaaS-Scanner"
}

var deprecatedRuntimes = map[string]bool{
	"python2.7":      true,
	"python3.6":      true,
	"python3.7":      true,
	"python3.8":      true,
	"nodejs":         true,
	"nodejs4.3":      true,
	"nodejs4.3-edge": true,
	"nodejs6.10":     true,
	"nodejs8.10":     true,
	"nodejs10.x":     true,
	"nodejs12.x":     true,
	"nodejs14.x":     true,
	"nodejs16.x":     true,
	"ruby2.5":        true,
	"ruby2.7":        true,
	"java8":          true,
	"java8.al2":      true,
	"dotnetcore1.0":  true,
	"dotnetcore2.0":  true,
	"dotnetcore2.1":  true,
	"dotnetcore3.1":  true,
	"go1.x":          true,
}

func detectSecretsInEnvVars(vars map[string]string) []string {
	var issues []string
	secretKeyKeywords := []string{
		"password",
		"secret",
		"apikey",
		"api_key",
		"auth_token",
		"private_key",
		"access_token",
		"secret_key",
		"app_secret",
		"client_secret",
	}

	for k, v := range vars {
		kLower := strings.ToLower(k)
		vLower := strings.ToLower(v)

		// Check variable key name
		for _, kw := range secretKeyKeywords {
			if strings.Contains(kLower, kw) {
				issues = append(issues, fmt.Sprintf("Environment variable '%s' key name suggests sensitive credentials", k))
				break
			}
		}

		// Check variable value content
		if strings.HasPrefix(v, "AKIA") || strings.HasPrefix(v, "ASIA") {
			issues = append(issues, fmt.Sprintf("Environment variable '%s' contains an AWS Access Key ID", k))
		} else if strings.Contains(vLower, "-----begin") || strings.Contains(vLower, "bearer ") {
			issues = append(issues, fmt.Sprintf("Environment variable '%s' contains private key or authorization token material", k))
		}
	}
	return issues
}

func isLambdaPolicyPubliclyAccessible(policyStr string) (bool, []string) {
	if strings.TrimSpace(policyStr) == "" {
		return false, nil
	}

	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policyStr), &parsed); err != nil {
		return false, nil
	}

	var statements []map[string]interface{}
	if err := json.Unmarshal(parsed.Statement, &statements); err != nil {
		var single map[string]interface{}
		if err := json.Unmarshal(parsed.Statement, &single); err == nil && single != nil {
			statements = append(statements, single)
		} else {
			return false, nil
		}
	}

	var issues []string
	for _, stmt := range statements {
		effect, _ := stmt["Effect"].(string)
		if !strings.EqualFold(effect, "Allow") {
			continue
		}

		isWildcardPrincipal := false
		switch p := stmt["Principal"].(type) {
		case string:
			if strings.TrimSpace(p) == "*" {
				isWildcardPrincipal = true
			}
		case map[string]interface{}:
			for _, v := range p {
				switch val := v.(type) {
				case string:
					if strings.TrimSpace(val) == "*" {
						isWildcardPrincipal = true
					}
				case []interface{}:
					for _, item := range val {
						if s, ok := item.(string); ok && strings.TrimSpace(s) == "*" {
							isWildcardPrincipal = true
							break
						}
					}
				}
				if isWildcardPrincipal {
					break
				}
			}
		}

		if !isWildcardPrincipal {
			continue
		}

		// Principal is wildcard, check for restrictive condition
		hasRestrictiveCondition := false
		if condMap, ok := stmt["Condition"].(map[string]interface{}); ok && len(condMap) > 0 {
			for _, condVal := range condMap {
				if fields, ok := condVal.(map[string]interface{}); ok {
					for condKey := range fields {
						kLower := strings.ToLower(strings.TrimSpace(condKey))
						if kLower == "aws:principalorgid" ||
							kLower == "aws:principalaccount" ||
							kLower == "aws:principalarn" ||
							kLower == "aws:sourceaccount" ||
							kLower == "aws:sourcearn" ||
							kLower == "aws:sourceowner" {
							hasRestrictiveCondition = true
							break
						}
					}
				}
				if hasRestrictiveCondition {
					break
				}
			}
		}

		if !hasRestrictiveCondition {
			sid, _ := stmt["Sid"].(string)
			if sid == "" {
				sid = "unnamed"
			}
			issues = append(issues, fmt.Sprintf("Statement '%s' allows wildcard Principal '*' without restrictive Condition (e.g. aws:PrincipalOrgID or aws:PrincipalAccount)", sid))
		}
	}

	return len(issues) > 0, issues
}

func detectHardcodedSecrets(description string, envVars map[string]string, tags map[string]string) []string {
	var issues []string

	scanText := func(source, text string) {
		if text == "" {
			return
		}

		// Exact / prefix patterns
		if strings.Contains(text, "AKIA") {
			issues = append(issues, fmt.Sprintf("%s contains AWS Access Key ID (AKIA)", source))
		}
		if strings.Contains(text, "ASIA") {
			issues = append(issues, fmt.Sprintf("%s contains AWS Temporary Access Key ID (ASIA)", source))
		}
		if strings.Contains(text, "ghp_") {
			issues = append(issues, fmt.Sprintf("%s contains GitHub token (ghp_)", source))
		}

		textLower := strings.ToLower(text)
		if strings.Contains(textLower, "begin rsa private key") || strings.Contains(textLower, "-----begin") {
			issues = append(issues, fmt.Sprintf("%s contains private key material", source))
		}
		if strings.Contains(textLower, "password=") || strings.Contains(textLower, "password =") {
			issues = append(issues, fmt.Sprintf("%s contains hardcoded password assignment", source))
		}
		if strings.Contains(textLower, "secret_key=") || strings.Contains(textLower, "secret_key =") {
			issues = append(issues, fmt.Sprintf("%s contains hardcoded secret_key assignment", source))
		}
		if strings.Contains(textLower, "api_key=") || strings.Contains(textLower, "api_key =") {
			issues = append(issues, fmt.Sprintf("%s contains hardcoded api_key assignment", source))
		}
		if strings.Contains(textLower, "private_key=") || strings.Contains(textLower, "private_key =") {
			issues = append(issues, fmt.Sprintf("%s contains hardcoded private_key assignment", source))
		}
	}

	if description != "" {
		scanText("Function description", description)
	}

	for k, v := range envVars {
		scanText(fmt.Sprintf("Environment variable '%s' key", k), k)
		scanText(fmt.Sprintf("Environment variable '%s' value", k), v)
		scanText(fmt.Sprintf("Environment variable '%s'", k), fmt.Sprintf("%s=%s", k, v))
	}

	for k, v := range tags {
		scanText(fmt.Sprintf("Tag '%s' key", k), k)
		scanText(fmt.Sprintf("Tag '%s' value", k), v)
		scanText(fmt.Sprintf("Tag '%s'", k), fmt.Sprintf("%s=%s", k, v))
	}

	// Deduplicate issues
	seen := make(map[string]bool)
	var deduped []string
	for _, issue := range issues {
		if !seen[issue] {
			seen[issue] = true
			deduped = append(deduped, issue)
		}
	}
	return deduped
}

func makeScanResult(
	fnName, roleArn, region, ruleID, status, severity, statusExtended, recommendation string,
	issues []string,
	extraMetrics map[string]interface{},
) scanner.ScanResult {
	metrics := map[string]interface{}{
		"FunctionName":   fnName,
		"StatusExtended": statusExtended,
		"Recommendation": recommendation,
	}
	if roleArn != "" {
		metrics["RoleARN"] = roleArn
	}
	if status == "FAIL" && len(issues) > 0 {
		metrics["SecurityIssues"] = issues
	}
	for k, v := range extraMetrics {
		metrics[k] = v
	}

	var edges []graph.Edge
	if roleArn != "" {
		edges = append(edges, graph.Edge{
			From:     fnName,
			To:       roleArn,
			Relation: "ASSUMES_ROLE",
		})
	}

	return scanner.ScanResult{
		ResourceID:   fnName,
		ResourceType: "SecaaS-Lambda",
		Region:       region,
		Status:       status,
		RuleID:       ruleID,
		Severity:     severity,
		Metrics:      metrics,
		Nodes:        []graph.Node{{ID: fnName, NodeType: "SecaaS-Lambda"}},
		Edges:        edges,
	}
}

func (s *LambdaScanner) checkRoleHasPermissivePolicies(ctx context.Context, roleArn string) bool {
	if s.iamClient == nil || roleArn == "" {
		return false
	}
	parts := strings.Split(roleArn, "/")
	if len(parts) <= 1 {
		return false
	}
	roleName := parts[len(parts)-1]

	// Check attached managed policies
	attached, err := s.iamClient.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil && attached != nil {
		for _, p := range attached.AttachedPolicies {
			if aws.ToString(p.PolicyName) == "AdministratorAccess" {
				return true
			}
		}
	}

	// Check inline policies
	inline, err := s.iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err == nil && inline != nil && len(inline.PolicyNames) > 0 {
		for _, policyName := range inline.PolicyNames {
			policyDoc, err := s.iamClient.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err == nil && policyDoc != nil {
				docUrlDecoded, decodeErr := url.QueryUnescape(aws.ToString(policyDoc.PolicyDocument))
				if decodeErr == nil {
					if strings.Contains(docUrlDecoded, "\"Resource\":\"*\"") ||
						strings.Contains(docUrlDecoded, "\"Resource\": \"*\"") ||
						strings.Contains(docUrlDecoded, "\"Resource\":\n*") {
						return true
					}
				}
			}
		}
	}

	return false
}

func (s *LambdaScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	if s.lambdaClient == nil {
		return nil, fmt.Errorf("lambda client is not initialized")
	}

	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	defaultRegion := s.region
	if defaultRegion == "" {
		defaultRegion = "regional"
	}

	paginator := lambda.NewListFunctionsPaginator(s.lambdaClient, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Lambda functions: %w", err)
		}

		for _, fn := range page.Functions {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			fnName := aws.ToString(fn.FunctionName)
			roleArn := aws.ToString(fn.Role)

			region := defaultRegion
			if s.region == "" {
				arnParts := strings.Split(aws.ToString(fn.FunctionArn), ":")
				if len(arnParts) >= 4 && arnParts[3] != "" {
					region = arnParts[3]
				}
			}

			// 1. awslambda_function_inside_vpc
			if fn.VpcConfig != nil && len(fn.VpcConfig.SubnetIds) > 0 {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_inside_vpc",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s is configured inside a VPC.", fnName),
					"Maintain Lambda VPC configuration for network isolation.",
					nil,
					map[string]interface{}{
						"SubnetIDs":      fn.VpcConfig.SubnetIds,
						"SecurityGroups": fn.VpcConfig.SecurityGroupIds,
						"VpcId":          aws.ToString(fn.VpcConfig.VpcId),
					},
				))
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_inside_vpc",
					"FAIL", "MEDIUM",
					fmt.Sprintf("Lambda function %s is not configured inside a VPC.", fnName),
					"Deploy Lambda functions inside a VPC with private subnets and restrictive security groups to enforce least privilege.",
					[]string{"Lambda function is not configured inside a VPC"},
					nil,
				))
			}

			// 2. awslambda_function_using_supported_runtimes
			rt := strings.ToLower(string(fn.Runtime))
			isDeprecated := false
			if fn.PackageType != lambdatypes.PackageTypeImage && rt != "" {
				if deprecatedRuntimes[rt] {
					isDeprecated = true
				}
			}

			if isDeprecated {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_using_supported_runtimes",
					"FAIL", "HIGH",
					fmt.Sprintf("Lambda function %s is using deprecated runtime %s.", fnName, rt),
					"Upgrade Lambda function runtime to a supported LTS version (e.g., Python 3.12, Node.js 20, Java 21).",
					[]string{fmt.Sprintf("Function uses obsolete runtime: %s", rt)},
					map[string]interface{}{
						"Runtime": rt,
					},
				))
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_using_supported_runtimes",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s is using a supported runtime (%s).", fnName, rt),
					"Continue using supported Lambda runtime versions and upgrade before deprecation.",
					nil,
					map[string]interface{}{
						"Runtime": rt,
					},
				))
			}

			// 3. awslambda_function_url_cors_policy
			urlConfig, urlErr := s.lambdaClient.GetFunctionUrlConfig(ctx, &lambda.GetFunctionUrlConfigInput{
				FunctionName: fn.FunctionName,
			})
			if urlErr != nil {
				var notFound *lambdatypes.ResourceNotFoundException
				if errors.As(urlErr, &notFound) || strings.Contains(urlErr.Error(), "ResourceNotFoundException") || strings.Contains(urlErr.Error(), "404") {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_url_cors_policy",
						"PASS", "INFO",
						fmt.Sprintf("Lambda function %s does not have a Function URL configured.", fnName),
						"Ensure any future Lambda function URLs enforce restrictive CORS policies.",
						nil, nil,
					))
				}
			} else if urlConfig != nil {
				corsInsecure := false
				var corsIssues []string
				var origins []string
				if urlConfig.Cors != nil {
					origins = urlConfig.Cors.AllowOrigins
					if len(origins) == 0 {
						corsInsecure = true
						corsIssues = append(corsIssues, "Lambda Function URL CORS configuration has empty AllowOrigins")
					} else {
						for _, o := range origins {
							if o == "*" {
								corsInsecure = true
								corsIssues = append(corsIssues, "Lambda Function URL CORS allows wildcard origin '*'")
								break
							}
						}
					}
				}

				if corsInsecure {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_url_cors_policy",
						"FAIL", "MEDIUM",
						fmt.Sprintf("Lambda function %s URL CORS configuration allows wildcard origin '*' or lacks restrictive origins.", fnName),
						"Restrict Function URL CORS AllowOrigins to specific, trusted domains and avoid '*'.",
						corsIssues,
						map[string]interface{}{
							"AllowOrigins": origins,
						},
					))
				} else {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_url_cors_policy",
						"PASS", "INFO",
						fmt.Sprintf("Lambda function %s URL CORS policy is properly restricted.", fnName),
						"Maintain restrictive CORS origins for Lambda function URLs.",
						nil,
						map[string]interface{}{
							"AllowOrigins": origins,
						},
					))
				}
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_url_cors_policy",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s does not have a Function URL configured.", fnName),
					"Ensure any future Lambda function URLs enforce restrictive CORS policies.",
					nil, nil,
				))
			}

			// 4. awslambda_function_no_dead_letter_queue
			hasDLQ := fn.DeadLetterConfig != nil && aws.ToString(fn.DeadLetterConfig.TargetArn) != ""
			if hasDLQ {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_no_dead_letter_queue",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s has Dead Letter Queue configured: %s.", fnName, aws.ToString(fn.DeadLetterConfig.TargetArn)),
					"Ensure the Dead Letter Queue is monitored for failed asynchronous invocations.",
					nil,
					map[string]interface{}{
						"DeadLetterTargetArn": aws.ToString(fn.DeadLetterConfig.TargetArn),
					},
				))
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_no_dead_letter_queue",
					"FAIL", "LOW",
					fmt.Sprintf("Lambda function %s does not have a Dead Letter Queue configured.", fnName),
					"Configure a Dead Letter Queue (SQS queue or SNS topic) to capture failed asynchronous invocations.",
					[]string{"Dead Letter Queue is not configured for asynchronous execution failures"},
					nil,
				))
			}

			// 5. awslambda_function_no_secrets_in_variables
			var secretIssues []string
			if fn.Environment != nil && fn.Environment.Variables != nil {
				secretIssues = detectSecretsInEnvVars(fn.Environment.Variables)
			}

			if len(secretIssues) > 0 {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_no_secrets_in_variables",
					"FAIL", "HIGH",
					fmt.Sprintf("Lambda function %s environment variables contain potential plaintext secrets (%d detected).", fnName, len(secretIssues)),
					"Store sensitive credentials and secrets in AWS Secrets Manager or Parameter Store rather than environment variables.",
					secretIssues,
					nil,
				))
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_no_secrets_in_variables",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s environment variables do not contain apparent plaintext secrets.", fnName),
					"Maintain secret hygiene and avoid placing plaintext credentials in environment variables.",
					nil,
					nil,
				))
			}

			// 6. awslambda_function_tracing_enabled
			isTracingActive := fn.TracingConfig != nil && fn.TracingConfig.Mode == lambdatypes.TracingModeActive
			currentTracingMode := "None"
			if fn.TracingConfig != nil {
				currentTracingMode = string(fn.TracingConfig.Mode)
			}

			if isTracingActive {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_tracing_enabled",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s has X-Ray active tracing enabled.", fnName),
					"Maintain X-Ray active tracing on Lambda functions for distributed observability.",
					nil,
					map[string]interface{}{
						"TracingMode": currentTracingMode,
					},
				))
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_tracing_enabled",
					"FAIL", "LOW",
					fmt.Sprintf("Lambda function %s does not have X-Ray active tracing enabled (current mode: %s).", fnName, currentTracingMode),
					"Enable AWS X-Ray active tracing on Lambda functions to detect latency, errors, and trace invocations.",
					[]string{fmt.Sprintf("X-Ray active tracing is not enabled (current mode: %s)", currentTracingMode)},
					map[string]interface{}{
						"TracingMode": currentTracingMode,
					},
				))
			}

			// 7. IAM Execution Role permission checking
			if s.iamClient != nil && roleArn != "" {
				hasPermissiveRole := s.checkRoleHasPermissivePolicies(ctx, roleArn)
				if hasPermissiveRole {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_execution_role_least_privilege",
						"FAIL", "HIGH",
						fmt.Sprintf("Lambda function %s execution role %s has overly permissive IAM policies.", fnName, roleArn),
						"Ensure Lambda execution roles adhere to the principle of least privilege.",
						[]string{"Execution role contains AdministratorAccess or overly broad wildcard Resource '*' permissions"},
						map[string]interface{}{
							"HasPermissiveRole": true,
						},
					))
				} else {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_execution_role_least_privilege",
						"PASS", "INFO",
						fmt.Sprintf("Lambda function %s execution role %s has least-privilege permissions.", fnName, roleArn),
						"Maintain least-privilege IAM execution roles for Lambda functions.",
						nil,
						map[string]interface{}{
							"HasPermissiveRole": false,
						},
					))
				}
			}

			// 8. awslambda_function_not_publicly_accessible (CRITICAL)
			policyOut, polErr := s.lambdaClient.GetPolicy(ctx, &lambda.GetPolicyInput{
				FunctionName: fn.FunctionName,
			})
			if polErr != nil {
				var notFound *lambdatypes.ResourceNotFoundException
				if errors.As(polErr, &notFound) || strings.Contains(polErr.Error(), "ResourceNotFoundException") || strings.Contains(polErr.Error(), "404") {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_not_publicly_accessible",
						"PASS", "INFO",
						fmt.Sprintf("Lambda function %s does not have a resource-based policy configured.", fnName),
						"Maintain restricted Lambda resource-based policies without public invoke permissions.",
						nil, nil,
					))
				} else {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_not_publicly_accessible",
						"PASS", "INFO",
						fmt.Sprintf("Lambda function %s resource-based policy is restricted or unavailable: %v.", fnName, polErr),
						"Maintain restricted Lambda resource-based policies without public invoke permissions.",
						nil, nil,
					))
				}
			} else if policyOut == nil || policyOut.Policy == nil || strings.TrimSpace(aws.ToString(policyOut.Policy)) == "" {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_not_publicly_accessible",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s has an empty resource-based policy.", fnName),
					"Maintain restricted Lambda resource-based policies without public invoke permissions.",
					nil, nil,
				))
			} else {
				policyStr := aws.ToString(policyOut.Policy)
				isPublic, publicIssues := isLambdaPolicyPubliclyAccessible(policyStr)
				if isPublic {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_not_publicly_accessible",
						"FAIL", "CRITICAL",
						fmt.Sprintf("Lambda function %s resource-based policy allows public invoke access.", fnName),
						"Remove public invoke permissions from Lambda resource-based policy.",
						publicIssues,
						map[string]interface{}{
							"Policy": policyStr,
						},
					))
				} else {
					results = append(results, makeScanResult(
						fnName, roleArn, region,
						"awslambda_function_not_publicly_accessible",
						"PASS", "INFO",
						fmt.Sprintf("Lambda function %s resource-based policy restricts invoke permissions.", fnName),
						"Maintain restricted Lambda resource-based policies without public invoke permissions.",
						nil,
						map[string]interface{}{
							"Policy": policyStr,
						},
					))
				}
			}

			// 9. awslambda_function_no_secrets_in_code (CRITICAL)
			var envVars map[string]string
			if fn.Environment != nil && fn.Environment.Variables != nil {
				envVars = fn.Environment.Variables
			}

			var tags map[string]string
			if tagClient, ok := s.lambdaClient.(interface {
				ListTags(ctx context.Context, params *lambda.ListTagsInput, optFns ...func(*lambda.Options)) (*lambda.ListTagsOutput, error)
			}); ok && fn.FunctionArn != nil {
				tagOut, err := tagClient.ListTags(ctx, &lambda.ListTagsInput{Resource: fn.FunctionArn})
				if err == nil && tagOut != nil {
					tags = tagOut.Tags
				}
			}

			codeSecretIssues := detectHardcodedSecrets(
				aws.ToString(fn.Description),
				envVars,
				tags,
			)

			if len(codeSecretIssues) > 0 {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_no_secrets_in_code",
					"FAIL", "CRITICAL",
					fmt.Sprintf("Lambda function %s contains hardcoded secrets in description, environment variables, or tags (%d detected).", fnName, len(codeSecretIssues)),
					"Remove hardcoded secrets from Lambda code and configuration; use AWS Secrets Manager.",
					codeSecretIssues,
					nil,
				))
			} else {
				results = append(results, makeScanResult(
					fnName, roleArn, region,
					"awslambda_function_no_secrets_in_code",
					"PASS", "INFO",
					fmt.Sprintf("Lambda function %s does not contain hardcoded secrets in description, environment variables, or tags.", fnName),
					"Maintain secret hygiene and use AWS Secrets Manager for sensitive credentials.",
					nil,
					nil,
				))
			}
		}
	}

	return results, nil
}
