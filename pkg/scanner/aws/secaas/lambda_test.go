package secaas

import (
	"context"
	"net/url"
	"testing"

	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLambdaClient struct {
	listFunctionsOutput *lambda.ListFunctionsOutput
	functionUrlConfigs  map[string]*lambda.GetFunctionUrlConfigOutput
	functionUrlErrors   map[string]error
	policies            map[string]*lambda.GetPolicyOutput
	policyErrors        map[string]error
	tags                map[string]map[string]string
	listFunctionsErr    error
}

func (m *mockLambdaClient) ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if m.listFunctionsErr != nil {
		return nil, m.listFunctionsErr
	}
	return m.listFunctionsOutput, nil
}

func (m *mockLambdaClient) GetFunctionUrlConfig(ctx context.Context, params *lambda.GetFunctionUrlConfigInput, optFns ...func(*lambda.Options)) (*lambda.GetFunctionUrlConfigOutput, error) {
	fnName := aws.ToString(params.FunctionName)
	if err, ok := m.functionUrlErrors[fnName]; ok && err != nil {
		return nil, err
	}
	if cfg, ok := m.functionUrlConfigs[fnName]; ok {
		return cfg, nil
	}
	return nil, &lambdatypes.ResourceNotFoundException{
		Message: aws.String("FunctionUrlConfig does not exist"),
	}
}

func (m *mockLambdaClient) GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	fnName := aws.ToString(params.FunctionName)
	if m.policyErrors != nil {
		if err, ok := m.policyErrors[fnName]; ok && err != nil {
			return nil, err
		}
	}
	if m.policies != nil {
		if p, ok := m.policies[fnName]; ok {
			return p, nil
		}
	}
	return nil, &lambdatypes.ResourceNotFoundException{
		Message: aws.String("The resource you requested does not exist."),
	}
}

func (m *mockLambdaClient) ListTags(ctx context.Context, params *lambda.ListTagsInput, optFns ...func(*lambda.Options)) (*lambda.ListTagsOutput, error) {
	arn := aws.ToString(params.Resource)
	if m.tags != nil {
		if t, ok := m.tags[arn]; ok {
			return &lambda.ListTagsOutput{Tags: t}, nil
		}
	}
	return &lambda.ListTagsOutput{Tags: map[string]string{}}, nil
}

type mockIAMClient struct {
	attachedPolicies map[string][]iamtypes.AttachedPolicy
	rolePolicies     map[string][]string
	policyDocuments  map[string]map[string]string
}

func (m *mockIAMClient) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	roleName := aws.ToString(params.RoleName)
	policies := m.attachedPolicies[roleName]
	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: policies,
	}, nil
}

func (m *mockIAMClient) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	roleName := aws.ToString(params.RoleName)
	names := m.rolePolicies[roleName]
	return &iam.ListRolePoliciesOutput{
		PolicyNames: names,
	}, nil
}

func (m *mockIAMClient) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	roleName := aws.ToString(params.RoleName)
	policyName := aws.ToString(params.PolicyName)
	doc := ""
	if roleDocs, ok := m.policyDocuments[roleName]; ok {
		doc = roleDocs[policyName]
	}
	return &iam.GetRolePolicyOutput{
		RoleName:       params.RoleName,
		PolicyName:     params.PolicyName,
		PolicyDocument: aws.String(url.QueryEscape(doc)),
	}, nil
}

func TestLambdaScanner_Compliant(t *testing.T) {
	fnName := "secure-lambda-fn"
	fnArn := "arn:aws:lambda:us-east-1:123456789012:function:secure-lambda-fn"
	roleArn := "arn:aws:iam::123456789012:role/lambda-secure-role"

	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName: aws.String(fnName),
					FunctionArn:  aws.String(fnArn),
					Role:         aws.String(roleArn),
					Runtime:      lambdatypes.RuntimePython312,
					PackageType:  lambdatypes.PackageTypeZip,
					VpcConfig: &lambdatypes.VpcConfigResponse{
						SubnetIds:        []string{"subnet-11111", "subnet-22222"},
						SecurityGroupIds: []string{"sg-33333"},
						VpcId:            aws.String("vpc-44444"),
					},
					DeadLetterConfig: &lambdatypes.DeadLetterConfig{
						TargetArn: aws.String("arn:aws:sqs:us-east-1:123456789012:my-dlq"),
					},
					Environment: &lambdatypes.EnvironmentResponse{
						Variables: map[string]string{
							"ENV":       "production",
							"LOG_LEVEL": "info",
							"PORT":      "8080",
						},
					},
					TracingConfig: &lambdatypes.TracingConfigResponse{
						Mode: lambdatypes.TracingModeActive,
					},
				},
			},
		},
		functionUrlConfigs: map[string]*lambda.GetFunctionUrlConfigOutput{
			fnName: {
				AuthType:    lambdatypes.FunctionUrlAuthTypeAwsIam,
				FunctionArn: aws.String(fnArn),
				Cors: &lambdatypes.Cors{
					AllowOrigins: []string{"https://app.example.com"},
					AllowMethods: []string{"GET", "POST"},
				},
			},
		},
	}

	iamMock := &mockIAMClient{
		attachedPolicies: map[string][]iamtypes.AttachedPolicy{
			"lambda-secure-role": {
				{PolicyName: aws.String("AWSLambdaBasicExecutionRole")},
			},
		},
		rolePolicies: map[string][]string{
			"lambda-secure-role": {"inline-restricted"},
		},
		policyDocuments: map[string]map[string]string{
			"lambda-secure-role": {
				"inline-restricted": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`,
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, iamMock, "us-east-1")
	assert.Equal(t, "Lambda-SecaaS-Scanner", lScanner.Name())

	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, results)

	resultsByRule := make(map[string]string)
	for _, r := range results {
		assert.Equal(t, fnName, r.ResourceID)
		assert.Equal(t, "SecaaS-Lambda", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status, "Expected PASS for rule %s", r.RuleID)
		assert.Equal(t, "INFO", r.Severity)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])
		assert.Nil(t, metrics["SecurityIssues"])
		assert.Equal(t, roleArn, metrics["RoleARN"])
		assert.Len(t, r.Nodes, 1)
		assert.Equal(t, fnName, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-Lambda", r.Nodes[0].NodeType)
		assert.Len(t, r.Edges, 1)
		assert.Equal(t, fnName, r.Edges[0].From)
		assert.Equal(t, roleArn, r.Edges[0].To)
		assert.Equal(t, "ASSUMES_ROLE", r.Edges[0].Relation)

		resultsByRule[r.RuleID] = r.Status
	}

	// Verify all expected check rule IDs were evaluated
	expectedRules := []string{
		"awslambda_function_inside_vpc",
		"awslambda_function_using_supported_runtimes",
		"awslambda_function_url_cors_policy",
		"awslambda_function_no_dead_letter_queue",
		"awslambda_function_no_secrets_in_variables",
		"awslambda_function_tracing_enabled",
		"awslambda_function_execution_role_least_privilege",
		"awslambda_function_not_publicly_accessible",
		"awslambda_function_no_secrets_in_code",
	}

	for _, expectedRule := range expectedRules {
		status, found := resultsByRule[expectedRule]
		assert.True(t, found, "Expected rule %s in results", expectedRule)
		assert.Equal(t, "PASS", status)
	}
}

func TestLambdaScanner_NonCompliant(t *testing.T) {
	fnName := "insecure-lambda-fn"
	fnArn := "arn:aws:lambda:us-west-2:123456789012:function:insecure-lambda-fn"
	roleArn := "arn:aws:iam::123456789012:role/lambda-admin-role"

	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName:     aws.String(fnName),
					FunctionArn:      aws.String(fnArn),
					Role:             aws.String(roleArn),
					Runtime:          "python3.7", // Deprecated runtime
					PackageType:      lambdatypes.PackageTypeZip,
					Description:      aws.String("Function with password=secret123 and ghp_testtoken12345"),
					VpcConfig:        nil, // Not inside VPC
					DeadLetterConfig: nil, // No DLQ
					Environment: &lambdatypes.EnvironmentResponse{
						Variables: map[string]string{
							"DB_PASSWORD":   "SuperSecretPassword123!",
							"AWS_KEY_ID":    "AKIAIOSFODNN7EXAMPLE",
							"APP_SECRET":    "my-app-secret-token",
							"STRIPE_APIKEY": "sk_test_12345",
						},
					},
					TracingConfig: &lambdatypes.TracingConfigResponse{
						Mode: lambdatypes.TracingModePassThrough, // Not Active
					},
				},
			},
		},
		functionUrlConfigs: map[string]*lambda.GetFunctionUrlConfigOutput{
			fnName: {
				AuthType:    lambdatypes.FunctionUrlAuthTypeNone,
				FunctionArn: aws.String(fnArn),
				Cors: &lambdatypes.Cors{
					AllowOrigins: []string{"*"}, // Wildcard CORS
				},
			},
		},
		policies: map[string]*lambda.GetPolicyOutput{
			fnName: {
				Policy: aws.String(`{"Version":"2012-10-17","Statement":[{"Sid":"public-invoke","Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunction"}]}`),
			},
		},
	}

	iamMock := &mockIAMClient{
		attachedPolicies: map[string][]iamtypes.AttachedPolicy{
			"lambda-admin-role": {
				{PolicyName: aws.String("AdministratorAccess")},
			},
		},
		rolePolicies: map[string][]string{},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, iamMock, "us-west-2")
	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, results)

	resultsMap := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsMap[r.RuleID] = r
	}

	// 1. VPC Check -> FAIL (MEDIUM)
	vpcRes, ok := resultsMap["awslambda_function_inside_vpc"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", vpcRes.Status)
	assert.Equal(t, "MEDIUM", vpcRes.Severity)
	vpcMetrics := vpcRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, vpcMetrics["SecurityIssues"])
	assert.NotEmpty(t, vpcMetrics["Recommendation"])

	// 2. Runtime check -> FAIL (HIGH)
	rtRes, ok := resultsMap["awslambda_function_using_supported_runtimes"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", rtRes.Status)
	assert.Equal(t, "HIGH", rtRes.Severity)
	rtMetrics := rtRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, rtMetrics["SecurityIssues"])

	// 3. CORS Policy -> FAIL (MEDIUM)
	corsRes, ok := resultsMap["awslambda_function_url_cors_policy"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", corsRes.Status)
	assert.Equal(t, "MEDIUM", corsRes.Severity)
	corsMetrics := corsRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, corsMetrics["SecurityIssues"])

	// 4. DLQ check -> FAIL (LOW)
	dlqRes, ok := resultsMap["awslambda_function_no_dead_letter_queue"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", dlqRes.Status)
	assert.Equal(t, "LOW", dlqRes.Severity)
	dlqMetrics := dlqRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, dlqMetrics["SecurityIssues"])

	// 5. Secret variables -> FAIL (HIGH)
	secRes, ok := resultsMap["awslambda_function_no_secrets_in_variables"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", secRes.Status)
	assert.Equal(t, "HIGH", secRes.Severity)
	secMetrics := secRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, secMetrics["SecurityIssues"])

	// 6. Tracing check -> FAIL (LOW)
	traceRes, ok := resultsMap["awslambda_function_tracing_enabled"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", traceRes.Status)
	assert.Equal(t, "LOW", traceRes.Severity)
	traceMetrics := traceRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, traceMetrics["SecurityIssues"])

	// 7. IAM check -> FAIL (HIGH)
	iamRes, ok := resultsMap["awslambda_function_execution_role_least_privilege"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", iamRes.Status)
	assert.Equal(t, "HIGH", iamRes.Severity)
	iamMetrics := iamRes.Metrics.(map[string]interface{})
	assert.NotEmpty(t, iamMetrics["SecurityIssues"])

	// 8. Public access -> FAIL (CRITICAL)
	pubRes, ok := resultsMap["awslambda_function_not_publicly_accessible"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", pubRes.Status)
	assert.Equal(t, "CRITICAL", pubRes.Severity)
	pubMetrics := pubRes.Metrics.(map[string]interface{})
	assert.Equal(t, "Remove public invoke permissions from Lambda resource-based policy.", pubMetrics["Recommendation"])
	assert.NotEmpty(t, pubMetrics["SecurityIssues"])

	// 9. Secrets in code/config -> FAIL (CRITICAL)
	codeSecRes, ok := resultsMap["awslambda_function_no_secrets_in_code"]
	require.True(t, ok)
	assert.Equal(t, "FAIL", codeSecRes.Status)
	assert.Equal(t, "CRITICAL", codeSecRes.Severity)
	codeSecMetrics := codeSecRes.Metrics.(map[string]interface{})
	assert.Equal(t, "Remove hardcoded secrets from Lambda code and configuration; use AWS Secrets Manager.", codeSecMetrics["Recommendation"])
	assert.NotEmpty(t, codeSecMetrics["SecurityIssues"])
}

func TestLambdaScanner_UrlConfigNotFound(t *testing.T) {
	fnName := "no-url-fn"
	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName: aws.String(fnName),
					Runtime:      lambdatypes.RuntimeNodejs20x,
				},
			},
		},
		functionUrlErrors: map[string]error{
			fnName: &lambdatypes.ResourceNotFoundException{
				Message: aws.String("FunctionUrlConfig does not exist"),
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, nil, "eu-west-1")
	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "awslambda_function_url_cors_policy" {
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
			return
		}
	}
	t.Fatal("awslambda_function_url_cors_policy result not found")
}

func TestLambdaScanner_UrlConfigEmptyOrigins(t *testing.T) {
	fnName := "empty-cors-fn"
	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName: aws.String(fnName),
					Runtime:      lambdatypes.RuntimeNodejs20x,
				},
			},
		},
		functionUrlConfigs: map[string]*lambda.GetFunctionUrlConfigOutput{
			fnName: {
				Cors: &lambdatypes.Cors{
					AllowOrigins: []string{}, // Empty origins
				},
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, nil, "eu-west-1")
	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "awslambda_function_url_cors_policy" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "MEDIUM", r.Severity)
			return
		}
	}
	t.Fatal("awslambda_function_url_cors_policy result not found")
}

func TestLambdaScanner_UrlConfigNoCors(t *testing.T) {
	fnName := "nil-cors-fn"
	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName: aws.String(fnName),
					Runtime:      lambdatypes.RuntimeNodejs20x,
				},
			},
		},
		functionUrlConfigs: map[string]*lambda.GetFunctionUrlConfigOutput{
			fnName: {
				Cors: nil, // CORS not configured
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, nil, "eu-west-1")
	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "awslambda_function_url_cors_policy" {
			assert.Equal(t, "PASS", r.Status)
			assert.Equal(t, "INFO", r.Severity)
			return
		}
	}
	t.Fatal("awslambda_function_url_cors_policy result not found")
}

func TestLambdaScanner_ContainerImage(t *testing.T) {
	fnName := "container-fn"
	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName: aws.String(fnName),
					PackageType:  lambdatypes.PackageTypeImage,
					Runtime:      "",
				},
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, nil, "ap-southeast-2")
	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "awslambda_function_using_supported_runtimes" {
			assert.Equal(t, "PASS", r.Status)
			return
		}
	}
	t.Fatal("awslambda_function_using_supported_runtimes result not found")
}

func TestLambdaScanner_InlinePolicyPermissive(t *testing.T) {
	fnName := "inline-perm-fn"
	roleArn := "arn:aws:iam::123456789012:role/permissive-inline-role"

	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{
					FunctionName: aws.String(fnName),
					Role:         aws.String(roleArn),
					Runtime:      lambdatypes.RuntimePython312,
				},
			},
		},
	}

	iamMock := &mockIAMClient{
		attachedPolicies: map[string][]iamtypes.AttachedPolicy{},
		rolePolicies: map[string][]string{
			"permissive-inline-role": {"inline-wildcard"},
		},
		policyDocuments: map[string]map[string]string{
			"permissive-inline-role": {
				"inline-wildcard": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, iamMock, "us-east-1")
	results, err := lScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "awslambda_function_execution_role_least_privilege" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "HIGH", r.Severity)
			return
		}
	}
	t.Fatal("awslambda_function_execution_role_least_privilege result not found")
}

func TestLambdaScanner_ResourceLimit(t *testing.T) {
	lambdaMock := &mockLambdaClient{
		listFunctionsOutput: &lambda.ListFunctionsOutput{
			Functions: []lambdatypes.FunctionConfiguration{
				{FunctionName: aws.String("fn-1"), Runtime: lambdatypes.RuntimePython312},
				{FunctionName: aws.String("fn-2"), Runtime: lambdatypes.RuntimePython312},
				{FunctionName: aws.String("fn-3"), Runtime: lambdatypes.RuntimePython312},
			},
		},
	}

	lScanner := NewLambdaScannerWithClient(lambdaMock, nil, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)

	results, err := lScanner.Scan(ctx)
	require.NoError(t, err)

	// Since limit is 1, only 1 function was processed
	for _, r := range results {
		assert.Equal(t, "fn-1", r.ResourceID)
	}
}

func TestLambdaScanner_PublicPolicyVariations(t *testing.T) {
	tests := []struct {
		name             string
		policy           string
		policyErr        error
		expectedStatus   string
		expectedSeverity string
	}{
		{
			name: "Wildcard principal without condition should FAIL",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowPublic",
					"Effect": "Allow",
					"Principal": "*",
					"Action": "lambda:InvokeFunction"
				}]
			}`,
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name: "AWS map wildcard principal without condition should FAIL",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowPublicAWS",
					"Effect": "Allow",
					"Principal": {"AWS": "*"},
					"Action": "lambda:InvokeFunction"
				}]
			}`,
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name: "Wildcard principal with aws:PrincipalOrgID condition should PASS",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowOrg",
					"Effect": "Allow",
					"Principal": "*",
					"Action": "lambda:InvokeFunction",
					"Condition": {
						"StringEquals": {
							"aws:PrincipalOrgID": "o-123456789"
						}
					}
				}]
			}`,
			expectedStatus:   "PASS",
			expectedSeverity: "INFO",
		},
		{
			name: "Wildcard principal with aws:PrincipalAccount condition should PASS",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowAccount",
					"Effect": "Allow",
					"Principal": "*",
					"Action": "lambda:InvokeFunction",
					"Condition": {
						"StringEquals": {
							"aws:PrincipalAccount": "123456789012"
						}
					}
				}]
			}`,
			expectedStatus:   "PASS",
			expectedSeverity: "INFO",
		},
		{
			name: "Specific IAM principal should PASS",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [{
					"Sid": "AllowSpecificAccount",
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
					"Action": "lambda:InvokeFunction"
				}]
			}`,
			expectedStatus:   "PASS",
			expectedSeverity: "INFO",
		},
		{
			name: "ResourceNotFound error should PASS",
			policyErr: &lambdatypes.ResourceNotFoundException{
				Message: aws.String("The resource you requested does not exist."),
			},
			expectedStatus:   "PASS",
			expectedSeverity: "INFO",
		},
		{
			name:             "Empty policy should PASS",
			policy:           "",
			expectedStatus:   "PASS",
			expectedSeverity: "INFO",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fnName := "test-policy-fn"
			mockClient := &mockLambdaClient{
				listFunctionsOutput: &lambda.ListFunctionsOutput{
					Functions: []lambdatypes.FunctionConfiguration{
						{
							FunctionName: aws.String(fnName),
							Runtime:      lambdatypes.RuntimePython312,
						},
					},
				},
			}
			if tc.policyErr != nil {
				mockClient.policyErrors = map[string]error{fnName: tc.policyErr}
			} else if tc.policy != "" {
				mockClient.policies = map[string]*lambda.GetPolicyOutput{
					fnName: {Policy: aws.String(tc.policy)},
				}
			}

			lScanner := NewLambdaScannerWithClient(mockClient, nil, "us-east-1")
			results, err := lScanner.Scan(context.Background())
			require.NoError(t, err)

			var policyResult *scanner.ScanResult
			for _, r := range results {
				if r.RuleID == "awslambda_function_not_publicly_accessible" {
					policyResult = &r
					break
				}
			}
			require.NotNil(t, policyResult, "Expected awslambda_function_not_publicly_accessible check")
			assert.Equal(t, tc.expectedStatus, policyResult.Status)
			assert.Equal(t, tc.expectedSeverity, policyResult.Severity)
			if tc.expectedStatus == "FAIL" {
				metrics := policyResult.Metrics.(map[string]interface{})
				assert.Equal(t, "Remove public invoke permissions from Lambda resource-based policy.", metrics["Recommendation"])
			}
		})
	}
}

func TestLambdaScanner_SecretsInCodeVariations(t *testing.T) {
	tests := []struct {
		name             string
		description      string
		envVars          map[string]string
		tags             map[string]string
		expectedStatus   string
		expectedSeverity string
	}{
		{
			name:             "Description with GitHub PAT",
			description:      "Deployment script with token ghp_1234567890abcdef",
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name:             "Description with RSA private key",
			description:      "Includes -----BEGIN RSA PRIVATE KEY----- header",
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name: "Env vars with AKIA",
			envVars: map[string]string{
				"AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE",
			},
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name: "Env vars with password assignment",
			envVars: map[string]string{
				"CONFIG": "password=mysecretpassword",
			},
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name: "Tags with secret_key",
			tags: map[string]string{
				"AppKey": "secret_key=topsecretvalue",
			},
			expectedStatus:   "FAIL",
			expectedSeverity: "CRITICAL",
		},
		{
			name:        "Clean configuration with no secrets",
			description: "Production order processing service",
			envVars: map[string]string{
				"ENV":       "prod",
				"LOG_LEVEL": "info",
			},
			tags: map[string]string{
				"Environment": "Production",
				"Owner":       "DevOps",
			},
			expectedStatus:   "PASS",
			expectedSeverity: "INFO",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fnName := "test-secret-fn"
			fnArn := "arn:aws:lambda:us-east-1:123456789012:function:test-secret-fn"
			mockClient := &mockLambdaClient{
				listFunctionsOutput: &lambda.ListFunctionsOutput{
					Functions: []lambdatypes.FunctionConfiguration{
						{
							FunctionName: aws.String(fnName),
							FunctionArn:  aws.String(fnArn),
							Description:  aws.String(tc.description),
							Runtime:      lambdatypes.RuntimePython312,
							Environment: &lambdatypes.EnvironmentResponse{
								Variables: tc.envVars,
							},
						},
					},
				},
				tags: map[string]map[string]string{
					fnArn: tc.tags,
				},
			}

			lScanner := NewLambdaScannerWithClient(mockClient, nil, "us-east-1")
			results, err := lScanner.Scan(context.Background())
			require.NoError(t, err)

			var secretResult *scanner.ScanResult
			for _, r := range results {
				if r.RuleID == "awslambda_function_no_secrets_in_code" {
					secretResult = &r
					break
				}
			}
			require.NotNil(t, secretResult, "Expected awslambda_function_no_secrets_in_code check")
			assert.Equal(t, tc.expectedStatus, secretResult.Status)
			assert.Equal(t, tc.expectedSeverity, secretResult.Severity)
			if tc.expectedStatus == "FAIL" {
				metrics := secretResult.Metrics.(map[string]interface{})
				assert.Equal(t, "Remove hardcoded secrets from Lambda code and configuration; use AWS Secrets Manager.", metrics["Recommendation"])
			}
		})
	}
}
