package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigatewaytypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigatewayv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amirmahdy/possum-core/pkg/scanner"
)

type mockAPIGatewayClient struct {
	getRestApisOutput  *apigateway.GetRestApisOutput
	getRestApisErr     error
	getStagesOutput    *apigateway.GetStagesOutput
	getStagesErr       error
	getResourcesOutput *apigateway.GetResourcesOutput
	getResourcesErr    error
}

func (m *mockAPIGatewayClient) GetRestApis(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	if m.getRestApisErr != nil {
		return nil, m.getRestApisErr
	}
	return m.getRestApisOutput, nil
}

func (m *mockAPIGatewayClient) GetStages(ctx context.Context, params *apigateway.GetStagesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	if m.getStagesErr != nil {
		return nil, m.getStagesErr
	}
	return m.getStagesOutput, nil
}

func (m *mockAPIGatewayClient) GetResources(ctx context.Context, params *apigateway.GetResourcesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	if m.getResourcesErr != nil {
		return nil, m.getResourcesErr
	}
	return m.getResourcesOutput, nil
}

type mockAPIGatewayV2Client struct {
	getApisOutput        *apigatewayv2.GetApisOutput
	getApisErr           error
	getStagesOutput      *apigatewayv2.GetStagesOutput
	getStagesErr         error
	getAuthorizersOutput *apigatewayv2.GetAuthorizersOutput
	getAuthorizersErr    error
}

func (m *mockAPIGatewayV2Client) GetApis(ctx context.Context, params *apigatewayv2.GetApisInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetApisOutput, error) {
	if m.getApisErr != nil {
		return nil, m.getApisErr
	}
	return m.getApisOutput, nil
}

func (m *mockAPIGatewayV2Client) GetStages(ctx context.Context, params *apigatewayv2.GetStagesInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetStagesOutput, error) {
	if m.getStagesErr != nil {
		return nil, m.getStagesErr
	}
	return m.getStagesOutput, nil
}

func (m *mockAPIGatewayV2Client) GetAuthorizers(ctx context.Context, params *apigatewayv2.GetAuthorizersInput, optFns ...func(*apigatewayv2.Options)) (*apigatewayv2.GetAuthorizersOutput, error) {
	if m.getAuthorizersErr != nil {
		return nil, m.getAuthorizersErr
	}
	return m.getAuthorizersOutput, nil
}

func TestAPIGatewayScanner_Name(t *testing.T) {
	sc := NewAPIGatewayScannerWithClients(nil, nil, "us-east-1")
	assert.Equal(t, "APIGateway-SecaaS-Scanner", sc.Name())
}

func TestAPIGatewayScanner_Constructors(t *testing.T) {
	cfg := aws.Config{Region: "us-east-1"}
	s1 := NewAPIGatewayScanner(cfg)
	assert.NotNil(t, s1)
	assert.Equal(t, "us-east-1", s1.region)

	s2 := NewAPIGatewayScannerWithClients(&mockAPIGatewayClient{}, &mockAPIGatewayV2Client{}, "us-west-2")
	assert.NotNil(t, s2)
	assert.Equal(t, "us-west-2", s2.region)

	s3 := NewAPIGatewayScannerWithClient(&mockAPIGatewayClient{}, "eu-west-1")
	assert.NotNil(t, s3)
	assert.Equal(t, "eu-west-1", s3.region)
}

func TestAPIGatewayScanner_Compliant_V1AndV2(t *testing.T) {
	v1Client := &mockAPIGatewayClient{
		getRestApisOutput: &apigateway.GetRestApisOutput{
			Items: []apigatewaytypes.RestApi{
				{
					Id:   aws.String("api-v1-comp"),
					Name: aws.String("CompliantRestApi"),
				},
			},
		},
		getResourcesOutput: &apigateway.GetResourcesOutput{
			Items: []apigatewaytypes.Resource{
				{
					Id:   aws.String("res-1"),
					Path: aws.String("/users"),
					ResourceMethods: map[string]apigatewaytypes.Method{
						"GET": {
							HttpMethod:        aws.String("GET"),
							AuthorizationType: aws.String("AWS_IAM"),
						},
						"POST": {
							HttpMethod:        aws.String("POST"),
							AuthorizationType: aws.String("CUSTOM"),
						},
						"OPTIONS": {
							HttpMethod:        aws.String("OPTIONS"),
							AuthorizationType: aws.String("NONE"), // OPTIONS with NONE is explicitly allowed!
						},
					},
				},
			},
		},
		getStagesOutput: &apigateway.GetStagesOutput{
			Item: []apigatewaytypes.Stage{
				{
					StageName:      aws.String("prod"),
					WebAclArn:      aws.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/abc123"),
					TracingEnabled: true,
					MethodSettings: map[string]apigatewaytypes.MethodSetting{
						"*/*": {
							LoggingLevel: aws.String("INFO"),
						},
					},
				},
			},
		},
	}

	v2Client := &mockAPIGatewayV2Client{
		getApisOutput: &apigatewayv2.GetApisOutput{
			Items: []apigatewayv2types.Api{
				{
					ApiId:        aws.String("api-v2-comp"),
					Name:         aws.String("CompliantHttpApi"),
					ProtocolType: apigatewayv2types.ProtocolTypeHttp,
				},
			},
		},
		getAuthorizersOutput: &apigatewayv2.GetAuthorizersOutput{
			Items: []apigatewayv2types.Authorizer{
				{
					AuthorizerId:   aws.String("auth-1"),
					Name:           aws.String("jwt-authorizer"),
					AuthorizerType: apigatewayv2types.AuthorizerTypeJwt,
				},
			},
		},
		getStagesOutput: &apigatewayv2.GetStagesOutput{
			Items: []apigatewayv2types.Stage{
				{
					StageName: aws.String("prod"),
					AccessLogSettings: &apigatewayv2types.AccessLogSettings{
						DestinationArn: aws.String("arn:aws:logs:us-east-1:123456789012:log-group:apigw-v2-logs"),
						Format:         aws.String(`{"requestId":"$context.requestId"}`),
					},
				},
			},
		},
	}

	sc := NewAPIGatewayScannerWithClients(v1Client, v2Client, "us-east-1")
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	// 5 checks from v1 (authorizers, waf, restapi_waf_acl, logging, tracing) + 2 from v2 (authorizers, access logging) = 7
	require.Len(t, results, 7)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Check %s should PASS", r.RuleID)
		assert.Equal(t, "INFO", r.Severity)
		assert.Equal(t, "us-east-1", r.Region)
		assert.NotEmpty(t, r.Nodes)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])
		assert.Nil(t, metrics["SecurityIssues"])

		resultsByRule[r.RuleID] = r
	}

	// Verify v1 Authorizers check
	rAuthV1 := resultsByRule["apigateway_restapi_authorizers_enabled"]
	assert.Equal(t, "api-v1-comp", rAuthV1.ResourceID)
	assert.Equal(t, "SecaaS-APIGateway", rAuthV1.ResourceType)

	// Verify v1 WAF check (apigateway_restapi_waf_acl_attached)
	rWaf := resultsByRule["apigateway_restapi_waf_acl_attached"]
	assert.Equal(t, "api-v1-comp/prod", rWaf.ResourceID)
	assert.Equal(t, "SecaaS-APIGateway", rWaf.ResourceType)
	require.Len(t, rWaf.Edges, 1)
	assert.Equal(t, "PROTECTED_BY", rWaf.Edges[0].Relation)
	assert.Equal(t, "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/abc123", rWaf.Edges[0].To)

	// Verify v1 WAF catalog check (apigateway_restapi_waf_acl_attached)
	rWafCat := resultsByRule["apigateway_restapi_waf_acl_attached"]
	assert.Equal(t, "api-v1-comp/prod", rWafCat.ResourceID)
	assert.Equal(t, "SecaaS-APIGateway", rWafCat.ResourceType)

	// Verify v1 Logging check
	rLogV1 := resultsByRule["apigateway_restapi_logging_enabled"]
	assert.Equal(t, "api-v1-comp/prod", rLogV1.ResourceID)
	assert.Equal(t, "SecaaS-APIGateway", rLogV1.ResourceType)

	// Verify v1 Tracing check
	rTraceV1 := resultsByRule["apigateway_restapi_tracing_enabled"]
	assert.Equal(t, "api-v1-comp/prod", rTraceV1.ResourceID)
	assert.Equal(t, "SecaaS-APIGateway", rTraceV1.ResourceType)

	// Verify v2 Authorizers check
	rAuthV2 := resultsByRule["apigatewayv2_api_authorizers_enabled"]
	assert.Equal(t, "api-v2-comp", rAuthV2.ResourceID)
	assert.Equal(t, "SecaaS-APIGatewayV2", rAuthV2.ResourceType)

	// Verify v2 Access Logging check
	rLogV2 := resultsByRule["apigatewayv2_api_access_logging_enabled"]
	assert.Equal(t, "api-v2-comp/prod", rLogV2.ResourceID)
	assert.Equal(t, "SecaaS-APIGatewayV2", rLogV2.ResourceType)
	require.Len(t, rLogV2.Edges, 1)
	assert.Equal(t, "LOGS_TO", rLogV2.Edges[0].Relation)
	assert.Equal(t, "arn:aws:logs:us-east-1:123456789012:log-group:apigw-v2-logs", rLogV2.Edges[0].To)
}

func TestAPIGatewayScanner_NonCompliant_V1AndV2(t *testing.T) {
	v1Client := &mockAPIGatewayClient{
		getRestApisOutput: &apigateway.GetRestApisOutput{
			Items: []apigatewaytypes.RestApi{
				{
					Id:   aws.String("api-v1-insecure"),
					Name: aws.String("InsecureRestApi"),
				},
			},
		},
		getResourcesOutput: &apigateway.GetResourcesOutput{
			Items: []apigatewaytypes.Resource{
				{
					Id:   aws.String("res-open"),
					Path: aws.String("/public"),
					ResourceMethods: map[string]apigatewaytypes.Method{
						"GET": {
							HttpMethod:        aws.String("GET"),
							AuthorizationType: aws.String("NONE"),
						},
					},
				},
			},
		},
		getStagesOutput: &apigateway.GetStagesOutput{
			Item: []apigatewaytypes.Stage{
				{
					StageName:      aws.String("dev"),
					WebAclArn:      nil,   // No WAF
					TracingEnabled: false, // No X-Ray
					MethodSettings: map[string]apigatewaytypes.MethodSetting{
						"*/*": {
							LoggingLevel: aws.String("OFF"), // Logging OFF
						},
					},
				},
			},
		},
	}

	v2Client := &mockAPIGatewayV2Client{
		getApisOutput: &apigatewayv2.GetApisOutput{
			Items: []apigatewayv2types.Api{
				{
					ApiId:        aws.String("api-v2-insecure"),
					Name:         aws.String("InsecureHttpApi"),
					ProtocolType: apigatewayv2types.ProtocolTypeHttp,
				},
			},
		},
		getAuthorizersOutput: &apigatewayv2.GetAuthorizersOutput{
			Items: []apigatewayv2types.Authorizer{}, // No authorizers
		},
		getStagesOutput: &apigatewayv2.GetStagesOutput{
			Items: []apigatewayv2types.Stage{
				{
					StageName:         aws.String("dev"),
					AccessLogSettings: nil, // No access logging
				},
			},
		},
	}

	sc := NewAPIGatewayScannerWithClients(v1Client, v2Client, "us-east-1")
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 7)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		assert.Equal(t, "FAIL", r.Status, "Check %s should FAIL", r.RuleID)
		assert.NotEmpty(t, r.Nodes)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])
		assert.NotEmpty(t, metrics["SecurityIssues"])

		resultsByRule[r.RuleID] = r
	}

	// Verify Severities
	assert.Equal(t, "HIGH", resultsByRule["apigateway_restapi_authorizers_enabled"].Severity)
	assert.Equal(t, "HIGH", resultsByRule["apigateway_restapi_waf_acl_attached"].Severity)
	assert.Equal(t, "HIGH", resultsByRule["apigateway_restapi_waf_acl_attached"].Severity)
	assert.Equal(t, "MEDIUM", resultsByRule["apigateway_restapi_logging_enabled"].Severity)
	assert.Equal(t, "LOW", resultsByRule["apigateway_restapi_tracing_enabled"].Severity)
	assert.Equal(t, "HIGH", resultsByRule["apigatewayv2_api_authorizers_enabled"].Severity)
	assert.Equal(t, "MEDIUM", resultsByRule["apigatewayv2_api_access_logging_enabled"].Severity)

	// Verify ResourceTypes
	assert.Equal(t, "SecaaS-APIGateway", resultsByRule["apigateway_restapi_authorizers_enabled"].ResourceType)
	assert.Equal(t, "SecaaS-APIGateway", resultsByRule["apigateway_restapi_waf_acl_attached"].ResourceType)
	assert.Equal(t, "SecaaS-APIGateway", resultsByRule["apigateway_restapi_waf_acl_attached"].ResourceType)
	assert.Equal(t, "SecaaS-APIGateway", resultsByRule["apigateway_restapi_logging_enabled"].ResourceType)
	assert.Equal(t, "SecaaS-APIGateway", resultsByRule["apigateway_restapi_tracing_enabled"].ResourceType)
	assert.Equal(t, "SecaaS-APIGatewayV2", resultsByRule["apigatewayv2_api_authorizers_enabled"].ResourceType)
	assert.Equal(t, "SecaaS-APIGatewayV2", resultsByRule["apigatewayv2_api_access_logging_enabled"].ResourceType)
}

func TestAPIGatewayScanner_ResourceLimit(t *testing.T) {
	v1Client := &mockAPIGatewayClient{
		getRestApisOutput: &apigateway.GetRestApisOutput{
			Items: []apigatewaytypes.RestApi{
				{Id: aws.String("api-1"), Name: aws.String("API 1")},
				{Id: aws.String("api-2"), Name: aws.String("API 2")},
			},
		},
		getResourcesOutput: &apigateway.GetResourcesOutput{Items: []apigatewaytypes.Resource{}},
		getStagesOutput:    &apigateway.GetStagesOutput{Item: []apigatewaytypes.Stage{}},
	}
	v2Client := &mockAPIGatewayV2Client{
		getApisOutput: &apigatewayv2.GetApisOutput{
			Items: []apigatewayv2types.Api{
				{ApiId: aws.String("api-v2-1"), Name: aws.String("V2 API 1")},
			},
		},
	}

	sc := NewAPIGatewayScannerWithClients(v1Client, v2Client, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	// With limit 1, only api-1 should be processed (which has 1 authorizers check and 0 stages)
	assert.Len(t, results, 1)
	assert.Equal(t, "api-1", results[0].ResourceID)
}

func TestAPIGatewayScanner_ClientErrors(t *testing.T) {
	v1ClientErr := &mockAPIGatewayClient{
		getRestApisErr: errors.New("v1 getRestApis error"),
	}
	sc := NewAPIGatewayScannerWithClients(v1ClientErr, nil, "us-east-1")
	_, err := sc.Scan(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "v1 getRestApis error")

	v2ClientErr := &mockAPIGatewayV2Client{
		getApisErr: errors.New("v2 getApis error"),
	}
	sc2 := NewAPIGatewayScannerWithClients(nil, v2ClientErr, "us-east-1")
	_, err = sc2.Scan(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "v2 getApis error")
}
