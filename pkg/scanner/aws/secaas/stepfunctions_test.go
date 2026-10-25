package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockStepFunctionsApi struct {
	listStateMachinesFn    func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	describeStateMachineFn func(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
}

func (m *mockStepFunctionsApi) ListStateMachines(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	if m.listStateMachinesFn != nil {
		return m.listStateMachinesFn(ctx, params, optFns...)
	}
	return &sfn.ListStateMachinesOutput{}, nil
}

func (m *mockStepFunctionsApi) DescribeStateMachine(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
	if m.describeStateMachineFn != nil {
		return m.describeStateMachineFn(ctx, params, optFns...)
	}
	return &sfn.DescribeStateMachineOutput{}, nil
}

func TestStepFunctionsScanner_Name(t *testing.T) {
	sfnScanner := NewStepFunctionsScannerWithClient(&mockStepFunctionsApi{}, "us-east-1")
	assert.Equal(t, "StepFunctions-SecaaS-Scanner", sfnScanner.Name())
}

func TestNewStepFunctionsScanner(t *testing.T) {
	sfnScanner := NewStepFunctionsScanner(aws.Config{Region: "eu-west-1"})
	require.NotNil(t, sfnScanner)
	assert.Equal(t, "StepFunctions-SecaaS-Scanner", sfnScanner.Name())
	assert.Equal(t, "eu-west-1", sfnScanner.region)
}

func TestStepFunctionsScanner_Compliant(t *testing.T) {
	smName := "compliant-workflow"
	smArn := "arn:aws:states:us-east-1:123456789012:stateMachine:compliant-workflow"
	definition := `{
		"Comment": "A compliant state machine that retrieves credentials safely at runtime",
		"StartAt": "GetSecret",
		"States": {
			"GetSecret": {
				"Type": "Task",
				"Resource": "arn:aws:states:::secretsmanager:getSecretValue",
				"Parameters": {
					"SecretId": "arn:aws:secretsmanager:us-east-1:123456789012:secret:app-db-creds"
				},
				"End": true
			}
		}
	}`

	mock := &mockStepFunctionsApi{
		listStateMachinesFn: func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
			return &sfn.ListStateMachinesOutput{
				StateMachines: []sfntypes.StateMachineListItem{
					{
						Name:            aws.String(smName),
						StateMachineArn: aws.String(smArn),
					},
				},
			}, nil
		},
		describeStateMachineFn: func(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
			return &sfn.DescribeStateMachineOutput{
				Name:            aws.String(smName),
				StateMachineArn: aws.String(smArn),
				Definition:      aws.String(definition),
			}, nil
		},
	}

	sfnScanner := NewStepFunctionsScannerWithClient(mock, "us-east-1")
	results, err := sfnScanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, smName, r.ResourceID)
	assert.Equal(t, "SecaaS-StepFunctions", r.ResourceType)
	assert.Equal(t, "us-east-1", r.Region)
	assert.Equal(t, "stepfunctions_statemachine_no_secrets_in_definition", r.RuleID)
	assert.Equal(t, "PASS", r.Status)
	assert.Equal(t, "INFO", r.Severity)

	metrics, ok := r.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, metrics["StatusExtended"])

	require.Len(t, r.Nodes, 1)
	assert.Equal(t, smArn, r.Nodes[0].ID)
	assert.Equal(t, "SecaaS-StepFunctions", r.Nodes[0].NodeType)
}

func TestStepFunctionsScanner_NonCompliant_SecretsInDefinition(t *testing.T) {
	testCases := []struct {
		name       string
		definition string
	}{
		{
			name:       "AKIA AWS Access Key ID pattern",
			definition: `{"StartAt":"Deploy","States":{"Deploy":{"Type":"Pass","Result":{"AccessKey":"AKIAIOSFODNN7EXAMPLE"},"End":true}}}`,
		},
		{
			name:       "BEGIN RSA PRIVATE KEY material",
			definition: `{"StartAt":"Sign","States":{"Sign":{"Type":"Pass","Result":{"Key":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."},"End":true}}}`,
		},
		{
			name:       "password sensitive keyword",
			definition: `{"StartAt":"Connect","States":{"Connect":{"Type":"Pass","Result":{"db_password":"my-cleartext-pass"},"End":true}}}`,
		},
		{
			name:       "secret_key sensitive keyword",
			definition: `{"StartAt":"Auth","States":{"Auth":{"Type":"Pass","Result":{"secret_key":"9876543210zyx"},"End":true}}}`,
		},
		{
			name:       "api_key sensitive keyword",
			definition: `{"StartAt":"CallApi","States":{"CallApi":{"Type":"Pass","Result":{"api_key":"prod-api-key-abcdef"},"End":true}}}`,
		},
		{
			name:       "auth_token sensitive keyword",
			definition: `{"StartAt":"Fetch","States":{"Fetch":{"Type":"Pass","Result":{"auth_token":"Bearer secret123"},"End":true}}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			smName := "vulnerable-workflow"
			smArn := "arn:aws:states:us-east-1:123456789012:stateMachine:vulnerable-workflow"

			mock := &mockStepFunctionsApi{
				listStateMachinesFn: func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
					return &sfn.ListStateMachinesOutput{
						StateMachines: []sfntypes.StateMachineListItem{
							{
								Name:            aws.String(smName),
								StateMachineArn: aws.String(smArn),
							},
						},
					}, nil
				},
				describeStateMachineFn: func(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
					return &sfn.DescribeStateMachineOutput{
						Name:            aws.String(smName),
						StateMachineArn: aws.String(smArn),
						Definition:      aws.String(tc.definition),
					}, nil
				},
			}

			sfnScanner := NewStepFunctionsScannerWithClient(mock, "us-east-1")
			results, err := sfnScanner.Scan(context.Background())
			require.NoError(t, err)
			require.Len(t, results, 1)

			r := results[0]
			assert.Equal(t, smName, r.ResourceID)
			assert.Equal(t, "SecaaS-StepFunctions", r.ResourceType)
			assert.Equal(t, "us-east-1", r.Region)
			assert.Equal(t, "stepfunctions_statemachine_no_secrets_in_definition", r.RuleID)
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "CRITICAL", r.Severity)

			metrics, ok := r.Metrics.(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, "Remove hardcoded credentials from state machine definition; use Secrets Manager tasks at runtime.", metrics["Recommendation"])
			issues, ok := metrics["SecurityIssues"].([]string)
			require.True(t, ok)
			assert.NotEmpty(t, issues)
		})
	}
}

func TestStepFunctionsScanner_ListStateMachinesError(t *testing.T) {
	mock := &mockStepFunctionsApi{
		listStateMachinesFn: func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	sfnScanner := NewStepFunctionsScannerWithClient(mock, "us-east-1")
	_, err := sfnScanner.Scan(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list Step Functions state machines")
}

func TestStepFunctionsScanner_DescribeStateMachineError_SkipsGracefully(t *testing.T) {
	mock := &mockStepFunctionsApi{
		listStateMachinesFn: func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
			return &sfn.ListStateMachinesOutput{
				StateMachines: []sfntypes.StateMachineListItem{
					{
						Name:            aws.String("error-sm"),
						StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:error-sm"),
					},
					{
						Name:            aws.String("good-sm"),
						StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:good-sm"),
					},
				},
			}, nil
		},
		describeStateMachineFn: func(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
			if aws.ToString(params.StateMachineArn) == "arn:aws:states:us-east-1:123456789012:stateMachine:error-sm" {
				return nil, errors.New("state machine not found")
			}
			return &sfn.DescribeStateMachineOutput{
				Name:            aws.String("good-sm"),
				StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:good-sm"),
				Definition:      aws.String(`{"Comment":"clean"}`),
			}, nil
		},
	}

	sfnScanner := NewStepFunctionsScannerWithClient(mock, "us-east-1")
	results, err := sfnScanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "good-sm", results[0].ResourceID)
	assert.Equal(t, "PASS", results[0].Status)
}

func TestStepFunctionsScanner_EmptyStateMachines(t *testing.T) {
	mock := &mockStepFunctionsApi{
		listStateMachinesFn: func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
			return &sfn.ListStateMachinesOutput{
				StateMachines: []sfntypes.StateMachineListItem{},
			}, nil
		},
	}

	sfnScanner := NewStepFunctionsScannerWithClient(mock, "us-east-1")
	results, err := sfnScanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestStepFunctionsScanner_PaginationAndResourceLimit(t *testing.T) {
	mock := &mockStepFunctionsApi{
		listStateMachinesFn: func(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
			if params.NextToken == nil {
				return &sfn.ListStateMachinesOutput{
					StateMachines: []sfntypes.StateMachineListItem{
						{
							Name:            aws.String("sm-1"),
							StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:sm-1"),
						},
					},
					NextToken: aws.String("page-2-token"),
				}, nil
			}
			return &sfn.ListStateMachinesOutput{
				StateMachines: []sfntypes.StateMachineListItem{
					{
						Name:            aws.String("sm-2"),
						StateMachineArn: aws.String("arn:aws:states:us-east-1:123456789012:stateMachine:sm-2"),
					},
				},
			}, nil
		},
		describeStateMachineFn: func(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
			arn := aws.ToString(params.StateMachineArn)
			return &sfn.DescribeStateMachineOutput{
				StateMachineArn: aws.String(arn),
				Definition:      aws.String(`{"Comment":"clean"}`),
			}, nil
		},
	}

	// Limit to 1 resource
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	sfnScanner := NewStepFunctionsScannerWithClient(mock, "us-east-1")
	results, err := sfnScanner.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "sm-1", results[0].ResourceID)
}
