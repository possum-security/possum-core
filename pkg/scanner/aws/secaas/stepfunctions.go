package secaas

import (
	"context"
	"fmt"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
)

// StepFunctionsApi defines the mockable interface for AWS Step Functions API operations.
type StepFunctionsApi interface {
	ListStateMachines(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
}

// StepFunctionsScanner evaluates AWS Step Functions state machine security postures.
type StepFunctionsScanner struct {
	client StepFunctionsApi
	region string
}

// NewStepFunctionsScanner creates a StepFunctionsScanner with the provided AWS config.
func NewStepFunctionsScanner(cfg aws.Config) *StepFunctionsScanner {
	return &StepFunctionsScanner{
		client: sfn.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewStepFunctionsScannerWithClient creates a StepFunctionsScanner with a custom/mock client.
func NewStepFunctionsScannerWithClient(client StepFunctionsApi, region string) *StepFunctionsScanner {
	return &StepFunctionsScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *StepFunctionsScanner) Name() string {
	return "StepFunctions-SecaaS-Scanner"
}

var (
	stepFunctionsSecretKeywords = []string{
		"password",
		"secret_key",
		"api_key",
		"auth_token",
	}
)

func checkStepFunctionsDefinitionSecrets(def string) (bool, []string) {
	if def == "" {
		return false, nil
	}
	var issues []string
	upper := strings.ToUpper(def)
	if strings.Contains(upper, "AKIA") {
		issues = append(issues, "State machine definition contains AWS Access Key ID pattern (AKIA)")
	}
	if strings.Contains(upper, "BEGIN RSA PRIVATE KEY") {
		issues = append(issues, "State machine definition contains RSA private key material")
	}

	lower := strings.ToLower(def)
	for _, kw := range stepFunctionsSecretKeywords {
		if strings.Contains(lower, kw) {
			issues = append(issues, fmt.Sprintf("State machine definition contains sensitive keyword '%s'", kw))
		}
	}

	return len(issues) > 0, issues
}

// Scan audits all Step Functions state machines in the configured region against security best practices.
func (s *StepFunctionsScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	var nextToken *string
	for {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		output, err := s.client.ListStateMachines(ctx, &sfn.ListStateMachinesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Step Functions state machines: %w", err)
		}

		for _, sm := range output.StateMachines {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++

			smArn := aws.ToString(sm.StateMachineArn)
			smName := aws.ToString(sm.Name)

			desc, err := s.client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
				StateMachineArn: sm.StateMachineArn,
			})
			if err != nil || desc == nil {
				continue
			}

			if descName := aws.ToString(desc.Name); descName != "" {
				smName = descName
			}
			if descArn := aws.ToString(desc.StateMachineArn); descArn != "" {
				smArn = descArn
			}
			if smName == "" {
				smName = smArn
			}
			if smArn == "" {
				smArn = fmt.Sprintf("arn:aws:states:%s::stateMachine:%s", region, smName)
			}
			if smName == "" {
				smName = "unknown"
			}

			nodes := []graph.Node{{ID: smArn, NodeType: "SecaaS-StepFunctions"}}

			definition := aws.ToString(desc.Definition)
			hasSecret, issues := checkStepFunctionsDefinitionSecrets(definition)

			// Check a: stepfunctions_statemachine_no_secrets_in_definition (CRITICAL)
			if hasSecret {
				results = append(results, scanner.ScanResult{
					ResourceID:   smName,
					ResourceType: "SecaaS-StepFunctions",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "stepfunctions_statemachine_no_secrets_in_definition",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"StateMachineName": smName,
						"StateMachineArn":  smArn,
						"StatusExtended":   fmt.Sprintf("Step Functions state machine %s definition contains hardcoded sensitive credentials or secrets.", smName),
						"SecurityIssues":   issues,
						"Recommendation":   "Remove hardcoded credentials from state machine definition; use Secrets Manager tasks at runtime.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   smName,
					ResourceType: "SecaaS-StepFunctions",
					Region:       region,
					Status:       "PASS",
					RuleID:       "stepfunctions_statemachine_no_secrets_in_definition",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"StateMachineName": smName,
						"StateMachineArn":  smArn,
						"StatusExtended":   fmt.Sprintf("Step Functions state machine %s definition does not contain hardcoded secrets.", smName),
					},
					Nodes: nodes,
				})
			}
		}

		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}

	return results, nil
}
