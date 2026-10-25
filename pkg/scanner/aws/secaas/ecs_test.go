package secaas

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
)

type mockECSClient struct {
	listTaskDefinitionsOutput    *ecs.ListTaskDefinitionsOutput
	describeTaskDefinitionOutput *ecs.DescribeTaskDefinitionOutput
	err                          error
}

func (m *mockECSClient) ListTaskDefinitions(ctx context.Context, params *ecs.ListTaskDefinitionsInput, optFns ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listTaskDefinitionsOutput, nil
}

func (m *mockECSClient) DescribeTaskDefinition(ctx context.Context, params *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.describeTaskDefinitionOutput, nil
}

func TestECSSecScanner_Compliant(t *testing.T) {
	taskArn := "arn:aws:ecs:us-east-1:123456789012:task-definition/secure-app:1"
	mock := &mockECSClient{
		listTaskDefinitionsOutput: &ecs.ListTaskDefinitionsOutput{
			TaskDefinitionArns: []string{taskArn},
		},
		describeTaskDefinitionOutput: &ecs.DescribeTaskDefinitionOutput{
			TaskDefinition: &ecstypes.TaskDefinition{
				Family:   aws.String("secure-app"),
				Revision: 1,
				PidMode:  ecstypes.PidModeTask,
				IpcMode:  ecstypes.IpcModeTask,
				ContainerDefinitions: []ecstypes.ContainerDefinition{
					{
						Name:                   aws.String("web"),
						Privileged:             aws.Bool(false),
						ReadonlyRootFilesystem: aws.Bool(true),
						Environment: []ecstypes.KeyValuePair{
							{
								Name:  aws.String("PORT"),
								Value: aws.String("8080"),
							},
						},
					},
				},
			},
		},
	}

	scanner := NewECSSecScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 4)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for %s", r.RuleID)
	}
}

func TestECSSecScanner_NonCompliant(t *testing.T) {
	taskArn := "arn:aws:ecs:us-east-1:123456789012:task-definition/risky-app:3"
	mock := &mockECSClient{
		listTaskDefinitionsOutput: &ecs.ListTaskDefinitionsOutput{
			TaskDefinitionArns: []string{taskArn},
		},
		describeTaskDefinitionOutput: &ecs.DescribeTaskDefinitionOutput{
			TaskDefinition: &ecstypes.TaskDefinition{
				Family:   aws.String("risky-app"),
				Revision: 3,
				PidMode:  ecstypes.PidModeHost,
				IpcMode:  ecstypes.IpcModeHost,
				ContainerDefinitions: []ecstypes.ContainerDefinition{
					{
						Name:                   aws.String("worker"),
						Privileged:             aws.Bool(true),
						ReadonlyRootFilesystem: aws.Bool(false),
						Environment: []ecstypes.KeyValuePair{
							{
								Name:  aws.String("DB_PASSWORD"),
								Value: aws.String("super-secret-plain-text"),
							},
						},
					},
				},
			},
		},
	}

	scanner := NewECSSecScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 4)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "FAIL", statusMap["ecs_task_definitions_no_privileged_containers"])
	assert.Equal(t, "FAIL", statusMap["ecs_task_definitions_host_namespace_not_shared"])
	assert.Equal(t, "FAIL", statusMap["ecs_task_definitions_containers_readonly_access"])
	assert.Equal(t, "FAIL", statusMap["ecs_task_definitions_no_environment_secrets"])
}
