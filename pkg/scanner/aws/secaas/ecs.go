package secaas

import (
	"context"
	"fmt"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// ECSClient defines the interface for ECS API operations.
type ECSClient interface {
	ListTaskDefinitions(ctx context.Context, params *ecs.ListTaskDefinitionsInput, optFns ...func(*ecs.Options)) (*ecs.ListTaskDefinitionsOutput, error)
	DescribeTaskDefinition(ctx context.Context, params *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// ECSSecScanner evaluates ECS container and task definition configurations.
type ECSSecScanner struct {
	client ECSClient
	region string
}

// NewECSSecScanner creates an ECSSecScanner with AWS config.
func NewECSSecScanner(cfg aws.Config) *ECSSecScanner {
	return &ECSSecScanner{
		client: ecs.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewECSSecScannerWithClient creates an ECSSecScanner with custom/mock client.
func NewECSSecScannerWithClient(client ECSClient, region string) *ECSSecScanner {
	return &ECSSecScanner{
		client: client,
		region: region,
	}
}

func (s *ECSSecScanner) Name() string {
	return "ECS-SecaaS-Scanner"
}

func (s *ECSSecScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
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

	paginator := ecs.NewListTaskDefinitionsPaginator(s.client, &ecs.ListTaskDefinitionsInput{
		Status: ecstypes.TaskDefinitionStatusActive,
	})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list ECS task definitions: %w", err)
		}

		for _, taskDefArn := range page.TaskDefinitionArns {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			descOut, err := s.client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: aws.String(taskDefArn),
			})
			if err != nil || descOut.TaskDefinition == nil {
				continue
			}

			td := descOut.TaskDefinition
			family := aws.ToString(td.Family)
			revision := td.Revision
			resourceID := fmt.Sprintf("%s:%d", family, revision)

			// 1. Privileged containers (ecs_task_definitions_no_privileged_containers - HIGH)
			hasPrivileged := false
			var privContainers []string
			for _, c := range td.ContainerDefinitions {
				if aws.ToBool(c.Privileged) {
					hasPrivileged = true
					privContainers = append(privContainers, aws.ToString(c.Name))
				}
			}

			if hasPrivileged {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecs_task_definitions_no_privileged_containers",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"Containers":     privContainers,
						"StatusExtended": fmt.Sprintf("ECS task definition %s contains privileged container(s): %v.", resourceID, privContainers),
						"SecurityIssues": []string{"Container running with host-level root privileges"},
						"Recommendation": "Run containers without elevated rights (privileged: false).",
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecs_task_definitions_no_privileged_containers",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"StatusExtended": fmt.Sprintf("ECS task definition %s has no privileged containers.", resourceID),
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			}

			// 2. Host namespace sharing (ecs_task_definitions_host_namespace_not_shared - HIGH)
			sharesHostNamespace := td.PidMode == ecstypes.PidModeHost || td.IpcMode == ecstypes.IpcModeHost
			if sharesHostNamespace {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecs_task_definitions_host_namespace_not_shared",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"PidMode":        string(td.PidMode),
						"IpcMode":        string(td.IpcMode),
						"StatusExtended": fmt.Sprintf("ECS task definition %s shares the host PID or IPC namespace.", resourceID),
						"SecurityIssues": []string{"Containers share host PID/IPC namespace, allowing cross-container inspection"},
						"Recommendation": "Do not configure pidMode or ipcMode as 'host' in ECS task definitions.",
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecs_task_definitions_host_namespace_not_shared",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"StatusExtended": fmt.Sprintf("ECS task definition %s does not share host namespace.", resourceID),
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			}

			// 3. Read-only root filesystem (ecs_task_definitions_containers_readonly_access - MEDIUM)
			allReadOnly := true
			for _, c := range td.ContainerDefinitions {
				if !aws.ToBool(c.ReadonlyRootFilesystem) {
					allReadOnly = false
					break
				}
			}

			if allReadOnly && len(td.ContainerDefinitions) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecs_task_definitions_containers_readonly_access",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"StatusExtended": fmt.Sprintf("ECS task definition %s containers have read-only root filesystems.", resourceID),
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecs_task_definitions_containers_readonly_access",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"StatusExtended": fmt.Sprintf("ECS task definition %s contains container(s) with writable root filesystems.", resourceID),
						"SecurityIssues": []string{"Container has write access to root filesystem"},
						"Recommendation": "Set readonlyRootFilesystem: true on container definitions.",
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			}

			// 4. No plaintext secrets in environment variables (ecs_task_definitions_no_environment_secrets - HIGH)
			var secretEnvVars []string
			secretKeywords := []string{"PASSWORD", "SECRET", "API_KEY", "ACCESS_KEY", "AUTH_TOKEN"}

			for _, c := range td.ContainerDefinitions {
				for _, env := range c.Environment {
					envName := strings.ToUpper(aws.ToString(env.Name))
					envVal := aws.ToString(env.Value)

					for _, kw := range secretKeywords {
						if strings.Contains(envName, kw) && envVal != "" &&
							!strings.HasPrefix(envVal, "arn:aws:secretsmanager") &&
							!strings.HasPrefix(envVal, "arn:aws:ssm") {
							secretEnvVars = append(secretEnvVars, fmt.Sprintf("%s:%s", aws.ToString(c.Name), envName))
							break
						}
					}
				}
			}

			if len(secretEnvVars) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "ecs_task_definitions_no_environment_secrets",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"SecretEnvVars":  secretEnvVars,
						"StatusExtended": fmt.Sprintf("ECS task definition %s contains plaintext secrets in environment variables: %v.", resourceID, secretEnvVars),
						"SecurityIssues": []string{"Plaintext secrets exposed in environment variables"},
						"Recommendation": "Store secrets in AWS Secrets Manager or SSM Parameter Store and reference them via secrets parameter.",
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-ECSTaskDefinition",
					Region:       region,
					Status:       "PASS",
					RuleID:       "ecs_task_definitions_no_environment_secrets",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"TaskDefinition": resourceID,
						"StatusExtended": fmt.Sprintf("ECS task definition %s has no plaintext secrets in environment variables.", resourceID),
					},
					Nodes: []graph.Node{{ID: taskDefArn, NodeType: "SecaaS-ECSTaskDefinition"}},
				})
			}
		}
	}

	return results, nil
}
