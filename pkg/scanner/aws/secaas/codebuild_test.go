package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCodeBuildApi struct {
	listProjectsFn     func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	batchGetProjectsFn func(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

func (m *mockCodeBuildApi) ListProjects(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	if m.listProjectsFn != nil {
		return m.listProjectsFn(ctx, params, optFns...)
	}
	return &codebuild.ListProjectsOutput{}, nil
}

func (m *mockCodeBuildApi) BatchGetProjects(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	if m.batchGetProjectsFn != nil {
		return m.batchGetProjectsFn(ctx, params, optFns...)
	}
	return &codebuild.BatchGetProjectsOutput{}, nil
}

func TestCodeBuildScanner_Name(t *testing.T) {
	cbScanner := NewCodeBuildScannerWithClient(&mockCodeBuildApi{}, "us-east-1")
	assert.Equal(t, "CodeBuild-SecaaS-Scanner", cbScanner.Name())
}

func TestNewCodeBuildScanner(t *testing.T) {
	cbScanner := NewCodeBuildScanner(aws.Config{Region: "us-west-2"})
	require.NotNil(t, cbScanner)
	assert.Equal(t, "CodeBuild-SecaaS-Scanner", cbScanner.Name())
	assert.Equal(t, "us-west-2", cbScanner.region)
}

func TestCodeBuildScanner_Compliant_AllPassing(t *testing.T) {
	projectName := "secure-project"
	projectArn := "arn:aws:codebuild:us-east-1:123456789012:project/secure-project"

	mock := &mockCodeBuildApi{
		listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
			return &codebuild.ListProjectsOutput{
				Projects: []string{projectName},
			}, nil
		},
		batchGetProjectsFn: func(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
			return &codebuild.BatchGetProjectsOutput{
				Projects: []codebuildtypes.Project{
					{
						Name: aws.String(projectName),
						Arn:  aws.String(projectArn),
						Environment: &codebuildtypes.ProjectEnvironment{
							EnvironmentVariables: []codebuildtypes.EnvironmentVariable{
								{
									Name:  aws.String("APP_ENV"),
									Value: aws.String("production"),
									Type:  codebuildtypes.EnvironmentVariableTypePlaintext,
								},
								{
									Name:  aws.String("APP_PORT"),
									Value: aws.String("8080"),
									Type:  codebuildtypes.EnvironmentVariableTypePlaintext,
								},
								// Sensitive variable names stored safely in Secrets Manager or Parameter Store
								{
									Name:  aws.String("DB_PASSWORD"),
									Value: aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:db_pass"),
									Type:  codebuildtypes.EnvironmentVariableTypeSecretsManager,
								},
								{
									Name:  aws.String("API_KEY"),
									Value: aws.String("/app/api_key"),
									Type:  codebuildtypes.EnvironmentVariableTypeParameterStore,
								},
							},
						},
						Source: &codebuildtypes.ProjectSource{
							Type:     codebuildtypes.SourceTypeGithub,
							Location: aws.String("https://github.com/my-org/secure-repo.git"),
						},
						SecondarySources: []codebuildtypes.ProjectSource{
							{
								Type:     codebuildtypes.SourceTypeGithub,
								Location: aws.String("git@github.com:my-org/secondary-repo.git"),
							},
						},
					},
				},
			}, nil
		},
	}

	cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
	results, err := cbScanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	expectedRules := map[string]string{
		"codebuild_project_no_secrets_in_variables":                  "PASS",
		"codebuild_project_source_repo_url_no_sensitive_credentials": "PASS",
	}

	for _, r := range results {
		assert.Equal(t, projectName, r.ResourceID)
		assert.Equal(t, "SecaaS-CodeBuild", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "INFO", r.Severity)

		expectedStatus, ok := expectedRules[r.RuleID]
		require.True(t, ok, "unexpected rule %s", r.RuleID)
		assert.Equal(t, expectedStatus, r.Status)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		require.Len(t, r.Nodes, 1)
		assert.Equal(t, projectArn, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-CodeBuild", r.Nodes[0].NodeType)
	}
}

func TestCodeBuildScanner_NonCompliant_SecretsInVariables(t *testing.T) {
	testCases := []struct {
		name     string
		varName  string
		varValue string
	}{
		{name: "AKIA in value", varName: "AWS_KEY", varValue: "AKIAIOSFODNN7EXAMPLE"},
		{name: "BEGIN RSA PRIVATE KEY in value", varName: "SSH_KEY", varValue: "-----BEGIN RSA PRIVATE KEY-----\nMIIEow..."},
		{name: "password in name", varName: "DATABASE_PASSWORD", varValue: "supersecret123"},
		{name: "secret in name", varName: "CLIENT_SECRET", varValue: "secretval"},
		{name: "api_key in name", varName: "API_KEY", varValue: "key-12345"},
		{name: "token in name", varName: "GITHUB_TOKEN", varValue: "ghp_1234567890"},
		{name: "access_key in name", varName: "AWS_ACCESS_KEY_ID", varValue: "somekey"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			projectName := "vulnerable-project"
			projectArn := "arn:aws:codebuild:us-east-1:123456789012:project/vulnerable-project"

			mock := &mockCodeBuildApi{
				listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
					return &codebuild.ListProjectsOutput{
						Projects: []string{projectName},
					}, nil
				},
				batchGetProjectsFn: func(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
					return &codebuild.BatchGetProjectsOutput{
						Projects: []codebuildtypes.Project{
							{
								Name: aws.String(projectName),
								Arn:  aws.String(projectArn),
								Environment: &codebuildtypes.ProjectEnvironment{
									EnvironmentVariables: []codebuildtypes.EnvironmentVariable{
										{
											Name:  aws.String(tc.varName),
											Value: aws.String(tc.varValue),
											Type:  codebuildtypes.EnvironmentVariableTypePlaintext,
										},
									},
								},
								Source: &codebuildtypes.ProjectSource{
									Type:     codebuildtypes.SourceTypeGithub,
									Location: aws.String("https://github.com/my-org/my-repo.git"),
								},
							},
						},
					}, nil
				},
			}

			cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
			results, err := cbScanner.Scan(context.Background())
			require.NoError(t, err)
			require.Len(t, results, 2)

			var secretResult *scanner.ScanResult
			for i := range results {
				if results[i].RuleID == "codebuild_project_no_secrets_in_variables" {
					secretResult = &results[i]
					break
				}
			}

			require.NotNil(t, secretResult)
			assert.Equal(t, "FAIL", secretResult.Status)
			assert.Equal(t, "CRITICAL", secretResult.Severity)
			assert.Equal(t, projectName, secretResult.ResourceID)
			assert.Equal(t, "SecaaS-CodeBuild", secretResult.ResourceType)

			metrics, ok := secretResult.Metrics.(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, "Store sensitive environment variables in AWS Secrets Manager or Parameter Store instead of PLAINTEXT.", metrics["Recommendation"])
			assert.NotEmpty(t, metrics["SecurityIssues"])
		})
	}
}

func TestCodeBuildScanner_NonCompliant_SourceRepoUrlWithCredentials(t *testing.T) {
	testCases := []struct {
		name          string
		primaryURL    *string
		secondaryURLs []string
	}{
		{
			name:       "HTTPS with user:pass in primary source",
			primaryURL: aws.String("https://user:password123@github.com/my-org/my-repo.git"),
		},
		{
			name:       "HTTPS with x-token-auth in primary source",
			primaryURL: aws.String("https://x-token-auth:mysecrettoken@bitbucket.org/my-org/my-repo.git"),
		},
		{
			name:       "HTTPS with token in primary source",
			primaryURL: aws.String("https://ghp_1234567890abcdef@github.com/my-org/my-repo.git"),
		},
		{
			name:          "Embedded credentials in secondary source",
			primaryURL:    aws.String("https://github.com/my-org/clean-repo.git"),
			secondaryURLs: []string{"https://user:secret@gitlab.com/my-org/sub-repo.git"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			projectName := "repo-cred-project"
			projectArn := "arn:aws:codebuild:us-east-1:123456789012:project/repo-cred-project"

			var secondarySources []codebuildtypes.ProjectSource
			for _, sec := range tc.secondaryURLs {
				secondarySources = append(secondarySources, codebuildtypes.ProjectSource{
					Type:     codebuildtypes.SourceTypeGithub,
					Location: aws.String(sec),
				})
			}

			mock := &mockCodeBuildApi{
				listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
					return &codebuild.ListProjectsOutput{
						Projects: []string{projectName},
					}, nil
				},
				batchGetProjectsFn: func(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
					return &codebuild.BatchGetProjectsOutput{
						Projects: []codebuildtypes.Project{
							{
								Name:             aws.String(projectName),
								Arn:              aws.String(projectArn),
								Environment:      &codebuildtypes.ProjectEnvironment{},
								Source:           &codebuildtypes.ProjectSource{Location: tc.primaryURL},
								SecondarySources: secondarySources,
							},
						},
					}, nil
				},
			}

			cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
			results, err := cbScanner.Scan(context.Background())
			require.NoError(t, err)
			require.Len(t, results, 2)

			var credResult *scanner.ScanResult
			for i := range results {
				if results[i].RuleID == "codebuild_project_source_repo_url_no_sensitive_credentials" {
					credResult = &results[i]
					break
				}
			}

			require.NotNil(t, credResult)
			assert.Equal(t, "FAIL", credResult.Status)
			assert.Equal(t, "CRITICAL", credResult.Severity)
			assert.Equal(t, projectName, credResult.ResourceID)
			assert.Equal(t, "SecaaS-CodeBuild", credResult.ResourceType)

			metrics, ok := credResult.Metrics.(map[string]interface{})
			require.True(t, ok)
			assert.Equal(t, "Remove sensitive credentials from repository URL; use OAuth or CodeStar connections.", metrics["Recommendation"])
			assert.NotEmpty(t, metrics["SecurityIssues"])
		})
	}
}

func TestCodeBuildScanner_ListProjectsError(t *testing.T) {
	mock := &mockCodeBuildApi{
		listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
	_, err := cbScanner.Scan(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list CodeBuild projects")
}

func TestCodeBuildScanner_BatchGetProjectsError(t *testing.T) {
	mock := &mockCodeBuildApi{
		listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
			return &codebuild.ListProjectsOutput{
				Projects: []string{"proj-1"},
			}, nil
		},
		batchGetProjectsFn: func(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
			return nil, errors.New("internal error")
		},
	}

	cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
	_, err := cbScanner.Scan(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to batch get CodeBuild projects")
}

func TestCodeBuildScanner_EmptyProjects(t *testing.T) {
	mock := &mockCodeBuildApi{
		listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
			return &codebuild.ListProjectsOutput{
				Projects: []string{},
			}, nil
		},
	}

	cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
	results, err := cbScanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestCodeBuildScanner_PaginationAndResourceLimit(t *testing.T) {
	callCount := 0
	mock := &mockCodeBuildApi{
		listProjectsFn: func(ctx context.Context, params *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
			callCount++
			if params.NextToken == nil {
				return &codebuild.ListProjectsOutput{
					Projects:  []string{"proj-1", "proj-2"},
					NextToken: aws.String("token-page-2"),
				}, nil
			}
			return &codebuild.ListProjectsOutput{
				Projects: []string{"proj-3"},
			}, nil
		},
		batchGetProjectsFn: func(ctx context.Context, params *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
			var projs []codebuildtypes.Project
			for _, name := range params.Names {
				projs = append(projs, codebuildtypes.Project{
					Name: aws.String(name),
					Arn:  aws.String("arn:aws:codebuild:us-east-1:123456789012:project/" + name),
				})
			}
			return &codebuild.BatchGetProjectsOutput{Projects: projs}, nil
		},
	}

	// Limit to 2 resources
	ctx := context.WithValue(context.Background(), "ResourceLimit", 2)
	cbScanner := NewCodeBuildScannerWithClient(mock, "us-east-1")
	results, err := cbScanner.Scan(ctx)
	require.NoError(t, err)
	// 2 projects * 2 checks = 4 results
	assert.Len(t, results, 4)
}
