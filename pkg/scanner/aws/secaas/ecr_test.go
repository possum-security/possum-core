package secaas

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
)

type mockECRClient struct {
	describeRepositoriesOutput *ecr.DescribeRepositoriesOutput
	getRepositoryPolicyOutput  *ecr.GetRepositoryPolicyOutput
	getRepositoryPolicyErr     error
	getLifecyclePolicyOutput   *ecr.GetLifecyclePolicyOutput
	getLifecyclePolicyErr      error
	err                        error
}

func (m *mockECRClient) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.describeRepositoriesOutput, nil
}

func (m *mockECRClient) GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	if m.getRepositoryPolicyErr != nil {
		return nil, m.getRepositoryPolicyErr
	}
	return m.getRepositoryPolicyOutput, nil
}

func (m *mockECRClient) GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	if m.getLifecyclePolicyErr != nil {
		return nil, m.getLifecyclePolicyErr
	}
	return m.getLifecyclePolicyOutput, nil
}

func TestECRSecScanner_Compliant(t *testing.T) {
	mock := &mockECRClient{
		describeRepositoriesOutput: &ecr.DescribeRepositoriesOutput{
			Repositories: []ecrtypes.Repository{
				{
					RepositoryName: aws.String("secure-app"),
					RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/secure-app"),
					ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{
						ScanOnPush: true,
					},
					ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable,
				},
			},
		},
		getRepositoryPolicyOutput: &ecr.GetRepositoryPolicyOutput{
			PolicyText: aws.String(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"ecr:*"}]}`),
		},
		getLifecyclePolicyOutput: &ecr.GetLifecyclePolicyOutput{
			LifecyclePolicyText: aws.String(`{"rules":[{"rulePriority":1,"description":"expire","selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":14},"action":{"type":"expire"}}]}`),
		},
	}

	scanner := NewECRSecScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 4)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for %s", r.RuleID)
	}
}

func TestECRSecScanner_NonCompliant(t *testing.T) {
	mock := &mockECRClient{
		describeRepositoriesOutput: &ecr.DescribeRepositoriesOutput{
			Repositories: []ecrtypes.Repository{
				{
					RepositoryName: aws.String("open-app"),
					RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/open-app"),
					ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{
						ScanOnPush: false,
					},
					ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
				},
			},
		},
		getRepositoryPolicyOutput: &ecr.GetRepositoryPolicyOutput{
			PolicyText: aws.String(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"ecr:*"}]}`),
		},
		getLifecyclePolicyErr: fmt.Errorf("LifecyclePolicyNotFoundException"),
	}

	scanner := NewECRSecScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 4)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "FAIL", statusMap["ecr_repositories_scan_images_on_push_enabled"])
	assert.Equal(t, "FAIL", statusMap["ecr_repositories_tag_immutability"])
	assert.Equal(t, "FAIL", statusMap["ecr_repositories_not_publicly_accessible"])
	assert.Equal(t, "FAIL", statusMap["ecr_repositories_lifecycle_policy_enabled"])
}
