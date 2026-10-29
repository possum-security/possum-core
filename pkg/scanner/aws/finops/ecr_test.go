package finops_test

import (
	"context"
	"testing"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockECRClient struct {
	describeRepositoriesOutput *ecr.DescribeRepositoriesOutput
	describeImagesOutput       *ecr.DescribeImagesOutput
	err                        error
}

func (m *mockECRClient) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.describeRepositoriesOutput, nil
}

func (m *mockECRClient) DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.describeImagesOutput, nil
}

func TestECRScanner_OrphanedWithCriticalCVEs_ImageScanFindings(t *testing.T) {
	mockClient := &mockECRClient{
		describeRepositoriesOutput: &ecr.DescribeRepositoriesOutput{
			Repositories: []ecrtypes.Repository{
				{
					RepositoryName: aws.String("payments-service"),
					RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/payments-service"),
				},
			},
		},
		describeImagesOutput: &ecr.DescribeImagesOutput{
			ImageDetails: []ecrtypes.ImageDetail{
				{
					ImageDigest:      aws.String("sha256:111122223333"),
					ImageTags:        []string{},                   // untagged -> orphaned
					ImageSizeInBytes: aws.Int64(500 * 1024 * 1024), // 500 MB
					ImageScanFindingsSummary: &ecrtypes.ImageScanFindingsSummary{
						FindingSeverityCounts: map[string]int32{
							"CRITICAL": 5,
							"HIGH":     3,
						},
					},
				},
			},
		},
	}

	sc := finops.NewECRScannerWithClient(mockClient, 180, true)
	assert.Equal(t, "ECR-Image-Scanner", sc.Name())

	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.True(t, res.IsOrphaned)
	assert.Equal(t, "ECR_IMAGE", res.ResourceType)
	assert.Equal(t, "sha256:111122223333", res.ResourceID)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, 5, metrics["CriticalCVEs"])
	assert.Equal(t, 3, metrics["HighCVEs"])
	assert.Equal(t, true, metrics["ZombieRiskBounty"])

	rec, ok := metrics["Recommendation"].(string)
	require.True(t, ok)
	assert.Contains(t, rec, "Deleting orphaned image untagged saves")
	assert.Contains(t, rec, "in ECR storage and eliminates 5 critical CVEs.")
}

func TestECRScanner_OrphanedWithContextVulnerabilities(t *testing.T) {
	oldDate := time.Now().AddDate(0, 0, -200) // 200 days old -> stale image (>180)
	mockClient := &mockECRClient{
		describeRepositoriesOutput: &ecr.DescribeRepositoriesOutput{
			Repositories: []ecrtypes.Repository{
				{
					RepositoryName: aws.String("auth-service"),
				},
			},
		},
		describeImagesOutput: &ecr.DescribeImagesOutput{
			ImageDetails: []ecrtypes.ImageDetail{
				{
					ImageDigest:      aws.String("sha256:444455556666"),
					ImageTags:        []string{"v0.1.0"},
					ImagePushedAt:    &oldDate,
					ImageSizeInBytes: aws.Int64(1024 * 1024 * 1024), // 1 GB -> $0.10/mo
				},
			},
		},
	}

	sc := finops.NewECRScannerWithClient(mockClient, 180, true)

	// Pass vulnerabilities via context
	vulnFindings := []model.SecurityFinding{
		{
			ResourceID: "auth-service:v0.1.0@sha256:444455556666",
			RuleID:     "CVE-2023-9999",
			Severity:   "CRITICAL",
		},
		{
			ResourceID: "auth-service:v0.1.0@sha256:444455556666",
			RuleID:     "CVE-2023-8888",
			Severity:   "CRITICAL",
		},
	}
	ctx := context.WithValue(context.Background(), "ContainerVulnerabilities", vulnFindings)

	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.True(t, res.IsOrphaned)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 2, metrics["CriticalCVEs"])
	assert.Equal(t, true, metrics["ZombieRiskBounty"])

	rec, ok := metrics["Recommendation"].(string)
	require.True(t, ok)
	expectedRec := "Deleting orphaned image v0.1.0 saves $0.10/mo in ECR storage and eliminates 2 critical CVEs."
	assert.Equal(t, expectedRec, rec)
}

func TestECRScanner_CleanOrphanedImage_NoVulnerabilities(t *testing.T) {
	mockClient := &mockECRClient{
		describeRepositoriesOutput: &ecr.DescribeRepositoriesOutput{
			Repositories: []ecrtypes.Repository{
				{
					RepositoryName: aws.String("clean-app"),
				},
			},
		},
		describeImagesOutput: &ecr.DescribeImagesOutput{
			ImageDetails: []ecrtypes.ImageDetail{
				{
					ImageDigest:      aws.String("sha256:clean123"),
					ImageTags:        []string{}, // untagged -> orphaned
					ImageSizeInBytes: aws.Int64(100 * 1024 * 1024),
				},
			},
		},
	}

	sc := finops.NewECRScannerWithClient(mockClient, 180, true)
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.True(t, res.IsOrphaned)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Nil(t, metrics["ZombieRiskBounty"])
	assert.Equal(t, "Delete Untagged Image", metrics["Recommendation"])
}

func TestECRScanner_NewECRScanner_Defaults(t *testing.T) {
	cfg := aws.Config{}
	sc := finops.NewECRScanner(cfg, 0, false)
	require.NotNil(t, sc)
	assert.Equal(t, 180, sc.RetentionDays)
	assert.False(t, sc.FlagUntagged)

	var _ scanner.Scanner = sc
}
