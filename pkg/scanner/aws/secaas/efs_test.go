package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockEFSApi struct {
	describeFileSystemsFn func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
}

func (m *mockEFSApi) DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	if m.describeFileSystemsFn != nil {
		return m.describeFileSystemsFn(ctx, params, optFns...)
	}
	return &efs.DescribeFileSystemsOutput{}, nil
}

func TestEFSScanner_EncryptedPass(t *testing.T) {
	mock := &mockEFSApi{
		describeFileSystemsFn: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId:  aws.String("fs-01234567"),
						FileSystemArn: aws.String("arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-01234567"),
						Encrypted:     aws.Bool(true),
						KmsKeyId:      aws.String("arn:aws:kms:us-east-1:123456789012:key/test-key-id"),
						Name:          aws.String("my-encrypted-fs"),
					},
				},
			}, nil
		},
	}

	scanner := NewEFSScannerWithClient(mock, "us-east-1")
	assert.Equal(t, "EFS-SecaaS-Scanner", scanner.Name())

	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, "fs-01234567", res.ResourceID)
	assert.Equal(t, "SecaaS-EFS", res.ResourceType)
	assert.Equal(t, "us-east-1", res.Region)
	assert.Equal(t, "PASS", res.Status)
	assert.Equal(t, "efs_encryption_at_rest_enabled", res.RuleID)
	assert.Equal(t, "INFO", res.Severity)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, metrics["Encrypted"])
	assert.Equal(t, "fs-01234567", metrics["FileSystemId"])
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/test-key-id", metrics["KmsKeyId"])

	require.Len(t, res.Nodes, 1)
	assert.Equal(t, "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-01234567", res.Nodes[0].ID)
	assert.Equal(t, "SecaaS-EFS", res.Nodes[0].NodeType)

	require.Len(t, res.Edges, 1)
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/test-key-id", res.Edges[0].To)
	assert.Equal(t, "ENCRYPTED_WITH", res.Edges[0].Relation)
}

func TestEFSScanner_UnencryptedFail(t *testing.T) {
	mock := &mockEFSApi{
		describeFileSystemsFn: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId:  aws.String("fs-unencrypted01"),
						FileSystemArn: aws.String("arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-unencrypted01"),
						Encrypted:     aws.Bool(false),
					},
				},
			}, nil
		},
	}

	scanner := NewEFSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)

	res := results[0]
	assert.Equal(t, "fs-unencrypted01", res.ResourceID)
	assert.Equal(t, "SecaaS-EFS", res.ResourceType)
	assert.Equal(t, "FAIL", res.Status)
	assert.Equal(t, "efs_encryption_at_rest_enabled", res.RuleID)
	assert.Equal(t, "HIGH", res.Severity)

	metrics, ok := res.Metrics.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, false, metrics["Encrypted"])
	assert.Equal(t, "Enable encryption at rest when creating EFS file systems.", metrics["Recommendation"])
	assert.Contains(t, metrics["SecurityIssues"], "EFS file system encryption at rest is disabled")
}

func TestEFSScanner_MultipleFileSystems(t *testing.T) {
	mock := &mockEFSApi{
		describeFileSystemsFn: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{
						FileSystemId: aws.String("fs-1"),
						Encrypted:    aws.Bool(true),
					},
					{
						FileSystemId: aws.String("fs-2"),
						Encrypted:    aws.Bool(false),
					},
				},
			}, nil
		},
	}

	scanner := NewEFSScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "INFO", results[0].Severity)
	assert.Equal(t, "FAIL", results[1].Status)
	assert.Equal(t, "HIGH", results[1].Severity)
}

func TestEFSScanner_Pagination(t *testing.T) {
	calls := 0
	mock := &mockEFSApi{
		describeFileSystemsFn: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			calls++
			if params.Marker == nil {
				return &efs.DescribeFileSystemsOutput{
					FileSystems: []efstypes.FileSystemDescription{
						{FileSystemId: aws.String("fs-page1"), Encrypted: aws.Bool(true)},
					},
					NextMarker: aws.String("marker-token"),
				}, nil
			}
			assert.Equal(t, "marker-token", *params.Marker)
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{FileSystemId: aws.String("fs-page2"), Encrypted: aws.Bool(false)},
				},
				NextMarker: nil,
			}, nil
		},
	}

	scanner := NewEFSScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	require.Len(t, results, 2)
	assert.Equal(t, "fs-page1", results[0].ResourceID)
	assert.Equal(t, "fs-page2", results[1].ResourceID)
}

func TestEFSScanner_Error(t *testing.T) {
	mock := &mockEFSApi{
		describeFileSystemsFn: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return nil, errors.New("efs describe error")
		},
	}

	scanner := NewEFSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "failed to describe EFS file systems")
}

func TestEFSScanner_ResourceLimit(t *testing.T) {
	mock := &mockEFSApi{
		describeFileSystemsFn: func(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
			return &efs.DescribeFileSystemsOutput{
				FileSystems: []efstypes.FileSystemDescription{
					{FileSystemId: aws.String("fs-1"), Encrypted: aws.Bool(true)},
					{FileSystemId: aws.String("fs-2"), Encrypted: aws.Bool(true)},
				},
			}, nil
		},
	}

	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	scanner := NewEFSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}


