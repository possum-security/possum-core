package secaas

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSageMakerClient struct {
	listOutput      *sagemaker.ListNotebookInstancesOutput
	listErr         error
	describeOutputs map[string]*sagemaker.DescribeNotebookInstanceOutput
	describeErr     error
	describeFunc    func(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput) (*sagemaker.DescribeNotebookInstanceOutput, error)
}

func (m *mockSageMakerClient) ListNotebookInstances(ctx context.Context, params *sagemaker.ListNotebookInstancesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listOutput, nil
}

func (m *mockSageMakerClient) DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error) {
	if m.describeFunc != nil {
		return m.describeFunc(ctx, params)
	}
	if m.describeErr != nil {
		return nil, m.describeErr
	}
	name := aws.ToString(params.NotebookInstanceName)
	if out, ok := m.describeOutputs[name]; ok {
		return out, nil
	}
	return nil, fmt.Errorf("notebook instance not found: %s", name)
}

func TestSageMakerScanner_Compliant(t *testing.T) {
	instanceName := "secure-notebook"
	instanceArn := "arn:aws:sagemaker:us-east-1:123456789012:notebook-instance/secure-notebook"
	subnetID := "subnet-0123456789abcdef0"
	kmsKeyID := "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{
			NotebookInstances: []sagemakertypes.NotebookInstanceSummary{
				{
					NotebookInstanceName: aws.String(instanceName),
					NotebookInstanceArn:  aws.String(instanceArn),
				},
			},
		},
		describeOutputs: map[string]*sagemaker.DescribeNotebookInstanceOutput{
			instanceName: {
				NotebookInstanceName: aws.String(instanceName),
				NotebookInstanceArn:  aws.String(instanceArn),
				SubnetId:             aws.String(subnetID),
				KmsKeyId:             aws.String(kmsKeyID),
				RootAccess:           sagemakertypes.RootAccessDisabled,
			},
		},
	}

	scanner := NewSageMakerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5)

	rulesMap := make(map[string]scannerResultCheck)
	for _, r := range results {
		assert.Equal(t, instanceArn, r.ResourceID)
		assert.Equal(t, "SecaaS-SageMakerNotebookInstance", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)
		require.Len(t, r.Nodes, 1)
		assert.Equal(t, instanceArn, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-SageMakerNotebookInstance", r.Nodes[0].NodeType)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, instanceName, metrics["NotebookInstanceName"])
		assert.NotEmpty(t, metrics["StatusExtended"])

		rulesMap[r.RuleID] = scannerResultCheck{
			status:   r.Status,
			severity: r.Severity,
		}
	}

	expectedRules := []string{
		"sagemaker_notebook_instance_vpc_settings_configured",
		"sagemaker_notebook_instance_vpc_settings_configured",
		"sagemaker_notebook_instance_encryption_enabled",
		"sagemaker_notebook_instance_encryption_enabled",
		"sagemaker_notebook_instance_root_access_disabled",
	}

	for _, ruleID := range expectedRules {
		chk, exists := rulesMap[ruleID]
		assert.True(t, exists, "rule %s should be present in results", ruleID)
		assert.Equal(t, "PASS", chk.status)
		assert.Equal(t, "INFO", chk.severity)
	}
}

func TestSageMakerScanner_NonCompliant(t *testing.T) {
	instanceName := "insecure-notebook"
	instanceArn := "arn:aws:sagemaker:us-west-2:123456789012:notebook-instance/insecure-notebook"

	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{
			NotebookInstances: []sagemakertypes.NotebookInstanceSummary{
				{
					NotebookInstanceName: aws.String(instanceName),
					NotebookInstanceArn:  aws.String(instanceArn),
				},
			},
		},
		describeOutputs: map[string]*sagemaker.DescribeNotebookInstanceOutput{
			instanceName: {
				NotebookInstanceName: aws.String(instanceName),
				NotebookInstanceArn:  aws.String(instanceArn),
				SubnetId:             nil,                              // No VPC
				KmsKeyId:             nil,                              // No KMS encryption
				RootAccess:           sagemakertypes.RootAccessEnabled, // Root access enabled
			},
		},
	}

	scanner := NewSageMakerScannerWithClient(mock, "us-west-2")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5)

	rulesMap := make(map[string]scannerResultCheck)
	for _, r := range results {
		assert.Equal(t, instanceArn, r.ResourceID)
		assert.Equal(t, "SecaaS-SageMakerNotebookInstance", r.ResourceType)
		assert.Equal(t, "us-west-2", r.Region)
		assert.Equal(t, "FAIL", r.Status)
		require.Len(t, r.Nodes, 1)

		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, instanceName, metrics["NotebookInstanceName"])
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])
		assert.NotEmpty(t, metrics["SecurityIssues"])

		rulesMap[r.RuleID] = scannerResultCheck{
			status:   r.Status,
			severity: r.Severity,
		}
	}

	// VPC checks: FAIL (HIGH)
	assert.Equal(t, "HIGH", rulesMap["sagemaker_notebook_instance_vpc_settings_configured"].severity)
	assert.Equal(t, "HIGH", rulesMap["sagemaker_notebook_instance_vpc_settings_configured"].severity)

	// Encryption checks: FAIL (HIGH)
	assert.Equal(t, "HIGH", rulesMap["sagemaker_notebook_instance_encryption_enabled"].severity)
	assert.Equal(t, "HIGH", rulesMap["sagemaker_notebook_instance_encryption_enabled"].severity)

	// Root access check: FAIL (MEDIUM)
	assert.Equal(t, "MEDIUM", rulesMap["sagemaker_notebook_instance_root_access_disabled"].severity)
}

func TestSageMakerScanner_PartiallyCompliant(t *testing.T) {
	instanceName := "mixed-notebook"
	instanceArn := "arn:aws:sagemaker:eu-west-1:123456789012:notebook-instance/mixed-notebook"

	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{
			NotebookInstances: []sagemakertypes.NotebookInstanceSummary{
				{
					NotebookInstanceName: aws.String(instanceName),
					NotebookInstanceArn:  aws.String(instanceArn),
				},
			},
		},
		describeOutputs: map[string]*sagemaker.DescribeNotebookInstanceOutput{
			instanceName: {
				NotebookInstanceName: aws.String(instanceName),
				NotebookInstanceArn:  aws.String(instanceArn),
				SubnetId:             aws.String("subnet-12345"),
				KmsKeyId:             aws.String(""), // empty string should be treated as not configured
				RootAccess:           sagemakertypes.RootAccessDisabled,
			},
		},
	}

	scanner := NewSageMakerScannerWithClient(mock, "eu-west-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5)

	rulesMap := make(map[string]scannerResultCheck)
	for _, r := range results {
		rulesMap[r.RuleID] = scannerResultCheck{
			status:   r.Status,
			severity: r.Severity,
		}
	}

	// VPC: PASS
	assert.Equal(t, "PASS", rulesMap["sagemaker_notebook_instance_vpc_settings_configured"].status)
	assert.Equal(t, "PASS", rulesMap["sagemaker_notebook_instance_vpc_settings_configured"].status)

	// Encryption: FAIL
	assert.Equal(t, "FAIL", rulesMap["sagemaker_notebook_instance_encryption_enabled"].status)
	assert.Equal(t, "HIGH", rulesMap["sagemaker_notebook_instance_encryption_enabled"].severity)
	assert.Equal(t, "FAIL", rulesMap["sagemaker_notebook_instance_encryption_enabled"].status)
	assert.Equal(t, "HIGH", rulesMap["sagemaker_notebook_instance_encryption_enabled"].severity)

	// Root access: PASS
	assert.Equal(t, "PASS", rulesMap["sagemaker_notebook_instance_root_access_disabled"].status)
}

func TestSageMakerScanner_EmptyInstances(t *testing.T) {
	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{
			NotebookInstances: []sagemakertypes.NotebookInstanceSummary{},
		},
	}

	scanner := NewSageMakerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestSageMakerScanner_ListError(t *testing.T) {
	mock := &mockSageMakerClient{
		listErr: fmt.Errorf("AccessDeniedException: not authorized to perform sagemaker:ListNotebookInstances"),
	}

	scanner := NewSageMakerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list SageMaker notebook instances")
	assert.Nil(t, results)
}

func TestSageMakerScanner_DescribeError_SkipsGracefully(t *testing.T) {
	instance1 := "failing-notebook"
	instance2 := "healthy-notebook"

	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{
			NotebookInstances: []sagemakertypes.NotebookInstanceSummary{
				{NotebookInstanceName: aws.String(instance1)},
				{NotebookInstanceName: aws.String(instance2)},
			},
		},
		describeOutputs: map[string]*sagemaker.DescribeNotebookInstanceOutput{
			instance2: {
				NotebookInstanceName: aws.String(instance2),
				SubnetId:             aws.String("subnet-999"),
				KmsKeyId:             aws.String("kms-999"),
				RootAccess:           sagemakertypes.RootAccessDisabled,
			},
		},
		describeFunc: func(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput) (*sagemaker.DescribeNotebookInstanceOutput, error) {
			if aws.ToString(params.NotebookInstanceName) == instance1 {
				return nil, fmt.Errorf("InternalError: failed to describe instance")
			}
			return &sagemaker.DescribeNotebookInstanceOutput{
				NotebookInstanceName: aws.String(instance2),
				SubnetId:             aws.String("subnet-999"),
				KmsKeyId:             aws.String("kms-999"),
				RootAccess:           sagemakertypes.RootAccessDisabled,
			}, nil
		},
	}

	scanner := NewSageMakerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	// Instance 1 skipped, Instance 2 yielded 5 results
	require.Len(t, results, 5)
	for _, r := range results {
		metrics := r.Metrics.(map[string]interface{})
		assert.Equal(t, instance2, metrics["NotebookInstanceName"])
	}
}

func TestSageMakerScanner_ResourceLimit(t *testing.T) {
	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{
			NotebookInstances: []sagemakertypes.NotebookInstanceSummary{
				{NotebookInstanceName: aws.String("nb-1")},
				{NotebookInstanceName: aws.String("nb-2")},
			},
		},
		describeOutputs: map[string]*sagemaker.DescribeNotebookInstanceOutput{
			"nb-1": {
				NotebookInstanceName: aws.String("nb-1"),
				SubnetId:             aws.String("subnet-1"),
				KmsKeyId:             aws.String("kms-1"),
				RootAccess:           sagemakertypes.RootAccessDisabled,
			},
			"nb-2": {
				NotebookInstanceName: aws.String("nb-2"),
				SubnetId:             aws.String("subnet-2"),
				KmsKeyId:             aws.String("kms-2"),
				RootAccess:           sagemakertypes.RootAccessDisabled,
			},
		},
	}

	scanner := NewSageMakerScannerWithClient(mock, "us-east-1")
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	// Only 1 instance should be processed -> 5 results
	require.Len(t, results, 5)
	metrics := results[0].Metrics.(map[string]interface{})
	assert.Equal(t, "nb-1", metrics["NotebookInstanceName"])
}

func TestSageMakerScanner_EmptyResults(t *testing.T) {
	mock := &mockSageMakerClient{
		listOutput: &sagemaker.ListNotebookInstancesOutput{},
	}
	s := NewSageMakerScannerWithClient(mock, "us-east-1")
	require.NotNil(t, s)

	results, err := s.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

type scannerResultCheck struct {
	status   string
	severity string
}
