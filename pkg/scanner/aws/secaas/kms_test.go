package secaas

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
)

type mockKMSClient struct {
	listKeysOutput             *kms.ListKeysOutput
	describeKeyOutput          *kms.DescribeKeyOutput
	getKeyPolicyOutput         *kms.GetKeyPolicyOutput
	getKeyRotationStatusOutput *kms.GetKeyRotationStatusOutput
	err                        error
}

func (m *mockKMSClient) ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listKeysOutput, nil
}

func (m *mockKMSClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.describeKeyOutput, nil
}

func (m *mockKMSClient) GetKeyPolicy(ctx context.Context, params *kms.GetKeyPolicyInput, optFns ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.getKeyPolicyOutput, nil
}

func (m *mockKMSClient) GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.getKeyRotationStatusOutput, nil
}

func TestKMSScanner_Compliant(t *testing.T) {
	keyID := "12345678-1234-1234-1234-123456789012"
	mock := &mockKMSClient{
		listKeysOutput: &kms.ListKeysOutput{
			Keys: []kmstypes.KeyListEntry{
				{
					KeyId:  aws.String(keyID),
					KeyArn: aws.String("arn:aws:kms:us-east-1:123456789012:key/" + keyID),
				},
			},
		},
		describeKeyOutput: &kms.DescribeKeyOutput{
			KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:      aws.String(keyID),
				KeyManager: kmstypes.KeyManagerTypeCustomer,
			},
		},
		getKeyRotationStatusOutput: &kms.GetKeyRotationStatusOutput{
			KeyRotationEnabled: true,
		},
		getKeyPolicyOutput: &kms.GetKeyPolicyOutput{
			Policy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"kms:*"}]}`),
		},
	}

	scanner := NewKMSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 2)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for %s", r.RuleID)
	}
}

func TestKMSScanner_NonCompliant(t *testing.T) {
	keyID := "87654321-4321-4321-4321-210987654321"
	mock := &mockKMSClient{
		listKeysOutput: &kms.ListKeysOutput{
			Keys: []kmstypes.KeyListEntry{
				{
					KeyId:  aws.String(keyID),
					KeyArn: aws.String("arn:aws:kms:us-east-1:123456789012:key/" + keyID),
				},
			},
		},
		describeKeyOutput: &kms.DescribeKeyOutput{
			KeyMetadata: &kmstypes.KeyMetadata{
				KeyId:      aws.String(keyID),
				KeyManager: kmstypes.KeyManagerTypeCustomer,
			},
		},
		getKeyRotationStatusOutput: &kms.GetKeyRotationStatusOutput{
			KeyRotationEnabled: false,
		},
		getKeyPolicyOutput: &kms.GetKeyPolicyOutput{
			Policy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:*"}]}`),
		},
	}

	scanner := NewKMSScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 2)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "FAIL", statusMap["kms_cmk_rotation_enabled"])
	assert.Equal(t, "FAIL", statusMap["kms_key_not_publicly_accessible"])
}
