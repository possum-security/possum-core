package secaas

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
)

type mockSecretsManagerClient struct {
	listSecretsOutput       *secretsmanager.ListSecretsOutput
	getResourcePolicyOutput *secretsmanager.GetResourcePolicyOutput
	err                     error
}

func (m *mockSecretsManagerClient) ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listSecretsOutput, nil
}

func (m *mockSecretsManagerClient) GetResourcePolicy(ctx context.Context, params *secretsmanager.GetResourcePolicyInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.getResourcePolicyOutput, nil
}

func TestSecretsManagerScanner_Compliant(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -10)
	mock := &mockSecretsManagerClient{
		listSecretsOutput: &secretsmanager.ListSecretsOutput{
			SecretList: []secretsmanagertypes.SecretListEntry{
				{
					Name:            aws.String("prod/db/credentials"),
					ARN:             aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/credentials"),
					RotationEnabled: aws.Bool(true),
					LastRotatedDate: &recent,
				},
			},
		},
		getResourcePolicyOutput: &secretsmanager.GetResourcePolicyOutput{
			ResourcePolicy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app"},"Action":"secretsmanager:GetSecretValue"}]}`),
		},
	}

	scanner := NewSecretsManagerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for %s", r.RuleID)
	}
}

func TestSecretsManagerScanner_NonCompliant(t *testing.T) {
	oldDate := time.Now().AddDate(0, 0, -120)
	mock := &mockSecretsManagerClient{
		listSecretsOutput: &secretsmanager.ListSecretsOutput{
			SecretList: []secretsmanagertypes.SecretListEntry{
				{
					Name:            aws.String("legacy/secret"),
					ARN:             aws.String("arn:aws:secretsmanager:us-east-1:123456789012:secret:legacy/secret"),
					RotationEnabled: aws.Bool(false),
					CreatedDate:     &oldDate,
				},
			},
		},
		getResourcePolicyOutput: &secretsmanager.GetResourcePolicyOutput{
			ResourcePolicy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue"}]}`),
		},
	}

	scanner := NewSecretsManagerScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "FAIL", statusMap["secretsmanager_automatic_rotation_enabled"])
	assert.Equal(t, "FAIL", statusMap["secretsmanager_secret_rotated_periodically"])
	assert.Equal(t, "FAIL", statusMap["secretsmanager_not_publicly_accessible"])
}
