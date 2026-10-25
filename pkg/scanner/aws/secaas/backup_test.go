package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockBackupClient struct {
	listBackupPlansOutput  *backup.ListBackupPlansOutput
	listBackupPlansErr     error
	listBackupVaultsOutput *backup.ListBackupVaultsOutput
	listBackupVaultsErr    error
}

func (m *mockBackupClient) ListBackupPlans(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
	if m.listBackupPlansErr != nil {
		return nil, m.listBackupPlansErr
	}
	if m.listBackupPlansOutput != nil {
		return m.listBackupPlansOutput, nil
	}
	return &backup.ListBackupPlansOutput{}, nil
}

func (m *mockBackupClient) ListBackupVaults(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	if m.listBackupVaultsErr != nil {
		return nil, m.listBackupVaultsErr
	}
	if m.listBackupVaultsOutput != nil {
		return m.listBackupVaultsOutput, nil
	}
	return &backup.ListBackupVaultsOutput{}, nil
}

func TestNewBackupScanner(t *testing.T) {
	cfg := aws.Config{Region: "us-west-2"}
	s := NewBackupScanner(cfg)
	assert.NotNil(t, s)
	assert.Equal(t, "Backup-SecaaS-Scanner", s.Name())
	assert.Equal(t, "us-west-2", s.region)

	mock := &mockBackupClient{}
	sClient := NewBackupScannerWithClient(mock, "eu-west-1")
	assert.NotNil(t, sClient)
	assert.Equal(t, "eu-west-1", sClient.region)
}

func TestBackupScanner_Compliant(t *testing.T) {
	mock := &mockBackupClient{
		listBackupPlansOutput: &backup.ListBackupPlansOutput{
			BackupPlansList: []backuptypes.BackupPlansListMember{
				{
					BackupPlanId:   aws.String("plan-01"),
					BackupPlanName: aws.String("DailyBackupPlan"),
				},
			},
		},
		listBackupVaultsOutput: &backup.ListBackupVaultsOutput{
			BackupVaultList: []backuptypes.BackupVaultListMember{
				{
					BackupVaultName: aws.String("DefaultVault"),
				},
			},
		},
	}

	scanner := NewBackupScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Verify backup_plans_exist
	rPlan := results[0]
	assert.Equal(t, "backup-us-east-1", rPlan.ResourceID)
	assert.Equal(t, "SecaaS-Backup", rPlan.ResourceType)
	assert.Equal(t, "us-east-1", rPlan.Region)
	assert.Equal(t, "PASS", rPlan.Status)
	assert.Equal(t, "INFO", rPlan.Severity)
	assert.Equal(t, "backup_plans_exist", rPlan.RuleID)

	// Verify backup_vaults_exist
	rVault := results[1]
	assert.Equal(t, "backup-us-east-1", rVault.ResourceID)
	assert.Equal(t, "SecaaS-Backup", rVault.ResourceType)
	assert.Equal(t, "us-east-1", rVault.Region)
	assert.Equal(t, "PASS", rVault.Status)
	assert.Equal(t, "INFO", rVault.Severity)
	assert.Equal(t, "backup_vaults_exist", rVault.RuleID)
}

func TestBackupScanner_NonCompliant_NoPlans(t *testing.T) {
	mock := &mockBackupClient{
		listBackupPlansOutput: &backup.ListBackupPlansOutput{
			BackupPlansList: []backuptypes.BackupPlansListMember{},
		},
		listBackupVaultsOutput: &backup.ListBackupVaultsOutput{
			BackupVaultList: []backuptypes.BackupVaultListMember{
				{
					BackupVaultName: aws.String("ProdVault"),
				},
			},
		},
	}

	scanner := NewBackupScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	rPlan := results[0]
	assert.Equal(t, "backup-us-east-1", rPlan.ResourceID)
	assert.Equal(t, "SecaaS-Backup", rPlan.ResourceType)
	assert.Equal(t, "FAIL", rPlan.Status)
	assert.Equal(t, "HIGH", rPlan.Severity)
	assert.Equal(t, "backup_plans_exist", rPlan.RuleID)
	metricsPlan := rPlan.Metrics.(map[string]interface{})
	assert.Equal(t, "Create AWS Backup plans to protect production resources.", metricsPlan["Recommendation"])

	rVault := results[1]
	assert.Equal(t, "PASS", rVault.Status)
	assert.Equal(t, "INFO", rVault.Severity)
	assert.Equal(t, "backup_vaults_exist", rVault.RuleID)
}

func TestBackupScanner_NonCompliant_NoVaults(t *testing.T) {
	mock := &mockBackupClient{
		listBackupPlansOutput: &backup.ListBackupPlansOutput{
			BackupPlansList: []backuptypes.BackupPlansListMember{
				{
					BackupPlanId:   aws.String("plan-01"),
					BackupPlanName: aws.String("ProdPlan"),
				},
			},
		},
		listBackupVaultsOutput: &backup.ListBackupVaultsOutput{
			BackupVaultList: []backuptypes.BackupVaultListMember{},
		},
	}

	scanner := NewBackupScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	rPlan := results[0]
	assert.Equal(t, "PASS", rPlan.Status)
	assert.Equal(t, "INFO", rPlan.Severity)
	assert.Equal(t, "backup_plans_exist", rPlan.RuleID)

	rVault := results[1]
	assert.Equal(t, "backup-us-east-1", rVault.ResourceID)
	assert.Equal(t, "SecaaS-Backup", rVault.ResourceType)
	assert.Equal(t, "FAIL", rVault.Status)
	assert.Equal(t, "MEDIUM", rVault.Severity)
	assert.Equal(t, "backup_vaults_exist", rVault.RuleID)
	metricsVault := rVault.Metrics.(map[string]interface{})
	assert.Equal(t, "Create AWS Backup vaults to store recovery points.", metricsVault["Recommendation"])
}

func TestBackupScanner_NonCompliant_BothEmpty(t *testing.T) {
	mock := &mockBackupClient{
		listBackupPlansOutput: &backup.ListBackupPlansOutput{
			BackupPlansList: []backuptypes.BackupPlansListMember{},
		},
		listBackupVaultsOutput: &backup.ListBackupVaultsOutput{
			BackupVaultList: []backuptypes.BackupVaultListMember{},
		},
	}

	scanner := NewBackupScannerWithClient(mock, "ap-southeast-1")
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 2)

	rPlan := results[0]
	assert.Equal(t, "FAIL", rPlan.Status)
	assert.Equal(t, "HIGH", rPlan.Severity)
	assert.Equal(t, "backup_plans_exist", rPlan.RuleID)
	assert.Equal(t, "Create AWS Backup plans to protect production resources.", rPlan.Metrics.(map[string]interface{})["Recommendation"])

	rVault := results[1]
	assert.Equal(t, "FAIL", rVault.Status)
	assert.Equal(t, "MEDIUM", rVault.Severity)
	assert.Equal(t, "backup_vaults_exist", rVault.RuleID)
	assert.Equal(t, "Create AWS Backup vaults to store recovery points.", rVault.Metrics.(map[string]interface{})["Recommendation"])
}

func TestBackupScanner_ListBackupPlansError(t *testing.T) {
	mock := &mockBackupClient{
		listBackupPlansErr: errors.New("access denied"),
	}

	scanner := NewBackupScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestBackupScanner_ListBackupVaultsError(t *testing.T) {
	mock := &mockBackupClient{
		listBackupPlansOutput: &backup.ListBackupPlansOutput{
			BackupPlansList: []backuptypes.BackupPlansListMember{
				{BackupPlanName: aws.String("PlanA")},
			},
		},
		listBackupVaultsErr: errors.New("vault service unavailable"),
	}

	scanner := NewBackupScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Nil(t, results)
}
