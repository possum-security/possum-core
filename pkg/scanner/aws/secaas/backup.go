package secaas

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
)

// BackupApi defines the mockable interface for AWS Backup operations.
type BackupApi interface {
	ListBackupPlans(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error)
	ListBackupVaults(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
}

// BackupScanner audits AWS Backup configurations.
type BackupScanner struct {
	client BackupApi
	region string
}

// NewBackupScanner creates a BackupScanner with the provided AWS config.
func NewBackupScanner(cfg aws.Config) *BackupScanner {
	return &BackupScanner{
		client: backup.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewBackupScannerWithClient creates a BackupScanner with a custom/mock client.
func NewBackupScannerWithClient(client BackupApi, region string) *BackupScanner {
	return &BackupScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *BackupScanner) Name() string {
	return "Backup-SecaaS-Scanner"
}

// Scan audits AWS Backup plans and vaults in the configured region.
func (s *BackupScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	resourceID := fmt.Sprintf("backup-%s", region)
	nodes := []graph.Node{{ID: resourceID, NodeType: "SecaaS-Backup"}}

	// a) backup_plans_exist (HIGH)
	plansOut, err := s.client.ListBackupPlans(ctx, &backup.ListBackupPlansInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list backup plans: %w", err)
	}

	if len(plansOut.BackupPlansList) == 0 {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Backup",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "backup_plans_exist",
			Severity:     "HIGH",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("No AWS Backup plans found in region %s.", region),
				"SecurityIssues": []string{"No AWS Backup plans configured"},
				"Recommendation": "Create AWS Backup plans to protect production resources.",
				"PlanCount":      0,
			},
			Nodes: nodes,
		})
	} else {
		var planNames []string
		for _, p := range plansOut.BackupPlansList {
			if p.BackupPlanName != nil {
				planNames = append(planNames, aws.ToString(p.BackupPlanName))
			}
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Backup",
			Region:       region,
			Status:       "PASS",
			RuleID:       "backup_plans_exist",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Found %d AWS Backup plan(s) in region %s.", len(plansOut.BackupPlansList), region),
				"PlanCount":      len(plansOut.BackupPlansList),
				"BackupPlans":    planNames,
			},
			Nodes: nodes,
		})
	}

	// b) backup_vaults_exist (MEDIUM)
	vaultsOut, err := s.client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list backup vaults: %w", err)
	}

	if len(vaultsOut.BackupVaultList) == 0 {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Backup",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "backup_vaults_exist",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("No AWS Backup vaults found in region %s.", region),
				"SecurityIssues": []string{"No AWS Backup vaults configured"},
				"Recommendation": "Create AWS Backup vaults to store recovery points.",
				"VaultCount":     0,
			},
			Nodes: nodes,
		})
	} else {
		var vaultNames []string
		for _, v := range vaultsOut.BackupVaultList {
			if v.BackupVaultName != nil {
				vaultNames = append(vaultNames, aws.ToString(v.BackupVaultName))
			}
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Backup",
			Region:       region,
			Status:       "PASS",
			RuleID:       "backup_vaults_exist",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Found %d AWS Backup vault(s) in region %s.", len(vaultsOut.BackupVaultList), region),
				"VaultCount":     len(vaultsOut.BackupVaultList),
				"BackupVaults":   vaultNames,
			},
			Nodes: nodes,
		})
	}

	return results, nil
}
