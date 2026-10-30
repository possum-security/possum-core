package secaas

import (
	"context"
	"fmt"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

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
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	resourceID := fmt.Sprintf("backup-%s", region)
	nodes := []graph.Node{{ID: resourceID, NodeType: "SecaaS-Backup"}}

	// a) backup_plans_exist (HIGH)
	var planNames []string
	planCount := 0
	plansPaginator := backup.NewListBackupPlansPaginator(s.client, &backup.ListBackupPlansInput{})
	for plansPaginator.HasMorePages() {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		plansOut, err := plansPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup plans: %w", err)
		}
		for _, p := range plansOut.BackupPlansList {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++
			planCount++
			if p.BackupPlanName != nil {
				planNames = append(planNames, aws.ToString(p.BackupPlanName))
			}
		}
	}

	if planCount == 0 {
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
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Backup",
			Region:       region,
			Status:       "PASS",
			RuleID:       "backup_plans_exist",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Found %d AWS Backup plan(s) in region %s.", planCount, region),
				"PlanCount":      planCount,
				"BackupPlans":    planNames,
			},
			Nodes: nodes,
		})
	}

	// b) backup_vaults_exist (MEDIUM)
	var vaultNames []string
	vaultCount := 0
	vaultsPaginator := backup.NewListBackupVaultsPaginator(s.client, &backup.ListBackupVaultsInput{})
	for vaultsPaginator.HasMorePages() {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		vaultsOut, err := vaultsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list backup vaults: %w", err)
		}
		for _, v := range vaultsOut.BackupVaultList {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++
			vaultCount++
			if v.BackupVaultName != nil {
				vaultNames = append(vaultNames, aws.ToString(v.BackupVaultName))
			}
		}
	}

	if vaultCount == 0 {
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
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-Backup",
			Region:       region,
			Status:       "PASS",
			RuleID:       "backup_vaults_exist",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("Found %d AWS Backup vault(s) in region %s.", vaultCount, region),
				"VaultCount":     vaultCount,
				"BackupVaults":   vaultNames,
			},
			Nodes: nodes,
		})
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *BackupScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "backup-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "backup",
		CheckIDs:      []string{"backup_plans_exist", "backup_vaults_exist"},
	}
}
