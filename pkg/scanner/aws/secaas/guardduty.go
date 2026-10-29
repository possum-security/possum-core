package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
)

// GuardDutyClient defines the interface for GuardDuty API calls.
type GuardDutyClient interface {
	ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
	ListFindings(ctx context.Context, params *guardduty.ListFindingsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error)
}

// GuardDutyScanner evaluates GuardDuty status, threat detections, and protection plans.
type GuardDutyScanner struct {
	client GuardDutyClient
	region string
}

// NewGuardDutyScanner creates a new GuardDutyScanner with AWS config.
func NewGuardDutyScanner(cfg aws.Config) *GuardDutyScanner {
	return &GuardDutyScanner{
		client: guardduty.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewGuardDutyScannerWithClient creates a scanner with custom/mock client.
func NewGuardDutyScannerWithClient(client GuardDutyClient, region string) *GuardDutyScanner {
	return &GuardDutyScanner{
		client: client,
		region: region,
	}
}

func (s *GuardDutyScanner) Name() string {
	return "GuardDuty-SecaaS-Scanner"
}

func (s *GuardDutyScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	detectorsOut, err := s.client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list GuardDuty detectors: %w", err)
	}

	resourceID := fmt.Sprintf("guardduty-%s", region)

	if len(detectorsOut.DetectorIds) == 0 {
		// GuardDuty is not enabled in this region
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-GuardDuty",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "guardduty_is_enabled",
			Severity:     "HIGH",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("GuardDuty is not enabled in region %s.", region),
				"SecurityIssues": []string{"No active GuardDuty detector found in region"},
				"Recommendation": "Enable GuardDuty across all active regions to provide automated threat detection.",
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-GuardDuty"}},
		})
		return results, nil
	}

	for _, detectorID := range detectorsOut.DetectorIds {
		det, err := s.client.GetDetector(ctx, &guardduty.GetDetectorInput{
			DetectorId: aws.String(detectorID),
		})
		if err != nil {
			continue
		}

		detArn := fmt.Sprintf("arn:aws:guardduty:%s::detector/%s", region, detectorID)

		// 1. Check if detector is enabled (guardduty_is_enabled - HIGH)
		isEnabled := det.Status == guarddutytypes.DetectorStatusEnabled
		if isEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "PASS",
				RuleID:       "guardduty_is_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s is enabled and active in %s.", detectorID, region),
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "guardduty_is_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s is disabled or suspended in %s.", detectorID, region),
					"SecurityIssues": []string{"Detector is not in ENABLED state"},
					"Recommendation": "Enable or resume the GuardDuty detector.",
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		}

		// 2. Check for High Severity Findings (guardduty_no_high_severity_findings - HIGH)
		findingsOut, err := s.client.ListFindings(ctx, &guardduty.ListFindingsInput{
			DetectorId: aws.String(detectorID),
			FindingCriteria: &guarddutytypes.FindingCriteria{
				Criterion: map[string]guarddutytypes.Condition{
					"severity": {
						Gte: aws.Int32(7),
					},
					"service.archived": {
						Eq: []string{"false"},
					},
				},
			},
		})
		if err == nil {
			if len(findingsOut.FindingIds) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   detectorID,
					ResourceType: "SecaaS-GuardDutyDetector",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "guardduty_no_high_severity_findings",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DetectorId":     detectorID,
						"FindingCount":   len(findingsOut.FindingIds),
						"StatusExtended": fmt.Sprintf("GuardDuty detector %s has %d unresolved high-severity security findings.", detectorID, len(findingsOut.FindingIds)),
						"SecurityIssues": []string{fmt.Sprintf("%d active high severity findings", len(findingsOut.FindingIds))},
						"Recommendation": "Investigate and remediate high-severity GuardDuty findings immediately.",
					},
					Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   detectorID,
					ResourceType: "SecaaS-GuardDutyDetector",
					Region:       region,
					Status:       "PASS",
					RuleID:       "guardduty_no_high_severity_findings",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DetectorId":     detectorID,
						"StatusExtended": fmt.Sprintf("GuardDuty detector %s has 0 unresolved high-severity findings.", detectorID),
					},
					Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
				})
			}
		}

		// Helper to check features
		featureMap := make(map[string]bool)
		for _, f := range det.Features {
			fName := strings.ToUpper(string(f.Name))
			featureMap[fName] = f.Status == guarddutytypes.FeatureStatusEnabled
		}

		// 3. S3 Protection (guardduty_s3_protection_enabled - HIGH)
		s3Enabled := (det.DataSources != nil && det.DataSources.S3Logs != nil && det.DataSources.S3Logs.Status == guarddutytypes.DataSourceStatusEnabled) ||
			featureMap["S3_DATA_EVENTS"]
		if s3Enabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "PASS",
				RuleID:       "guardduty_s3_protection_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s has S3 Protection enabled.", detectorID),
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "guardduty_s3_protection_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s does not have S3 Protection enabled.", detectorID),
					"SecurityIssues": []string{"S3 data events protection is disabled"},
					"Recommendation": "Enable GuardDuty S3 Protection to monitor object-level access anomalies.",
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		}

		// 4. EKS Audit Logs (guardduty_eks_audit_log_enabled - HIGH)
		eksAuditEnabled := (det.DataSources != nil && det.DataSources.Kubernetes != nil && det.DataSources.Kubernetes.AuditLogs != nil && det.DataSources.Kubernetes.AuditLogs.Status == guarddutytypes.DataSourceStatusEnabled) ||
			featureMap["EKS_AUDIT_LOGS"]
		if eksAuditEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "PASS",
				RuleID:       "guardduty_eks_audit_log_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s has EKS Audit Log monitoring enabled.", detectorID),
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "guardduty_eks_audit_log_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s does not have EKS Audit Log monitoring enabled.", detectorID),
					"SecurityIssues": []string{"Kubernetes audit logs monitoring is disabled"},
					"Recommendation": "Enable GuardDuty EKS Audit Log protection for cluster activity monitoring.",
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		}

		// 5. RDS Protection (guardduty_rds_protection_enabled - HIGH)
		rdsEnabled := featureMap["RDS_LOGIN_EVENTS"]
		if rdsEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "PASS",
				RuleID:       "guardduty_rds_protection_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s has RDS Login Events protection enabled.", detectorID),
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "guardduty_rds_protection_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s does not have RDS Login Events protection enabled.", detectorID),
					"SecurityIssues": []string{"RDS login protection is disabled"},
					"Recommendation": "Enable GuardDuty RDS Protection to detect suspicious database login attempts.",
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		}

		// 6. Lambda Protection (guardduty_lambda_protection_enabled - HIGH)
		lambdaEnabled := featureMap["LAMBDA_NETWORK_LOGS"]
		if lambdaEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "PASS",
				RuleID:       "guardduty_lambda_protection_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s has Lambda Network Logs protection enabled.", detectorID),
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "guardduty_lambda_protection_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s does not have Lambda Network Logs protection enabled.", detectorID),
					"SecurityIssues": []string{"Lambda network protection is disabled"},
					"Recommendation": "Enable GuardDuty Lambda Protection to analyze network traffic from serverless invocations.",
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		}

		// 7. EC2 Malware Protection (guardduty_ec2_malware_protection_enabled - HIGH)
		malwareEnabled := featureMap["EBS_MALWARE_PROTECTION"]
		if malwareEnabled {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "PASS",
				RuleID:       "guardduty_ec2_malware_protection_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s has EBS Malware Protection enabled.", detectorID),
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   detectorID,
				ResourceType: "SecaaS-GuardDutyDetector",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "guardduty_ec2_malware_protection_enabled",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"DetectorId":     detectorID,
					"StatusExtended": fmt.Sprintf("GuardDuty detector %s does not have EBS Malware Protection enabled.", detectorID),
					"SecurityIssues": []string{"Malware protection for EBS volumes is disabled"},
					"Recommendation": "Enable GuardDuty Malware Protection to scan EBS volumes attached to EC2 instances.",
				},
				Nodes: []graph.Node{{ID: detArn, NodeType: "SecaaS-GuardDutyDetector"}},
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *GuardDutyScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "guardduty-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "guardduty",
		CheckIDs:      []string{"guardduty_ec2_malware_protection_enabled", "guardduty_eks_audit_log_enabled", "guardduty_is_enabled", "guardduty_lambda_protection_enabled", "guardduty_no_high_severity_findings", "guardduty_rds_protection_enabled", "guardduty_s3_protection_enabled"},
	}
}
