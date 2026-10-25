package secaas

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/stretchr/testify/assert"
)

type mockGuardDutyClient struct {
	listDetectorsOutput *guardduty.ListDetectorsOutput
	getDetectorOutput   *guardduty.GetDetectorOutput
	listFindingsOutput  *guardduty.ListFindingsOutput
	err                 error
}

func (m *mockGuardDutyClient) ListDetectors(ctx context.Context, params *guardduty.ListDetectorsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listDetectorsOutput, nil
}

func (m *mockGuardDutyClient) GetDetector(ctx context.Context, params *guardduty.GetDetectorInput, optFns ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.getDetectorOutput, nil
}

func (m *mockGuardDutyClient) ListFindings(ctx context.Context, params *guardduty.ListFindingsInput, optFns ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listFindingsOutput, nil
}

func TestGuardDutyScanner_Compliant(t *testing.T) {
	detectorID := "det-12345"
	mock := &mockGuardDutyClient{
		listDetectorsOutput: &guardduty.ListDetectorsOutput{
			DetectorIds: []string{detectorID},
		},
		getDetectorOutput: &guardduty.GetDetectorOutput{
			Status: guarddutytypes.DetectorStatusEnabled,
			DataSources: &guarddutytypes.DataSourceConfigurationsResult{
				S3Logs: &guarddutytypes.S3LogsConfigurationResult{
					Status: guarddutytypes.DataSourceStatusEnabled,
				},
				Kubernetes: &guarddutytypes.KubernetesConfigurationResult{
					AuditLogs: &guarddutytypes.KubernetesAuditLogsConfigurationResult{
						Status: guarddutytypes.DataSourceStatusEnabled,
					},
				},
			},
			Features: []guarddutytypes.DetectorFeatureConfigurationResult{
				{
					Name:   guarddutytypes.DetectorFeatureResultRdsLoginEvents,
					Status: guarddutytypes.FeatureStatusEnabled,
				},
				{
					Name:   guarddutytypes.DetectorFeatureResultLambdaNetworkLogs,
					Status: guarddutytypes.FeatureStatusEnabled,
				},
				{
					Name:   guarddutytypes.DetectorFeatureResultEbsMalwareProtection,
					Status: guarddutytypes.FeatureStatusEnabled,
				},
			},
		},
		listFindingsOutput: &guardduty.ListFindingsOutput{
			FindingIds: []string{}, // No high severity findings
		},
	}

	scanner := NewGuardDutyScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 7)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for rule %s", r.RuleID)
	}
}

func TestGuardDutyScanner_DisabledOrNotConfigured(t *testing.T) {
	// No detectors in region
	mock := &mockGuardDutyClient{
		listDetectorsOutput: &guardduty.ListDetectorsOutput{
			DetectorIds: []string{},
		},
	}

	scanner := NewGuardDutyScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "guardduty_is_enabled", results[0].RuleID)
}

func TestGuardDutyScanner_HighSeverityFindingsAndDisabledFeatures(t *testing.T) {
	detectorID := "det-vulnerable"
	mock := &mockGuardDutyClient{
		listDetectorsOutput: &guardduty.ListDetectorsOutput{
			DetectorIds: []string{detectorID},
		},
		getDetectorOutput: &guardduty.GetDetectorOutput{
			Status: guarddutytypes.DetectorStatusEnabled,
			DataSources: &guarddutytypes.DataSourceConfigurationsResult{
				S3Logs: &guarddutytypes.S3LogsConfigurationResult{
					Status: guarddutytypes.DataSourceStatusDisabled,
				},
				Kubernetes: &guarddutytypes.KubernetesConfigurationResult{
					AuditLogs: &guarddutytypes.KubernetesAuditLogsConfigurationResult{
						Status: guarddutytypes.DataSourceStatusDisabled,
					},
				},
			},
			Features: []guarddutytypes.DetectorFeatureConfigurationResult{
				{
					Name:   guarddutytypes.DetectorFeatureResultRdsLoginEvents,
					Status: guarddutytypes.FeatureStatusDisabled,
				},
				{
					Name:   guarddutytypes.DetectorFeatureResultLambdaNetworkLogs,
					Status: guarddutytypes.FeatureStatusDisabled,
				},
				{
					Name:   guarddutytypes.DetectorFeatureResultEbsMalwareProtection,
					Status: guarddutytypes.FeatureStatusDisabled,
				},
			},
		},
		listFindingsOutput: &guardduty.ListFindingsOutput{
			FindingIds: []string{"finding-high-1", "finding-high-2"},
		},
	}

	scanner := NewGuardDutyScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 7)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "PASS", statusMap["guardduty_is_enabled"])
	assert.Equal(t, "FAIL", statusMap["guardduty_no_high_severity_findings"])
	assert.Equal(t, "FAIL", statusMap["guardduty_s3_protection_enabled"])
	assert.Equal(t, "FAIL", statusMap["guardduty_eks_audit_log_enabled"])
	assert.Equal(t, "FAIL", statusMap["guardduty_rds_protection_enabled"])
	assert.Equal(t, "FAIL", statusMap["guardduty_lambda_protection_enabled"])
	assert.Equal(t, "FAIL", statusMap["guardduty_ec2_malware_protection_enabled"])
}
