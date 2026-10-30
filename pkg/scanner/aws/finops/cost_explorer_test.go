package finops_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/possum-security/possum-core/pkg/scanner/aws/finops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCEClient struct {
	getCostAndUsageFn func(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
	getAnomaliesFn    func(ctx context.Context, params *costexplorer.GetAnomaliesInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetAnomaliesOutput, error)
}

func (m *mockCEClient) GetCostAndUsage(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
	if m.getCostAndUsageFn != nil {
		return m.getCostAndUsageFn(ctx, params, optFns...)
	}
	return &costexplorer.GetCostAndUsageOutput{}, nil
}

func (m *mockCEClient) GetAnomalies(ctx context.Context, params *costexplorer.GetAnomaliesInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetAnomaliesOutput, error) {
	if m.getAnomaliesFn != nil {
		return m.getAnomaliesFn(ctx, params, optFns...)
	}
	return &costexplorer.GetAnomaliesOutput{}, nil
}

func TestNewCostExplorerScanner_Defaults(t *testing.T) {
	cfg := aws.Config{}

	// Test default when days <= 0
	scannerDefault := finops.NewCostExplorerScanner(cfg, 0)
	if scannerDefault == nil {
		t.Fatal("expected scanner instance, got nil")
	}
	if scannerDefault.Name() != "CostExplorer-Scanner" {
		t.Errorf("expected CostExplorer-Scanner, got %s", scannerDefault.Name())
	}

	// Verify it satisfies the Scanner and MetaScanner interfaces
	var _ scanner.Scanner = scannerDefault
	var _ scanner.MetaScanner = scannerDefault

	// Test explicit 30 days
	scanner30 := finops.NewCostExplorerScanner(cfg, 30)
	if scanner30 == nil {
		t.Fatal("expected scanner instance, got nil")
	}

	// Test NewCostExplorerScannerWithClient
	scClient := finops.NewCostExplorerScannerWithClient(&mockCEClient{})
	assert.NotNil(t, scClient)
	assert.Equal(t, "CostExplorer-Scanner", scClient.Name())

	// Test NewCostExplorerScannerWithClientAndDays
	scDays := finops.NewCostExplorerScannerWithClientAndDays(&mockCEClient{}, 14)
	assert.NotNil(t, scDays)
}

func TestCostExplorerScanner_SpendTrackingAndPagination(t *testing.T) {
	callCount := 0
	mockClient := &mockCEClient{
		getCostAndUsageFn: func(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
			callCount++
			if params.NextPageToken == nil {
				return &costexplorer.GetCostAndUsageOutput{
					NextPageToken: aws.String("page2-token"),
					ResultsByTime: []cetypes.ResultByTime{
						{
							TimePeriod: &cetypes.DateInterval{
								Start: aws.String("2026-10-01"),
								End:   aws.String("2026-10-02"),
							},
							Groups: []cetypes.Group{
								{
									Keys: []string{"Amazon Elastic Compute Cloud - Compute"},
									Metrics: map[string]cetypes.MetricValue{
										"UnblendedCost": {
											Amount: aws.String("150.25"),
											Unit:   aws.String("USD"),
										},
									},
								},
								{
									Keys: []string{}, // empty key, should be skipped
								},
							},
						},
					},
				}, nil
			}

			// Page 2
			return &costexplorer.GetCostAndUsageOutput{
				NextPageToken: nil,
				ResultsByTime: []cetypes.ResultByTime{
					{
						TimePeriod: &cetypes.DateInterval{
							Start: aws.String("2026-10-02"),
							End:   aws.String("2026-10-03"),
						},
						Groups: []cetypes.Group{
							{
								Keys: []string{"Amazon Relational Database Service"},
								Metrics: map[string]cetypes.MetricValue{
									"UnblendedCost": {
										Amount: aws.String("45.10"),
										Unit:   aws.String("USD"),
									},
								},
							},
						},
					},
				},
			}, nil
		},
	}

	sc := finops.NewCostExplorerScannerWithClientAndDays(mockClient, 30)
	results, err := sc.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
	require.Len(t, results, 2)

	// EC2 result
	assert.Equal(t, "Amazon Elastic Compute Cloud - Compute", results[0].ResourceID)
	assert.Equal(t, finops.RuleCostExplorerSpendTracked, results[0].RuleID)
	assert.Equal(t, model.StatusPass, results[0].Status)
	assert.Equal(t, "global", results[0].Region)
	m0 := results[0].Metrics.(map[string]interface{})
	assert.Equal(t, 150.25, m0["EstimatedMonthlyCost"])
	assert.Equal(t, "USD", m0["Currency"])

	// RDS result
	assert.Equal(t, "Amazon Relational Database Service", results[1].ResourceID)
	assert.Equal(t, model.StatusPass, results[1].Status)
	m1 := results[1].Metrics.(map[string]interface{})
	assert.Equal(t, 45.10, m1["EstimatedMonthlyCost"])
}

func TestCostExplorerScanner_CostAnomaliesAPI(t *testing.T) {
	mockClient := &mockCEClient{
		getAnomaliesFn: func(ctx context.Context, params *costexplorer.GetAnomaliesInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetAnomaliesOutput, error) {
			return &costexplorer.GetAnomaliesOutput{
				Anomalies: []cetypes.Anomaly{
					{
						AnomalyId: aws.String("anomaly-1234"),
						AnomalyScore: &cetypes.AnomalyScore{
							CurrentScore: 95.5,
							MaxScore:     99.0,
						},
						Impact: &cetypes.Impact{
							TotalImpact: 520.00,
						},
					},
				},
			}, nil
		},
	}

	out, err := mockClient.GetAnomalies(context.Background(), &costexplorer.GetAnomaliesInput{})
	require.NoError(t, err)
	require.Len(t, out.Anomalies, 1)
	assert.Equal(t, "anomaly-1234", *out.Anomalies[0].AnomalyId)
	assert.Equal(t, 520.00, out.Anomalies[0].Impact.TotalImpact)
}

func TestCostExplorerScanner_Error(t *testing.T) {
	mockClient := &mockCEClient{
		getCostAndUsageFn: func(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
			return nil, errors.New("ce: get cost and usage failed")
		},
	}

	sc := finops.NewCostExplorerScannerWithClient(mockClient)
	_, err := sc.Scan(context.Background())
	assert.Error(t, err)
}

func TestCostExplorerScanner_Limit(t *testing.T) {
	mockClient := &mockCEClient{
		getCostAndUsageFn: func(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error) {
			return &costexplorer.GetCostAndUsageOutput{
				ResultsByTime: []cetypes.ResultByTime{
					{
						TimePeriod: &cetypes.DateInterval{Start: aws.String("2026-10-01")},
						Groups: []cetypes.Group{
							{Keys: []string{"s1"}, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String("1.0")}}},
							{Keys: []string{"s2"}, Metrics: map[string]cetypes.MetricValue{"UnblendedCost": {Amount: aws.String("2.0")}}},
						},
					},
				},
			}, nil
		},
	}

	sc := finops.NewCostExplorerScannerWithClient(mockClient)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := sc.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
