package secaas

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
)

type mockConfigServiceClient struct {
	recordersOutput *configservice.DescribeConfigurationRecordersOutput
	statusOutput    *configservice.DescribeConfigurationRecorderStatusOutput
	err             error
}

func (m *mockConfigServiceClient) DescribeConfigurationRecorders(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.recordersOutput, nil
}

func (m *mockConfigServiceClient) DescribeConfigurationRecorderStatus(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.statusOutput, nil
}

func TestConfigServiceScanner_Active(t *testing.T) {
	mock := &mockConfigServiceClient{
		recordersOutput: &configservice.DescribeConfigurationRecordersOutput{
			ConfigurationRecorders: []configtypes.ConfigurationRecorder{
				{Name: aws.String("default")},
			},
		},
		statusOutput: &configservice.DescribeConfigurationRecorderStatusOutput{
			ConfigurationRecordersStatus: []configtypes.ConfigurationRecorderStatus{
				{
					Name:       aws.String("default"),
					Recording:  true,
					LastStatus: configtypes.RecorderStatusSuccess,
				},
			},
		},
	}

	scanner := NewConfigServiceScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "config_recorder_all_regions_enabled", results[0].RuleID)
}

func TestConfigServiceScanner_NoRecorders(t *testing.T) {
	mock := &mockConfigServiceClient{
		recordersOutput: &configservice.DescribeConfigurationRecordersOutput{
			ConfigurationRecorders: []configtypes.ConfigurationRecorder{},
		},
	}

	scanner := NewConfigServiceScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "config_recorder_all_regions_enabled", results[0].RuleID)
}

func TestConfigServiceScanner_NotRecording(t *testing.T) {
	mock := &mockConfigServiceClient{
		recordersOutput: &configservice.DescribeConfigurationRecordersOutput{
			ConfigurationRecorders: []configtypes.ConfigurationRecorder{
				{Name: aws.String("default")},
			},
		},
		statusOutput: &configservice.DescribeConfigurationRecorderStatusOutput{
			ConfigurationRecordersStatus: []configtypes.ConfigurationRecorderStatus{
				{
					Name:       aws.String("default"),
					Recording:  false,
					LastStatus: configtypes.RecorderStatusFailure,
				},
			},
		},
	}

	scanner := NewConfigServiceScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "MEDIUM", results[0].Severity)
}
