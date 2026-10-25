package secaas

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	configtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
)

// ConfigServiceClient defines the interface for AWS Config API calls.
type ConfigServiceClient interface {
	DescribeConfigurationRecorders(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
}

// ConfigServiceScanner evaluates AWS Config recording status in a region.
type ConfigServiceScanner struct {
	client ConfigServiceClient
	region string
}

// NewConfigServiceScanner creates a new ConfigServiceScanner with AWS config.
func NewConfigServiceScanner(cfg aws.Config) *ConfigServiceScanner {
	return &ConfigServiceScanner{
		client: configservice.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewConfigServiceScannerWithClient creates a scanner with a custom/mock client.
func NewConfigServiceScannerWithClient(client ConfigServiceClient, region string) *ConfigServiceScanner {
	return &ConfigServiceScanner{
		client: client,
		region: region,
	}
}

func (s *ConfigServiceScanner) Name() string {
	return "Config-SecaaS-Scanner"
}

func (s *ConfigServiceScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	region := s.region
	if region == "" {
		region = "global"
	}

	recordersOut, err := s.client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe configuration recorders: %w", err)
	}

	resourceID := fmt.Sprintf("config-recorder-%s", region)

	if len(recordersOut.ConfigurationRecorders) == 0 {
		results = append(results, scanner.ScanResult{
			ResourceID:   resourceID,
			ResourceType: "SecaaS-ConfigRecorder",
			Region:       region,
			Status:       "FAIL",
			RuleID:       "config_recorder_all_regions_enabled",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("AWS Config is not enabled in region %s (no configuration recorders found).", region),
				"SecurityIssues": []string{"No AWS Config recorder configured in region"},
				"Recommendation": "Create and enable an AWS Config recorder in this region to track resource changes.",
			},
			Nodes: []graph.Node{{ID: resourceID, NodeType: "SecaaS-ConfigRecorder"}},
		})
		return results, nil
	}

	statusesOut, err := s.client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe configuration recorder status: %w", err)
	}

	statusMap := make(map[string]configtypes.ConfigurationRecorderStatus)
	for _, status := range statusesOut.ConfigurationRecordersStatus {
		statusMap[aws.ToString(status.Name)] = status
	}

	for _, recorder := range recordersOut.ConfigurationRecorders {
		name := aws.ToString(recorder.Name)
		status, exists := statusMap[name]

		isRecording := exists && status.Recording
		isHealthy := exists && status.LastStatus != configtypes.RecorderStatusFailure

		if isRecording && isHealthy {
			results = append(results, scanner.ScanResult{
				ResourceID:   name,
				ResourceType: "SecaaS-ConfigRecorder",
				Region:       region,
				Status:       "PASS",
				RuleID:       "config_recorder_all_regions_enabled",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"RecorderName":   name,
					"Recording":      true,
					"StatusExtended": fmt.Sprintf("AWS Config recorder %s is enabled and actively recording in %s.", name, region),
				},
				Nodes: []graph.Node{{ID: name, NodeType: "SecaaS-ConfigRecorder"}},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   name,
				ResourceType: "SecaaS-ConfigRecorder",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "config_recorder_all_regions_enabled",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"RecorderName":   name,
					"Recording":      isRecording,
					"LastStatus":     string(status.LastStatus),
					"StatusExtended": fmt.Sprintf("AWS Config recorder %s is not actively recording or in failure state in %s.", name, region),
					"SecurityIssues": []string{"AWS Config recorder disabled or in failure state"},
					"Recommendation": "Start the configuration recorder and ensure delivery channel permissions are correct.",
				},
				Nodes: []graph.Node{{ID: name, NodeType: "SecaaS-ConfigRecorder"}},
			})
		}
	}

	return results, nil
}
