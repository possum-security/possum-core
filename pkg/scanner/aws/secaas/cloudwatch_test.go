package secaas_test

import (
	"context"
	"errors"
	"testing"

	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type mockCloudWatchLogsAPI struct {
	describeMetricFiltersOutput *cloudwatchlogs.DescribeMetricFiltersOutput
	describeMetricFiltersErr    error
}

func (m *mockCloudWatchLogsAPI) DescribeMetricFilters(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error) {
	if m.describeMetricFiltersErr != nil {
		return nil, m.describeMetricFiltersErr
	}
	return m.describeMetricFiltersOutput, nil
}

type mockCloudWatchAPI struct {
	describeAlarmsOutput *cloudwatch.DescribeAlarmsOutput
	describeAlarmsErr    error
}

func (m *mockCloudWatchAPI) DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	if m.describeAlarmsErr != nil {
		return nil, m.describeAlarmsErr
	}
	return m.describeAlarmsOutput, nil
}

func TestCloudWatchScanner_AllMissing_AllFail(t *testing.T) {
	mockLogs := &mockCloudWatchLogsAPI{
		describeMetricFiltersOutput: &cloudwatchlogs.DescribeMetricFiltersOutput{
			MetricFilters: []cwlogstypes.MetricFilter{},
		},
	}
	mockCW := &mockCloudWatchAPI{
		describeAlarmsOutput: &cloudwatch.DescribeAlarmsOutput{
			MetricAlarms: []cwtypes.MetricAlarm{},
		},
	}

	sc := secaas.NewCloudWatchScannerWithClients(mockLogs, mockCW, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 15 {
		t.Fatalf("expected 15 checks, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != "FAIL" {
			t.Errorf("expected check %s to FAIL, got %s", r.RuleID, r.Status)
		}
	}
}

func TestCloudWatchScanner_AllConfigured_AllPass(t *testing.T) {
	patterns := map[string]string{
		"unauth":   `{($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")}`,
		"nomfa":    `{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }`,
		"root":     `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`,
		"policy":   `{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=CreatePolicy)}`,
		"trail":    `{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail)}`,
		"authfail": `{($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication")}`,
		"kms":      `{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }`,
		"s3":       `{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy))}`,
		"config":   `{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel))}`,
		"sg":       `{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = CreateSecurityGroup) }`,
		"nacl":     `{ ($.eventName = CreateNetworkAcl) || ($.eventName = DeleteNetworkAcl) }`,
		"gw":       `{ ($.eventName = CreateCustomerGateway) || ($.eventName = AttachInternetGateway) }`,
		"route":    `{($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable))}`,
		"vpc":      `{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) }`,
		"orgs":     `{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "CreateAccount")) }`,
	}

	var filters []cwlogstypes.MetricFilter
	var alarms []cwtypes.MetricAlarm

	for key, pattern := range patterns {
		metricName := key + "_metric"
		alarmName := key + "_alarm"
		namespace := "CISBenchmark"

		filters = append(filters, cwlogstypes.MetricFilter{
			FilterName:    aws.String(key + "_filter"),
			FilterPattern: aws.String(pattern),
			MetricTransformations: []cwlogstypes.MetricTransformation{
				{
					MetricName:      aws.String(metricName),
					MetricNamespace: aws.String(namespace),
					MetricValue:     aws.String("1"),
				},
			},
		})

		alarms = append(alarms, cwtypes.MetricAlarm{
			AlarmName:  aws.String(alarmName),
			AlarmArn:   aws.String("arn:aws:cloudwatch:us-east-1:123456789012:alarm:" + alarmName),
			MetricName: aws.String(metricName),
			Namespace:  aws.String(namespace),
		})
	}

	mockLogs := &mockCloudWatchLogsAPI{
		describeMetricFiltersOutput: &cloudwatchlogs.DescribeMetricFiltersOutput{
			MetricFilters: filters,
		},
	}
	mockCW := &mockCloudWatchAPI{
		describeAlarmsOutput: &cloudwatch.DescribeAlarmsOutput{
			MetricAlarms: alarms,
		},
	}

	sc := secaas.NewCloudWatchScannerWithClients(mockLogs, mockCW, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 15 {
		t.Fatalf("expected 15 checks, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != "PASS" {
			t.Errorf("expected check %s to PASS, got %s", r.RuleID, r.Status)
		}
		if r.Severity != "INFO" {
			t.Errorf("expected check %s severity to be INFO on PASS, got %s", r.RuleID, r.Severity)
		}
	}
}

func TestCloudWatchScanner_MetricFilterWithoutAlarm_Fails(t *testing.T) {
	mockLogs := &mockCloudWatchLogsAPI{
		describeMetricFiltersOutput: &cloudwatchlogs.DescribeMetricFiltersOutput{
			MetricFilters: []cwlogstypes.MetricFilter{
				{
					FilterName:    aws.String("root_filter"),
					FilterPattern: aws.String(`{ $.userIdentity.type = "Root" }`),
					MetricTransformations: []cwlogstypes.MetricTransformation{
						{
							MetricName:      aws.String("root_metric"),
							MetricNamespace: aws.String("CISBenchmark"),
							MetricValue:     aws.String("1"),
						},
					},
				},
			},
		},
	}
	// No alarms!
	mockCW := &mockCloudWatchAPI{
		describeAlarmsOutput: &cloudwatch.DescribeAlarmsOutput{
			MetricAlarms: []cwtypes.MetricAlarm{},
		},
	}

	sc := secaas.NewCloudWatchScannerWithClients(mockLogs, mockCW, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range results {
		if r.RuleID == "cloudwatch_log_metric_filter_root_usage" {
			if r.Status != "FAIL" {
				t.Fatalf("expected root usage to FAIL without alarm, got %s", r.Status)
			}
		}
	}
}

func TestCloudWatchScanner_ErrorHandling(t *testing.T) {
	mockLogs := &mockCloudWatchLogsAPI{
		describeMetricFiltersErr: errors.New("logs service unavailable"),
	}
	mockCW := &mockCloudWatchAPI{
		describeAlarmsOutput: &cloudwatch.DescribeAlarmsOutput{},
	}

	sc := secaas.NewCloudWatchScannerWithClients(mockLogs, mockCW, "us-east-1")
	_, err := sc.Scan(context.Background())
	if err == nil {
		t.Fatal("expected error on logs failure, got nil")
	}
}
