package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwlogstypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CloudWatchLogsAPI defines the interface for CloudWatch Logs operations.
type CloudWatchLogsAPI interface {
	DescribeMetricFilters(ctx context.Context, params *cloudwatchlogs.DescribeMetricFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error)
}

// CloudWatchAPI defines the interface for CloudWatch metric and alarm operations.
type CloudWatchAPI interface {
	DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

// CloudWatchScanner audits CloudWatch Logs metric filters and metric alarms for CIS Benchmark compliance.
type CloudWatchScanner struct {
	logsClient CloudWatchLogsAPI
	cwClient   CloudWatchAPI
	region     string
}

// NewCloudWatchScanner creates a new CloudWatchScanner with real AWS clients.
func NewCloudWatchScanner(cfg aws.Config) *CloudWatchScanner {
	return &CloudWatchScanner{
		logsClient: cloudwatchlogs.NewFromConfig(cfg),
		cwClient:   cloudwatch.NewFromConfig(cfg),
		region:     cfg.Region,
	}
}

// NewCloudWatchScannerWithClients allows injecting mock clients for unit testing.
func NewCloudWatchScannerWithClients(logsClient CloudWatchLogsAPI, cwClient CloudWatchAPI, region string) *CloudWatchScanner {
	return &CloudWatchScanner{
		logsClient: logsClient,
		cwClient:   cwClient,
		region:     region,
	}
}

func (s *CloudWatchScanner) Name() string {
	return "CloudWatch-SecaaS-Scanner"
}

type filterRuleDef struct {
	checkID  string
	title    string
	severity string
	matcher  func(pattern string) bool
}

func normalizePattern(p string) string {
	p = strings.ToLower(p)
	p = strings.ReplaceAll(p, " ", "")
	p = strings.ReplaceAll(p, "\t", "")
	p = strings.ReplaceAll(p, "\n", "")
	p = strings.ReplaceAll(p, "\"", "")
	p = strings.ReplaceAll(p, "\\", "")
	return p
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func getCloudWatchFilterRules() []filterRuleDef {
	return []filterRuleDef{
		{
			checkID:  "cloudwatch_log_metric_filter_unauthorized_api_calls",
			title:    "Unauthorized API calls metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm, "unauthorizedoperation", "accessdenied")
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_sign_in_without_mfa",
			title:    "Console sign-in without MFA metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return strings.Contains(norm, "consolelogin") &&
					(strings.Contains(norm, "mfaused!=yes") || strings.Contains(norm, "mfaused=no") || strings.Contains(norm, "mfa"))
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_root_usage",
			title:    "Root account usage metric filter and alarm",
			severity: "HIGH",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return strings.Contains(norm, "root") &&
					(strings.Contains(norm, "useridentity") || strings.Contains(norm, "eventtype"))
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_policy_changes",
			title:    "IAM policy changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"deletegrouppolicy", "deleterolepolicy", "deleteuserpolicy",
					"putgrouppolicy", "putrolepolicy", "putuserpolicy",
					"createpolicy", "deletepolicy", "createpolicyversion",
					"deletepolicyversion", "attachrolepolicy", "detachrolepolicy",
					"attachuserpolicy", "detachuserpolicy", "attachgrouppolicy", "detachgrouppolicy",
				)
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
			title:    "CloudTrail configuration changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm, "createtrail", "updatetrail", "deletetrail", "startlogging", "stoplogging")
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_authentication_failures",
			title:    "Console authentication failures metric filter and alarm",
			severity: "LOW",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return strings.Contains(norm, "consolelogin") &&
					containsAny(norm, "failedauthentication", "failed", "errormessage")
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
			title:    "Disabling or scheduled deletion of KMS CMK metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm, "disablekey", "schedulekeydeletion")
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes",
			title:    "S3 bucket policy changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"putbucketpolicy", "putbucketacl", "putbucketcors",
					"putbucketlifecycle", "putbucketreplication", "deletebucketpolicy",
					"deletebucketcors", "deletebucketlifecycle", "deletebucketreplication",
				)
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
			title:    "AWS Config configuration changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm, "stopconfigurationrecorder", "deletedeliverychannel", "putdeliverychannel", "putconfigurationrecorder")
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_security_group_changes",
			title:    "Security group changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"authorizesecuritygroupingress", "revokesecuritygroupingress",
					"authorizesecuritygroupegress", "revokesecuritygroupegress",
					"createsecuritygroup", "deletesecuritygroup",
				)
			},
		},
		{
			checkID:  "cloudwatch_changes_to_network_acls_alarm_configured",
			title:    "Network ACL changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"createnetworkacl", "createnetworkaclentry",
					"deletenetworkacl", "deletenetworkaclentry",
					"replacenetworkaclentry", "replacenetworkaclassociation",
				)
			},
		},
		{
			checkID:  "cloudwatch_changes_to_network_gateways_alarm_configured",
			title:    "Network Gateway changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"createcustomergateway", "deletecustomergateway",
					"attachinternetgateway", "createinternetgateway",
					"deleteinternetgateway", "detachinternetgateway",
				)
			},
		},
		{
			checkID:  "cloudwatch_changes_to_network_route_tables_alarm_configured",
			title:    "Route table changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"createroute", "createroutetable",
					"replaceroute", "replaceroutetableassociation",
					"deleteroutetable", "deleteroute", "disassociateroutetable",
				)
			},
		},
		{
			checkID:  "cloudwatch_changes_to_vpcs_alarm_configured",
			title:    "VPC changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"createvpc", "deletevpc", "modifyvpcattribute",
					"acceptvpcpeeringconnection", "createvpcpeeringconnection",
					"deletevpcpeeringconnection", "rejectvpcpeeringconnection",
				)
			},
		},
		{
			checkID:  "cloudwatch_log_metric_filter_aws_organizations_changes",
			title:    "AWS Organizations changes metric filter and alarm",
			severity: "MEDIUM",
			matcher: func(p string) bool {
				norm := normalizePattern(p)
				return containsAny(norm,
					"organizations.amazonaws.com", "accepthandshake",
					"attachpolicy", "cancelhandshake", "createaccount",
					"createorganization", "leaveorganization", "detachpolicy",
				)
			},
		},
	}
}

type alarmRef struct {
	name string
	arn  string
}

func (s *CloudWatchScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}

	region := s.region
	if region == "" {
		region = "global"
	}

	// 1. Fetch all Metric Filters across log groups
	var filters []cwlogstypes.MetricFilter
	var nextToken *string
	for {
		out, err := s.logsClient.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe CloudWatch log metric filters: %w", err)
		}
		filters = append(filters, out.MetricFilters...)
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	// 2. Fetch all Metric Alarms
	alarmMap := make(map[string]alarmRef) // key: "namespace/metricName"
	var alarmToken *string
	for {
		out, err := s.cwClient.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
			NextToken: alarmToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe CloudWatch alarms: %w", err)
		}
		for _, a := range out.MetricAlarms {
			key := fmt.Sprintf("%s/%s", aws.ToString(a.Namespace), aws.ToString(a.MetricName))
			alarmMap[key] = alarmRef{
				name: aws.ToString(a.AlarmName),
				arn:  aws.ToString(a.AlarmArn),
			}
			// Also index with empty namespace in case metric transformation namespace is omitted
			if a.MetricName != nil {
				alarmMap["/"+aws.ToString(a.MetricName)] = alarmRef{
					name: aws.ToString(a.AlarmName),
					arn:  aws.ToString(a.AlarmArn),
				}
			}
		}
		if out.NextToken == nil {
			break
		}
		alarmToken = out.NextToken
	}

	// 3. Find filter + alarm pairs
	type matchedFilterAlarm struct {
		filterName string
		alarmName  string
		alarmArn   string
		pattern    string
	}

	var configuredPairs []matchedFilterAlarm
	for _, f := range filters {
		pattern := aws.ToString(f.FilterPattern)
		filterName := aws.ToString(f.FilterName)
		for _, tf := range f.MetricTransformations {
			key := fmt.Sprintf("%s/%s", aws.ToString(tf.MetricNamespace), aws.ToString(tf.MetricName))
			if alarm, exists := alarmMap[key]; exists {
				configuredPairs = append(configuredPairs, matchedFilterAlarm{
					filterName: filterName,
					alarmName:  alarm.name,
					alarmArn:   alarm.arn,
					pattern:    pattern,
				})
			} else {
				// Fallback to name-only check
				fallbackKey := "/" + aws.ToString(tf.MetricName)
				if alarm, exists := alarmMap[fallbackKey]; exists {
					configuredPairs = append(configuredPairs, matchedFilterAlarm{
						filterName: filterName,
						alarmName:  alarm.name,
						alarmArn:   alarm.arn,
						pattern:    pattern,
					})
				}
			}
		}
	}

	rules := getCloudWatchFilterRules()
	var results []scanner.ScanResult
	processedCount := 0

	for _, r := range rules {
		if limit > 0 && processedCount >= limit {
			break
		}
		processedCount++

		var matched *matchedFilterAlarm
		for i := range configuredPairs {
			if r.matcher(configuredPairs[i].pattern) {
				matched = &configuredPairs[i]
				break
			}
		}

		if matched != nil {
			// PASS
			resID := matched.alarmArn
			if resID == "" {
				resID = matched.alarmName
			}
			metrics := map[string]interface{}{
				"FilterName":     matched.filterName,
				"AlarmName":      matched.alarmName,
				"FilterPattern":  matched.pattern,
				"StatusExtended": fmt.Sprintf("Metric filter '%s' and alarm '%s' are configured for %s.", matched.filterName, matched.alarmName, r.title),
				"Recommendation": "Maintain metric filter and alarm configuration.",
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   resID,
				ResourceType: "SecaaS-CloudWatchAlarm",
				Region:       region,
				Status:       "PASS",
				RuleID:       r.checkID,
				Severity:     "INFO",
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       resID,
						NodeType: "SecaaS-CloudWatchAlarm",
					},
				},
			})
		} else {
			// FAIL
			resID := fmt.Sprintf("cloudwatch-%s-%s", region, r.checkID)
			metrics := map[string]interface{}{
				"StatusExtended": fmt.Sprintf("No metric filter and alarm configured for %s.", r.title),
				"SecurityIssues": []string{fmt.Sprintf("Missing metric filter or alarm for %s", r.title)},
				"Recommendation": fmt.Sprintf("Configure a CloudWatch Logs metric filter and alarm for %s.", r.title),
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   resID,
				ResourceType: "SecaaS-CloudWatchAlarm",
				Region:       region,
				Status:       "FAIL",
				RuleID:       r.checkID,
				Severity:     r.severity,
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       resID,
						NodeType: "SecaaS-CloudWatchAlarm",
					},
				},
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *CloudWatchScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "cloudwatch-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "cloudwatch",
		CheckIDs:      []string{"cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured", "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured", "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled", "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", "cloudwatch_log_metric_filter_authentication_failures", "cloudwatch_log_metric_filter_aws_organizations_changes", "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk", "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", "cloudwatch_log_metric_filter_policy_changes", "cloudwatch_log_metric_filter_root_usage", "cloudwatch_log_metric_filter_security_group_changes", "cloudwatch_log_metric_filter_sign_in_without_mfa", "cloudwatch_log_metric_filter_unauthorized_api_calls"},
	}
}
