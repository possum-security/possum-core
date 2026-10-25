package secaas

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CloudTrailAPI defines the interface for CloudTrail operations.
type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetEventSelectors(ctx context.Context, params *cloudtrail.GetEventSelectorsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error)
}

// CloudTrailS3API defines the interface for S3 operations related to CloudTrail target buckets.
type CloudTrailS3API interface {
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
}

type CloudTrailScanner struct {
	client   CloudTrailAPI
	s3Client CloudTrailS3API
}

func NewCloudTrailScanner(cfg aws.Config) *CloudTrailScanner {
	return &CloudTrailScanner{
		client:   cloudtrail.NewFromConfig(cfg),
		s3Client: s3.NewFromConfig(cfg),
	}
}

func NewCloudTrailScannerWithClients(client CloudTrailAPI, s3Client CloudTrailS3API) *CloudTrailScanner {
	return &CloudTrailScanner{
		client:   client,
		s3Client: s3Client,
	}
}

func (s *CloudTrailScanner) Name() string {
	return "CloudTrail-SecaaS-Scanner"
}

func (s *CloudTrailScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	output, err := s.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, err
	}

	if len(output.TrailList) == 0 {
		// Account has no trails configured (CIS 3.1)
		results = append(results, scanner.ScanResult{
			ResourceID:   "CloudTrail",
			ResourceType: "SecaaS-CloudTrail",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "cloudtrail_multi_region_enabled",
			Severity:     "CRITICAL",
			Metrics: map[string]interface{}{
				"StatusExtended": "No CloudTrail trails are configured in the AWS account.",
				"SecurityIssues": []string{"CloudTrail logging is completely disabled"},
				"Recommendation": "Create a multi-region CloudTrail trail to log management and data events across all regions.",
			},
			Nodes: []graph.Node{{ID: "CloudTrail", NodeType: "SecaaS-IAM"}},
		})
		return results, nil
	}

	for _, trail := range output.TrailList {
		if limit > 0 && processedCount >= limit {
			break
		}
		processedCount++

		trailName := aws.ToString(trail.Name)
		trailArn := aws.ToString(trail.TrailARN)
		homeRegion := aws.ToString(trail.HomeRegion)
		if homeRegion == "" {
			homeRegion = "global"
		}
		bucketName := aws.ToString(trail.S3BucketName)

		trailNode := graph.Node{
			ID:       trailArn,
			NodeType: "SecaaS-CloudTrail",
		}

		// 1. Multi-region logging (CIS 3.1)
		isMultiRegion := aws.ToBool(trail.IsMultiRegionTrail)
		mrStatus := "PASS"
		mrSev := "INFO"
		mrExt := fmt.Sprintf("CloudTrail trail %s is configured with multi-region logging.", trailName)
		if !isMultiRegion {
			mrStatus = "FAIL"
			mrSev = "HIGH"
			mrExt = fmt.Sprintf("CloudTrail trail %s is not configured for multi-region logging.", trailName)
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   trailName,
			ResourceType: "SecaaS-CloudTrail",
			Region:       homeRegion,
			Status:       mrStatus,
			RuleID:       "cloudtrail_multi_region_enabled",
			Severity:     mrSev,
			Metrics: map[string]interface{}{
				"TrailName":          trailName,
				"IsMultiRegionTrail": isMultiRegion,
				"StatusExtended":     mrExt,
				"Recommendation":     "Enable multi-region logging on all CloudTrail trails.",
			},
			Nodes: []graph.Node{trailNode},
		})

		// 2. Log file validation (CIS 3.2)
		logValidation := aws.ToBool(trail.LogFileValidationEnabled)
		lvStatus := "PASS"
		lvSev := "INFO"
		lvExt := fmt.Sprintf("CloudTrail trail %s has log file validation enabled.", trailName)
		if !logValidation {
			lvStatus = "FAIL"
			lvSev = "MEDIUM"
			lvExt = fmt.Sprintf("CloudTrail trail %s does not have log file validation enabled.", trailName)
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   trailName,
			ResourceType: "SecaaS-CloudTrail",
			Region:       homeRegion,
			Status:       lvStatus,
			RuleID:       "cloudtrail_log_file_validation_enabled",
			Severity:     lvSev,
			Metrics: map[string]interface{}{
				"TrailName":                trailName,
				"LogFileValidationEnabled": logValidation,
				"StatusExtended":           lvExt,
				"Recommendation":           "Enable log file validation to ensure cryptographic digest verification of trail logs.",
			},
			Nodes: []graph.Node{trailNode},
		})

		// 3. CloudWatch Logs Integration (CIS 3.4)
		hasCWLogs := trail.CloudWatchLogsLogGroupArn != nil && aws.ToString(trail.CloudWatchLogsLogGroupArn) != ""
		cwStatus := "PASS"
		cwSev := "INFO"
		cwExt := fmt.Sprintf("CloudTrail trail %s forwards events to CloudWatch Logs (%s).", trailName, aws.ToString(trail.CloudWatchLogsLogGroupArn))
		if !hasCWLogs {
			cwStatus = "FAIL"
			cwSev = "LOW"
			cwExt = fmt.Sprintf("CloudTrail trail %s is not integrated with CloudWatch Logs.", trailName)
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   trailName,
			ResourceType: "SecaaS-CloudTrail",
			Region:       homeRegion,
			Status:       cwStatus,
			RuleID:       "cloudtrail_cloudwatch_logging_enabled",
			Severity:     cwSev,
			Metrics: map[string]interface{}{
				"TrailName":      trailName,
				"CWLogGroup":     aws.ToString(trail.CloudWatchLogsLogGroupArn),
				"StatusExtended": cwExt,
				"Recommendation": "Deliver CloudTrail logs to CloudWatch Logs for real-time metric filtering and alerting.",
			},
			Nodes: []graph.Node{trailNode},
		})

		// 4. KMS Encryption at Rest (CIS 3.7)
		hasKMS := trail.KmsKeyId != nil && aws.ToString(trail.KmsKeyId) != ""
		kmsStatus := "PASS"
		kmsSev := "INFO"
		kmsExt := fmt.Sprintf("CloudTrail trail %s is encrypted with customer-managed KMS key %s.", trailName, aws.ToString(trail.KmsKeyId))
		if !hasKMS {
			kmsStatus = "FAIL"
			kmsSev = "HIGH"
			kmsExt = fmt.Sprintf("CloudTrail trail %s is not encrypted using a customer-managed KMS key.", trailName)
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   trailName,
			ResourceType: "SecaaS-CloudTrail",
			Region:       homeRegion,
			Status:       kmsStatus,
			RuleID:       "cloudtrail_kms_encryption_enabled",
			Severity:     kmsSev,
			Metrics: map[string]interface{}{
				"TrailName":      trailName,
				"KmsKeyId":       aws.ToString(trail.KmsKeyId),
				"StatusExtended": kmsExt,
				"Recommendation": "Encrypt CloudTrail log files using a Customer Managed Key (CMK) in AWS KMS.",
			},
			Nodes: []graph.Node{trailNode},
		})

		// 5 & 6. S3 Data Events (Read & Write) (CIS 3.10 & 3.11)
		hasWriteDataEvents := false
		hasReadDataEvents := false
		selectorsOut, selErr := s.client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: trail.Name})
		if selErr == nil && selectorsOut != nil {
			for _, sel := range selectorsOut.EventSelectors {
				for _, res := range sel.DataResources {
					if aws.ToString(res.Type) == "AWS::S3::Object" {
						rwType := sel.ReadWriteType
						if rwType == cttypes.ReadWriteTypeAll || rwType == cttypes.ReadWriteTypeWriteOnly {
							hasWriteDataEvents = true
						}
						if rwType == cttypes.ReadWriteTypeAll || rwType == cttypes.ReadWriteTypeReadOnly {
							hasReadDataEvents = true
						}
					}
				}
			}
			for _, advSel := range selectorsOut.AdvancedEventSelectors {
				for _, fs := range advSel.FieldSelectors {
					if aws.ToString(fs.Field) == "resources.type" {
						for _, eqVal := range fs.Equals {
							if eqVal == "AWS::S3::Object" {
								hasWriteDataEvents = true
								hasReadDataEvents = true
							}
						}
					}
				}
			}
		}

		// cloudtrail_s3_dataevents_write_enabled
		wStatus := "PASS"
		wSev := "INFO"
		wExt := fmt.Sprintf("CloudTrail trail %s logs S3 data events for Write operations.", trailName)
		if !hasWriteDataEvents {
			wStatus = "FAIL"
			wSev = "LOW"
			wExt = fmt.Sprintf("CloudTrail trail %s does not record S3 Write data events.", trailName)
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   trailName,
			ResourceType: "SecaaS-CloudTrail",
			Region:       homeRegion,
			Status:       wStatus,
			RuleID:       "cloudtrail_s3_dataevents_write_enabled",
			Severity:     wSev,
			Metrics: map[string]interface{}{
				"TrailName":      trailName,
				"StatusExtended": wExt,
				"Recommendation": "Enable data event logging for S3 Object write operations on CloudTrail.",
			},
			Nodes: []graph.Node{trailNode},
		})

		// cloudtrail_s3_dataevents_read_enabled
		rStatus := "PASS"
		rSev := "INFO"
		rExt := fmt.Sprintf("CloudTrail trail %s logs S3 data events for Read operations.", trailName)
		if !hasReadDataEvents {
			rStatus = "FAIL"
			rSev = "LOW"
			rExt = fmt.Sprintf("CloudTrail trail %s does not record S3 Read data events.", trailName)
		}
		results = append(results, scanner.ScanResult{
			ResourceID:   trailName,
			ResourceType: "SecaaS-CloudTrail",
			Region:       homeRegion,
			Status:       rStatus,
			RuleID:       "cloudtrail_s3_dataevents_read_enabled",
			Severity:     rSev,
			Metrics: map[string]interface{}{
				"TrailName":      trailName,
				"StatusExtended": rExt,
				"Recommendation": "Enable data event logging for S3 Object read operations on CloudTrail.",
			},
			Nodes: []graph.Node{trailNode},
		})

		// 7 & 8. Target S3 Bucket Security (CIS 3.3 & 3.6)
		if bucketName != "" && s.s3Client != nil {
			// S3 Public Access Block
			pabOut, pabErr := s.s3Client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucketName)})
			isBucketPublic := false
			if pabErr != nil || pabOut == nil || pabOut.PublicAccessBlockConfiguration == nil ||
				!aws.ToBool(pabOut.PublicAccessBlockConfiguration.BlockPublicAcls) ||
				!aws.ToBool(pabOut.PublicAccessBlockConfiguration.BlockPublicPolicy) ||
				!aws.ToBool(pabOut.PublicAccessBlockConfiguration.IgnorePublicAcls) ||
				!aws.ToBool(pabOut.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
				isBucketPublic = true
			}
			bPubStatus := "PASS"
			bPubSev := "INFO"
			bPubExt := fmt.Sprintf("CloudTrail audit log bucket %s has S3 Block Public Access fully enabled.", bucketName)
			if isBucketPublic {
				bPubStatus = "FAIL"
				bPubSev = "CRITICAL"
				bPubExt = fmt.Sprintf("CloudTrail audit log bucket %s does not have all S3 Public Access Block settings enabled.", bucketName)
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       bPubStatus,
				RuleID:       "cloudtrail_logs_s3_bucket_is_not_publicly_accessible",
				Severity:     bPubSev,
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"TrailName":      trailName,
					"StatusExtended": bPubExt,
					"Recommendation": "Enable all four S3 Block Public Access settings on the CloudTrail audit log bucket.",
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})

			// S3 Access Logging (CIS 3.6)
			logOut, logErr := s.s3Client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: aws.String(bucketName)})
			isLoggingEnabled := logErr == nil && logOut != nil && logOut.LoggingEnabled != nil
			bLogStatus := "PASS"
			bLogSev := "INFO"
			bLogExt := fmt.Sprintf("CloudTrail audit log bucket %s has access logging enabled.", bucketName)
			if !isLoggingEnabled {
				bLogStatus = "FAIL"
				bLogSev = "MEDIUM"
				bLogExt = fmt.Sprintf("CloudTrail audit log bucket %s does not have server access logging enabled.", bucketName)
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       bLogStatus,
				RuleID:       "cloudtrail_logs_s3_bucket_access_logging_enabled",
				Severity:     bLogSev,
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"TrailName":      trailName,
					"StatusExtended": bLogExt,
					"Recommendation": "Enable server access logging on the CloudTrail audit log bucket.",
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}
	}

	return results, nil
}
