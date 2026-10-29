package secaas

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
)

// AutoScalingApi defines the interface for AWS Auto Scaling operations.
type AutoScalingApi interface {
	DescribeAutoScalingGroups(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
	DescribeLaunchConfigurations(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error)
}

// AutoScalingScanner evaluates security postures for Auto Scaling groups and launch configurations.
type AutoScalingScanner struct {
	client AutoScalingApi
	region string
}

// NewAutoScalingScanner creates a new AutoScalingScanner with AWS config.
func NewAutoScalingScanner(cfg aws.Config) *AutoScalingScanner {
	return &AutoScalingScanner{
		client: autoscaling.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewAutoScalingScannerWithClient creates a new AutoScalingScanner with a custom/mock client.
func NewAutoScalingScannerWithClient(client AutoScalingApi, region string) *AutoScalingScanner {
	return &AutoScalingScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *AutoScalingScanner) Name() string {
	return "AutoScaling-SecaaS-Scanner"
}

// hasPlaintextSecret checks if the given UserData contains plaintext credentials or secrets.
func hasPlaintextSecret(userData *string) bool {
	if userData == nil || *userData == "" {
		return false
	}
	content := *userData
	if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
		content = string(decoded) + "\n" + content
	}

	if strings.Contains(content, "AKIA") || strings.Contains(content, "BEGIN RSA PRIVATE KEY") {
		return true
	}

	contentLower := strings.ToLower(content)
	if strings.Contains(contentLower, "password=") || strings.Contains(contentLower, "secret_key=") {
		return true
	}

	return false
}

// Scan audits Auto Scaling groups and launch configurations for security best practices.
func (s *AutoScalingScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	// 1. Fetch launch configurations
	lcsByName := make(map[string]asgtypes.LaunchConfiguration)
	var allLCs []asgtypes.LaunchConfiguration

	lcPaginator := autoscaling.NewDescribeLaunchConfigurationsPaginator(s.client, &autoscaling.DescribeLaunchConfigurationsInput{})
	for lcPaginator.HasMorePages() {
		page, err := lcPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lc := range page.LaunchConfigurations {
			if lc.LaunchConfigurationName != nil {
				lcsByName[*lc.LaunchConfigurationName] = lc
			}
			allLCs = append(allLCs, lc)
		}
	}

	// 2. Fetch Auto Scaling groups
	asgPaginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(s.client, &autoscaling.DescribeAutoScalingGroupsInput{})
	var allASGs []asgtypes.AutoScalingGroup
	for asgPaginator.HasMorePages() {
		page, err := asgPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		allASGs = append(allASGs, page.AutoScalingGroups...)
	}

	// 3. Evaluate
	if len(allASGs) > 0 {
		for _, asg := range allASGs {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			asgName := aws.ToString(asg.AutoScalingGroupName)
			asgArn := aws.ToString(asg.AutoScalingGroupARN)
			nodeID := asgArn
			if nodeID == "" {
				nodeID = asgName
			}
			nodes := []graph.Node{
				{
					ID:       nodeID,
					NodeType: "SecaaS-AutoScaling",
				},
			}

			// If ASG uses a launch template instead of a launch configuration
			if asg.LaunchTemplate != nil || asg.MixedInstancesPolicy != nil {
				ltName := ""
				if asg.LaunchTemplate != nil {
					ltName = aws.ToString(asg.LaunchTemplate.LaunchTemplateName)
				}
				templateMetrics := map[string]interface{}{
					"AutoScalingGroupName": asgName,
					"LaunchTemplateName":   ltName,
					"StatusExtended":       fmt.Sprintf("Auto Scaling group %s uses a launch template instead of a launch configuration.", asgName),
				}

				results = append(results,
					scanner.ScanResult{
						ResourceID:   asgName,
						ResourceType: "SecaaS-AutoScaling",
						Region:       region,
						Status:       "PASS",
						RuleID:       "autoscaling_group_launch_configuration_requires_imdsv2",
						Severity:     "INFO",
						Metrics:      templateMetrics,
						Nodes:        nodes,
					},
					scanner.ScanResult{
						ResourceID:   asgName,
						ResourceType: "SecaaS-AutoScaling",
						Region:       region,
						Status:       "PASS",
						RuleID:       "autoscaling_find_secrets_ec2_launch_configuration",
						Severity:     "INFO",
						Metrics:      templateMetrics,
						Nodes:        nodes,
					},
					scanner.ScanResult{
						ResourceID:   asgName,
						ResourceType: "SecaaS-AutoScaling",
						Region:       region,
						Status:       "PASS",
						RuleID:       "autoscaling_group_launch_configuration_no_public_ip",
						Severity:     "INFO",
						Metrics:      templateMetrics,
						Nodes:        nodes,
					},
				)
				continue
			}

			// ASG uses a launch configuration
			lcName := aws.ToString(asg.LaunchConfigurationName)
			lc, hasLC := lcsByName[lcName]

			// Check 1: IMDSv2
			imdsPass := hasLC && lc.MetadataOptions != nil && (lc.MetadataOptions.HttpTokens == asgtypes.InstanceMetadataHttpTokensStateRequired || string(lc.MetadataOptions.HttpTokens) == "required")
			imdsStatus := "PASS"
			imdsSev := "INFO"
			imdsExt := fmt.Sprintf("Auto Scaling group %s launch configuration enforces IMDSv2 (HttpTokens=required).", asgName)
			imdsRec := ""
			if !imdsPass {
				imdsStatus = "FAIL"
				imdsSev = "HIGH"
				imdsExt = fmt.Sprintf("Auto Scaling group %s launch configuration does not enforce IMDSv2.", asgName)
				imdsRec = "Configure the launch configuration to enforce IMDSv2 by setting HttpTokens to 'required'."
			}
			imdsMetrics := map[string]interface{}{
				"AutoScalingGroupName":    asgName,
				"LaunchConfigurationName": lcName,
				"StatusExtended":          imdsExt,
			}
			if imdsRec != "" {
				imdsMetrics["Recommendation"] = imdsRec
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   asgName,
				ResourceType: "SecaaS-AutoScaling",
				Region:       region,
				Status:       imdsStatus,
				RuleID:       "autoscaling_group_launch_configuration_requires_imdsv2",
				Severity:     imdsSev,
				Metrics:      imdsMetrics,
				Nodes:        nodes,
			})

			// Check 2: Secrets in UserData
			hasSecret := hasLC && hasPlaintextSecret(lc.UserData)
			secStatus := "PASS"
			secSev := "INFO"
			secExt := fmt.Sprintf("Auto Scaling group %s launch configuration UserData does not contain plaintext secrets.", asgName)
			secRec := ""
			if hasSecret {
				secStatus = "FAIL"
				secSev = "CRITICAL"
				secExt = fmt.Sprintf("Auto Scaling group %s launch configuration UserData contains plaintext secrets.", asgName)
				secRec = "Remove plaintext credentials, passwords, and secret keys from launch configuration UserData. Use IAM roles or Secrets Manager instead."
			}
			secMetrics := map[string]interface{}{
				"AutoScalingGroupName":    asgName,
				"LaunchConfigurationName": lcName,
				"StatusExtended":          secExt,
			}
			if secRec != "" {
				secMetrics["Recommendation"] = secRec
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   asgName,
				ResourceType: "SecaaS-AutoScaling",
				Region:       region,
				Status:       secStatus,
				RuleID:       "autoscaling_find_secrets_ec2_launch_configuration",
				Severity:     secSev,
				Metrics:      secMetrics,
				Nodes:        nodes,
			})

			// Check 3: No Public IP
			hasPublicIP := hasLC && lc.AssociatePublicIpAddress != nil && *lc.AssociatePublicIpAddress
			ipStatus := "PASS"
			ipSev := "INFO"
			ipExt := fmt.Sprintf("Auto Scaling group %s launch configuration does not assign a public IP address.", asgName)
			ipRec := ""
			if hasPublicIP {
				ipStatus = "FAIL"
				ipSev = "MEDIUM"
				ipExt = fmt.Sprintf("Auto Scaling group %s launch configuration assigns a public IP address (AssociatePublicIpAddress=true).", asgName)
				ipRec = "Set AssociatePublicIpAddress to false in the launch configuration and deploy instances in private subnets."
			}
			ipMetrics := map[string]interface{}{
				"AutoScalingGroupName":    asgName,
				"LaunchConfigurationName": lcName,
				"StatusExtended":          ipExt,
			}
			if ipRec != "" {
				ipMetrics["Recommendation"] = ipRec
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   asgName,
				ResourceType: "SecaaS-AutoScaling",
				Region:       region,
				Status:       ipStatus,
				RuleID:       "autoscaling_group_launch_configuration_no_public_ip",
				Severity:     ipSev,
				Metrics:      ipMetrics,
				Nodes:        nodes,
			})
		}
	} else {
		// When no ASGs exist but standalone Launch Configurations exist
		for _, lc := range allLCs {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			lcName := aws.ToString(lc.LaunchConfigurationName)
			lcArn := aws.ToString(lc.LaunchConfigurationARN)
			nodeID := lcArn
			if nodeID == "" {
				nodeID = lcName
			}
			nodes := []graph.Node{
				{
					ID:       nodeID,
					NodeType: "SecaaS-AutoScaling",
				},
			}

			// Check 1: IMDSv2
			imdsPass := lc.MetadataOptions != nil && (lc.MetadataOptions.HttpTokens == asgtypes.InstanceMetadataHttpTokensStateRequired || string(lc.MetadataOptions.HttpTokens) == "required")
			imdsStatus := "PASS"
			imdsSev := "INFO"
			imdsExt := fmt.Sprintf("Launch configuration %s enforces IMDSv2 (HttpTokens=required).", lcName)
			imdsRec := ""
			if !imdsPass {
				imdsStatus = "FAIL"
				imdsSev = "HIGH"
				imdsExt = fmt.Sprintf("Launch configuration %s does not enforce IMDSv2.", lcName)
				imdsRec = "Configure the launch configuration to enforce IMDSv2 by setting HttpTokens to 'required'."
			}
			imdsMetrics := map[string]interface{}{
				"LaunchConfigurationName": lcName,
				"StatusExtended":          imdsExt,
			}
			if imdsRec != "" {
				imdsMetrics["Recommendation"] = imdsRec
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lcName,
				ResourceType: "SecaaS-AutoScaling",
				Region:       region,
				Status:       imdsStatus,
				RuleID:       "autoscaling_group_launch_configuration_requires_imdsv2",
				Severity:     imdsSev,
				Metrics:      imdsMetrics,
				Nodes:        nodes,
			})

			// Check 2: Secrets in UserData
			hasSecret := hasPlaintextSecret(lc.UserData)
			secStatus := "PASS"
			secSev := "INFO"
			secExt := fmt.Sprintf("Launch configuration %s UserData does not contain plaintext secrets.", lcName)
			secRec := ""
			if hasSecret {
				secStatus = "FAIL"
				secSev = "CRITICAL"
				secExt = fmt.Sprintf("Launch configuration %s UserData contains plaintext secrets.", lcName)
				secRec = "Remove plaintext credentials, passwords, and secret keys from launch configuration UserData. Use IAM roles or Secrets Manager instead."
			}
			secMetrics := map[string]interface{}{
				"LaunchConfigurationName": lcName,
				"StatusExtended":          secExt,
			}
			if secRec != "" {
				secMetrics["Recommendation"] = secRec
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lcName,
				ResourceType: "SecaaS-AutoScaling",
				Region:       region,
				Status:       secStatus,
				RuleID:       "autoscaling_find_secrets_ec2_launch_configuration",
				Severity:     secSev,
				Metrics:      secMetrics,
				Nodes:        nodes,
			})

			// Check 3: No Public IP
			hasPublicIP := lc.AssociatePublicIpAddress != nil && *lc.AssociatePublicIpAddress
			ipStatus := "PASS"
			ipSev := "INFO"
			ipExt := fmt.Sprintf("Launch configuration %s does not assign a public IP address.", lcName)
			ipRec := ""
			if hasPublicIP {
				ipStatus = "FAIL"
				ipSev = "MEDIUM"
				ipExt = fmt.Sprintf("Launch configuration %s assigns a public IP address (AssociatePublicIpAddress=true).", lcName)
				ipRec = "Set AssociatePublicIpAddress to false in the launch configuration and deploy instances in private subnets."
			}
			ipMetrics := map[string]interface{}{
				"LaunchConfigurationName": lcName,
				"StatusExtended":          ipExt,
			}
			if ipRec != "" {
				ipMetrics["Recommendation"] = ipRec
			}
			results = append(results, scanner.ScanResult{
				ResourceID:   lcName,
				ResourceType: "SecaaS-AutoScaling",
				Region:       region,
				Status:       ipStatus,
				RuleID:       "autoscaling_group_launch_configuration_no_public_ip",
				Severity:     ipSev,
				Metrics:      ipMetrics,
				Nodes:        nodes,
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *AutoScalingScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "autoscaling-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "autoscaling",
		CheckIDs:      []string{"autoscaling_find_secrets_ec2_launch_configuration", "autoscaling_group_launch_configuration_no_public_ip", "autoscaling_group_launch_configuration_requires_imdsv2"},
	}
}
