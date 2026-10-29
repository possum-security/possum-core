package secaas_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	asgtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
)

type mockAutoScalingApi struct {
	describeAutoScalingGroupsOutput    *autoscaling.DescribeAutoScalingGroupsOutput
	describeAutoScalingGroupsErr       error
	describeLaunchConfigurationsOutput *autoscaling.DescribeLaunchConfigurationsOutput
	describeLaunchConfigurationsErr    error
}

func (m *mockAutoScalingApi) DescribeAutoScalingGroups(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	if m.describeAutoScalingGroupsErr != nil {
		return nil, m.describeAutoScalingGroupsErr
	}
	if m.describeAutoScalingGroupsOutput == nil {
		return &autoscaling.DescribeAutoScalingGroupsOutput{}, nil
	}
	return m.describeAutoScalingGroupsOutput, nil
}

func (m *mockAutoScalingApi) DescribeLaunchConfigurations(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error) {
	if m.describeLaunchConfigurationsErr != nil {
		return nil, m.describeLaunchConfigurationsErr
	}
	if m.describeLaunchConfigurationsOutput == nil {
		return &autoscaling.DescribeLaunchConfigurationsOutput{}, nil
	}
	return m.describeLaunchConfigurationsOutput, nil
}

func TestAutoScalingScanner_Name(t *testing.T) {
	sc := secaas.NewAutoScalingScannerWithClient(&mockAutoScalingApi{}, "us-east-1")
	if sc.Name() != "AutoScaling-SecaaS-Scanner" {
		t.Errorf("expected scanner name 'AutoScaling-SecaaS-Scanner', got %s", sc.Name())
	}
}

func TestAutoScalingScanner_Compliant_AllPass(t *testing.T) {
	mockAPI := &mockAutoScalingApi{
		describeLaunchConfigurationsOutput: &autoscaling.DescribeLaunchConfigurationsOutput{
			LaunchConfigurations: []asgtypes.LaunchConfiguration{
				{
					LaunchConfigurationName:  aws.String("secure-lc"),
					AssociatePublicIpAddress: aws.Bool(false),
					MetadataOptions: &asgtypes.InstanceMetadataOptions{
						HttpTokens: asgtypes.InstanceMetadataHttpTokensStateRequired,
					},
					UserData: aws.String("#!/bin/bash\necho 'safe boot'"),
				},
			},
		},
		describeAutoScalingGroupsOutput: &autoscaling.DescribeAutoScalingGroupsOutput{
			AutoScalingGroups: []asgtypes.AutoScalingGroup{
				{
					AutoScalingGroupName:    aws.String("secure-asg"),
					LaunchConfigurationName: aws.String("secure-lc"),
				},
				{
					AutoScalingGroupName: aws.String("template-asg"),
					LaunchTemplate: &asgtypes.LaunchTemplateSpecification{
						LaunchTemplateName: aws.String("modern-template"),
					},
				},
			},
		},
	}

	sc := secaas.NewAutoScalingScannerWithClient(mockAPI, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 checks for secure-asg + 3 checks for template-asg = 6 results
	if len(results) != 6 {
		t.Fatalf("expected 6 results, got %d", len(results))
	}

	for _, r := range results {
		if r.ResourceType != "SecaaS-AutoScaling" {
			t.Errorf("expected ResourceType SecaaS-AutoScaling, got %s", r.ResourceType)
		}
		if r.Status != "PASS" {
			t.Errorf("expected check %s on %s to PASS, got %s", r.RuleID, r.ResourceID, r.Status)
		}
		if r.Severity != "INFO" {
			t.Errorf("expected severity INFO for PASS result, got %s", r.Severity)
		}
	}
}

func TestAutoScalingScanner_NonCompliant_AllFail(t *testing.T) {
	mockAPI := &mockAutoScalingApi{
		describeLaunchConfigurationsOutput: &autoscaling.DescribeLaunchConfigurationsOutput{
			LaunchConfigurations: []asgtypes.LaunchConfiguration{
				{
					LaunchConfigurationName:  aws.String("insecure-lc"),
					AssociatePublicIpAddress: aws.Bool(true),
					MetadataOptions: &asgtypes.InstanceMetadataOptions{
						HttpTokens: asgtypes.InstanceMetadataHttpTokensStateOptional,
					},
					UserData: aws.String("#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE\npassword=adminsecret"),
				},
			},
		},
		describeAutoScalingGroupsOutput: &autoscaling.DescribeAutoScalingGroupsOutput{
			AutoScalingGroups: []asgtypes.AutoScalingGroup{
				{
					AutoScalingGroupName:    aws.String("insecure-asg"),
					LaunchConfigurationName: aws.String("insecure-lc"),
				},
			},
		},
	}

	sc := secaas.NewAutoScalingScannerWithClient(mockAPI, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != "FAIL" {
			t.Errorf("expected check %s to FAIL, got %s", r.RuleID, r.Status)
		}
		switch r.RuleID {
		case "autoscaling_group_launch_configuration_requires_imdsv2":
			if r.Severity != "HIGH" {
				t.Errorf("expected IMDSv2 severity HIGH, got %s", r.Severity)
			}
		case "autoscaling_find_secrets_ec2_launch_configuration":
			if r.Severity != "CRITICAL" {
				t.Errorf("expected secrets severity CRITICAL, got %s", r.Severity)
			}
		case "autoscaling_group_launch_configuration_no_public_ip":
			if r.Severity != "MEDIUM" {
				t.Errorf("expected no_public_ip severity MEDIUM, got %s", r.Severity)
			}
		default:
			t.Errorf("unexpected rule ID: %s", r.RuleID)
		}
	}
}

func TestAutoScalingScanner_SecretPatterns(t *testing.T) {
	tests := []struct {
		name     string
		userData string
		shouldEx bool
	}{
		{
			name:     "AKIA pattern",
			userData: "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			shouldEx: true,
		},
		{
			name:     "BEGIN RSA PRIVATE KEY pattern",
			userData: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...",
			shouldEx: true,
		},
		{
			name:     "password= pattern",
			userData: "export db_password=supersecret",
			shouldEx: true,
		},
		{
			name:     "secret_key= pattern",
			userData: "secret_key=abracadabra123",
			shouldEx: true,
		},
		{
			name:     "base64 encoded AKIA secret",
			userData: base64.StdEncoding.EncodeToString([]byte("AKIAEXAMPLEKEY12345")),
			shouldEx: true,
		},
		{
			name:     "clean script without secrets",
			userData: "#!/bin/bash\nsystemctl start httpd",
			shouldEx: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockAPI := &mockAutoScalingApi{
				describeLaunchConfigurationsOutput: &autoscaling.DescribeLaunchConfigurationsOutput{
					LaunchConfigurations: []asgtypes.LaunchConfiguration{
						{
							LaunchConfigurationName:  aws.String("test-lc"),
							AssociatePublicIpAddress: aws.Bool(false),
							MetadataOptions: &asgtypes.InstanceMetadataOptions{
								HttpTokens: asgtypes.InstanceMetadataHttpTokensStateRequired,
							},
							UserData: aws.String(tc.userData),
						},
					},
				},
				describeAutoScalingGroupsOutput: &autoscaling.DescribeAutoScalingGroupsOutput{
					AutoScalingGroups: []asgtypes.AutoScalingGroup{
						{
							AutoScalingGroupName:    aws.String("test-asg"),
							LaunchConfigurationName: aws.String("test-lc"),
						},
					},
				},
			}

			sc := secaas.NewAutoScalingScannerWithClient(mockAPI, "us-east-1")
			results, err := sc.Scan(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var secretResult *autoscalingScanResultFinder
			for _, r := range results {
				if r.RuleID == "autoscaling_find_secrets_ec2_launch_configuration" {
					secretResult = &autoscalingScanResultFinder{status: r.Status, severity: r.Severity}
					break
				}
			}

			if secretResult == nil {
				t.Fatalf("secret check result not found")
			}

			if tc.shouldEx {
				if secretResult.status != "FAIL" {
					t.Errorf("expected FAIL for pattern, got %s", secretResult.status)
				}
				if secretResult.severity != "CRITICAL" {
					t.Errorf("expected severity CRITICAL, got %s", secretResult.severity)
				}
			} else {
				if secretResult.status != "PASS" {
					t.Errorf("expected PASS for clean script, got %s", secretResult.status)
				}
			}
		})
	}
}

type autoscalingScanResultFinder struct {
	status   string
	severity string
}

func TestAutoScalingScanner_StandaloneLaunchConfigurations(t *testing.T) {
	mockAPI := &mockAutoScalingApi{
		describeLaunchConfigurationsOutput: &autoscaling.DescribeLaunchConfigurationsOutput{
			LaunchConfigurations: []asgtypes.LaunchConfiguration{
				{
					LaunchConfigurationName:  aws.String("standalone-lc"),
					AssociatePublicIpAddress: nil, // should PASS no public IP
					MetadataOptions: &asgtypes.InstanceMetadataOptions{
						HttpTokens: asgtypes.InstanceMetadataHttpTokensStateRequired,
					},
					UserData: nil, // no secrets
				},
			},
		},
		describeAutoScalingGroupsOutput: &autoscaling.DescribeAutoScalingGroupsOutput{
			AutoScalingGroups: []asgtypes.AutoScalingGroup{}, // empty ASGs
		},
	}

	sc := secaas.NewAutoScalingScannerWithClient(mockAPI, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("expected 3 results for standalone LC, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != "PASS" {
			t.Errorf("expected %s to PASS, got %s", r.RuleID, r.Status)
		}
		if r.ResourceID != "standalone-lc" {
			t.Errorf("expected ResourceID 'standalone-lc', got %s", r.ResourceID)
		}
	}
}

func TestAutoScalingScanner_Errors(t *testing.T) {
	t.Run("DescribeLaunchConfigurations error", func(t *testing.T) {
		mockAPI := &mockAutoScalingApi{
			describeLaunchConfigurationsErr: errors.New("launch config error"),
		}
		sc := secaas.NewAutoScalingScannerWithClient(mockAPI, "us-east-1")
		_, err := sc.Scan(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("DescribeAutoScalingGroups error", func(t *testing.T) {
		mockAPI := &mockAutoScalingApi{
			describeAutoScalingGroupsErr: errors.New("asg error"),
		}
		sc := secaas.NewAutoScalingScannerWithClient(mockAPI, "us-east-1")
		_, err := sc.Scan(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
