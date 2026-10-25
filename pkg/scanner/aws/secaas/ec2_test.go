package secaas_test

import (
	"context"
	"errors"
	"testing"

	"github.com/possum-sec/possum/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockEC2Api struct {
	describeInstancesOutput          *ec2.DescribeInstancesOutput
	describeInstancesErr             error
	getEbsEncryptionByDefaultOutput  *ec2.GetEbsEncryptionByDefaultOutput
	getEbsEncryptionByDefaultErr     error
	describeImagesOutput             *ec2.DescribeImagesOutput
	describeImagesErr                error
	describeSnapshotsOutput          *ec2.DescribeSnapshotsOutput
	describeSnapshotsErr             error
	describeSnapshotAttributeOutputs map[string]*ec2.DescribeSnapshotAttributeOutput
	describeSnapshotAttributeErr     error
	describeSecurityGroupsOutput     *ec2.DescribeSecurityGroupsOutput
	describeSecurityGroupsErr        error
}

func (m *mockEC2Api) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if m.describeInstancesErr != nil {
		return nil, m.describeInstancesErr
	}
	if m.describeInstancesOutput == nil {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return m.describeInstancesOutput, nil
}

func (m *mockEC2Api) GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error) {
	if m.getEbsEncryptionByDefaultErr != nil {
		return nil, m.getEbsEncryptionByDefaultErr
	}
	return m.getEbsEncryptionByDefaultOutput, nil
}

func (m *mockEC2Api) DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	if m.describeImagesErr != nil {
		return nil, m.describeImagesErr
	}
	if m.describeImagesOutput == nil {
		return &ec2.DescribeImagesOutput{}, nil
	}
	return m.describeImagesOutput, nil
}

func (m *mockEC2Api) DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if m.describeSnapshotsErr != nil {
		return nil, m.describeSnapshotsErr
	}
	if m.describeSnapshotsOutput == nil {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}
	return m.describeSnapshotsOutput, nil
}

func (m *mockEC2Api) DescribeSnapshotAttribute(ctx context.Context, params *ec2.DescribeSnapshotAttributeInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error) {
	if m.describeSnapshotAttributeErr != nil {
		return nil, m.describeSnapshotAttributeErr
	}
	if params != nil && params.SnapshotId != nil && m.describeSnapshotAttributeOutputs != nil {
		if out, ok := m.describeSnapshotAttributeOutputs[*params.SnapshotId]; ok {
			return out, nil
		}
	}
	return &ec2.DescribeSnapshotAttributeOutput{}, nil
}

func (m *mockEC2Api) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.describeSecurityGroupsErr != nil {
		return nil, m.describeSecurityGroupsErr
	}
	if m.describeSecurityGroupsOutput == nil {
		return &ec2.DescribeSecurityGroupsOutput{}, nil
	}
	return m.describeSecurityGroupsOutput, nil
}

func TestEC2Scanner_Compliant_AllPass(t *testing.T) {
	mockAPI := &mockEC2Api{
		getEbsEncryptionByDefaultOutput: &ec2.GetEbsEncryptionByDefaultOutput{
			EbsEncryptionByDefault: aws.Bool(true),
		},
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{
							InstanceId: aws.String("i-0123456789abcdef0"),
							IamInstanceProfile: &ec2types.IamInstanceProfile{
								Arn: aws.String("arn:aws:iam::123456789012:instance-profile/AppRole"),
							},
							MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
								HttpTokens:   ec2types.HttpTokensStateRequired,
								HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
							},
						},
						{
							InstanceId: aws.String("i-0987654321fedcba0"),
							IamInstanceProfile: &ec2types.IamInstanceProfile{
								Arn: aws.String("arn:aws:iam::123456789012:instance-profile/AppRole"),
							},
							MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
								HttpTokens:   ec2types.HttpTokensStateOptional,
								HttpEndpoint: ec2types.InstanceMetadataEndpointStateDisabled,
							},
						},
					},
				},
			},
		},
		describeImagesOutput: &ec2.DescribeImagesOutput{
			Images: []ec2types.Image{
				{
					ImageId: aws.String("ami-0123456789private"),
					Name:    aws.String("my-private-ami"),
					Public:  aws.Bool(false),
				},
			},
		},
		describeSnapshotsOutput: &ec2.DescribeSnapshotsOutput{
			Snapshots: []ec2types.Snapshot{
				{
					SnapshotId: aws.String("snap-0123456789private"),
					VolumeId:   aws.String("vol-0123456789abcdef"),
				},
			},
		},
		describeSnapshotAttributeOutputs: map[string]*ec2.DescribeSnapshotAttributeOutput{
			"snap-0123456789private": {
				SnapshotId: aws.String("snap-0123456789private"),
				CreateVolumePermissions: []ec2types.CreateVolumePermission{
					{
						UserId: aws.String("123456789012"),
					},
				},
			},
		},
	}

	sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1 (EBS default) + 42 (2 instances x 21 checks) + 1 (AMI) + 1 (Snapshot) = 45 results
	if len(results) != 45 {
		t.Fatalf("expected 45 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != "PASS" {
			t.Errorf("expected check %s to PASS, got %s", r.RuleID, r.Status)
		}
		if r.Severity != "INFO" {
			t.Errorf("expected check %s to have INFO severity for PASS, got %s", r.RuleID, r.Severity)
		}
	}
}

func TestEC2Scanner_NonCompliant_AllFail(t *testing.T) {
	mockAPI := &mockEC2Api{
		getEbsEncryptionByDefaultOutput: &ec2.GetEbsEncryptionByDefaultOutput{
			EbsEncryptionByDefault: aws.Bool(false),
		},
		describeInstancesOutput: &ec2.DescribeInstancesOutput{
			Reservations: []ec2types.Reservation{
				{
					Instances: []ec2types.Instance{
						{
							InstanceId:         aws.String("i-insecure-optional"),
							IamInstanceProfile: nil,
							PublicIpAddress:    aws.String("54.210.1.1"),
							SecurityGroups: []ec2types.GroupIdentifier{
								{GroupId: aws.String("sg-open-all")},
							},
							EnclaveOptions: &ec2types.EnclaveOptions{
								Enabled: aws.Bool(true),
							},
							MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
								HttpTokens:   ec2types.HttpTokensStateOptional,
								HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
							},
						},
						{
							InstanceId:         aws.String("i-insecure-nil"),
							IamInstanceProfile: nil,
							PublicIpAddress:    aws.String("54.210.1.2"),
							SecurityGroups: []ec2types.GroupIdentifier{
								{GroupId: aws.String("sg-open-all")},
							},
							EnclaveOptions: &ec2types.EnclaveOptions{
								Enabled: aws.Bool(true),
							},
							MetadataOptions: nil,
						},
					},
				},
			},
		},
		describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
			SecurityGroups: []ec2types.SecurityGroup{
				{
					GroupId: aws.String("sg-open-all"),
					IpPermissions: []ec2types.IpPermission{
						{
							IpProtocol: aws.String("-1"),
							IpRanges: []ec2types.IpRange{
								{CidrIp: aws.String("0.0.0.0/0")},
							},
						},
					},
				},
			},
		},
		describeImagesOutput: &ec2.DescribeImagesOutput{
			Images: []ec2types.Image{
				{
					ImageId: aws.String("ami-public-exposed"),
					Name:    aws.String("leaked-prod-ami"),
					Public:  aws.Bool(true),
				},
			},
		},
		describeSnapshotsOutput: &ec2.DescribeSnapshotsOutput{
			Snapshots: []ec2types.Snapshot{
				{
					SnapshotId: aws.String("snap-public-exposed"),
					VolumeId:   aws.String("vol-insecure"),
				},
			},
		},
		describeSnapshotAttributeOutputs: map[string]*ec2.DescribeSnapshotAttributeOutput{
			"snap-public-exposed": {
				SnapshotId: aws.String("snap-public-exposed"),
				CreateVolumePermissions: []ec2types.CreateVolumePermission{
					{
						Group: ec2types.PermissionGroupAll,
					},
				},
			},
		},
	}

	sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1 (EBS default) + 42 (2 instances x 21 checks) + 1 (AMI) + 1 (Snapshot) = 45 results
	if len(results) != 45 {
		t.Fatalf("expected 45 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != "FAIL" {
			t.Errorf("expected check %s to FAIL, got %s", r.RuleID, r.Status)
		}
		if r.RuleID == "ec2_instance_imdsv2_enabled" {
			if r.Severity != "HIGH" {
				t.Errorf("expected ec2_instance_imdsv2_enabled severity HIGH, got %s", r.Severity)
			}
			expectedRec := "Enforce IMDSv2 on EC2 instance by requiring HTTP tokens or disabling metadata service."
			metrics, ok := r.Metrics.(map[string]interface{})
			if !ok || metrics["Recommendation"] != expectedRec {
				t.Errorf("expected recommendation %q, got %v", expectedRec, r.Metrics)
			}
		}
		if r.RuleID == "ec2_confidential_workload_host_imdsv2_not_enforced" {
			if r.Severity != "HIGH" {
				t.Errorf("expected ec2_confidential_workload_host_imdsv2_not_enforced severity HIGH, got %s", r.Severity)
			}
			expectedRec := "Enforce IMDSv2 on confidential-workload (Nitro Enclave) hosts by setting HttpTokens to required."
			metrics, ok := r.Metrics.(map[string]interface{})
			if !ok || metrics["Recommendation"] != expectedRec {
				t.Errorf("expected recommendation %q, got %v", expectedRec, r.Metrics)
			}
		}
		if r.RuleID == "ec2_confidential_workload_host_unrestricted_ingress" {
			if r.Severity != "HIGH" {
				t.Errorf("expected ec2_confidential_workload_host_unrestricted_ingress severity HIGH, got %s", r.Severity)
			}
			expectedRec := "Restrict confidential-workload host ingress to standard ports (22, 80, 443) only."
			metrics, ok := r.Metrics.(map[string]interface{})
			if !ok || metrics["Recommendation"] != expectedRec {
				t.Errorf("expected recommendation %q, got %v", expectedRec, r.Metrics)
			}
		}
		if r.RuleID == "ec2_ami_public" {
			if r.Severity != "CRITICAL" {
				t.Errorf("expected ec2_ami_public severity CRITICAL, got %s", r.Severity)
			}
			if r.ResourceType != "SecaaS-EC2" {
				t.Errorf("expected ResourceType SecaaS-EC2, got %s", r.ResourceType)
			}
		}
		if r.RuleID == "ec2_ebs_public_snapshot" {
			if r.Severity != "CRITICAL" {
				t.Errorf("expected ec2_ebs_public_snapshot severity CRITICAL, got %s", r.Severity)
			}
			if r.ResourceType != "SecaaS-EBS" {
				t.Errorf("expected ResourceType SecaaS-EBS, got %s", r.ResourceType)
			}
		}
	}
}

func TestEC2Scanner_PublicExposureChecks(t *testing.T) {
	t.Run("public and private AMIs and Snapshots evaluated correctly", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			getEbsEncryptionByDefaultOutput: &ec2.GetEbsEncryptionByDefaultOutput{
				EbsEncryptionByDefault: aws.Bool(true),
			},
			describeImagesOutput: &ec2.DescribeImagesOutput{
				Images: []ec2types.Image{
					{
						ImageId: aws.String("ami-private"),
						Public:  aws.Bool(false),
					},
					{
						ImageId: aws.String("ami-public"),
						Public:  aws.Bool(true),
					},
				},
			},
			describeSnapshotsOutput: &ec2.DescribeSnapshotsOutput{
				Snapshots: []ec2types.Snapshot{
					{
						SnapshotId: aws.String("snap-private"),
					},
					{
						SnapshotId: aws.String("snap-public"),
					},
				},
			},
			describeSnapshotAttributeOutputs: map[string]*ec2.DescribeSnapshotAttributeOutput{
				"snap-private": {
					SnapshotId:              aws.String("snap-private"),
					CreateVolumePermissions: []ec2types.CreateVolumePermission{},
				},
				"snap-public": {
					SnapshotId: aws.String("snap-public"),
					CreateVolumePermissions: []ec2types.CreateVolumePermission{
						{
							Group: "all",
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-west-2")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		statusByResourceAndRule := make(map[string]string)
		sevByResourceAndRule := make(map[string]string)
		for _, r := range results {
			key := r.ResourceID + ":" + r.RuleID
			statusByResourceAndRule[key] = r.Status
			sevByResourceAndRule[key] = r.Severity
		}

		if statusByResourceAndRule["ami-private:ec2_ami_public"] != "PASS" {
			t.Errorf("expected ami-private to PASS, got %s", statusByResourceAndRule["ami-private:ec2_ami_public"])
		}
		if statusByResourceAndRule["ami-public:ec2_ami_public"] != "FAIL" {
			t.Errorf("expected ami-public to FAIL, got %s", statusByResourceAndRule["ami-public:ec2_ami_public"])
		}
		if sevByResourceAndRule["ami-public:ec2_ami_public"] != "CRITICAL" {
			t.Errorf("expected ami-public severity CRITICAL, got %s", sevByResourceAndRule["ami-public:ec2_ami_public"])
		}

		if statusByResourceAndRule["snap-private:ec2_ebs_public_snapshot"] != "PASS" {
			t.Errorf("expected snap-private to PASS, got %s", statusByResourceAndRule["snap-private:ec2_ebs_public_snapshot"])
		}
		if statusByResourceAndRule["snap-public:ec2_ebs_public_snapshot"] != "FAIL" {
			t.Errorf("expected snap-public to FAIL, got %s", statusByResourceAndRule["snap-public:ec2_ebs_public_snapshot"])
		}
		if sevByResourceAndRule["snap-public:ec2_ebs_public_snapshot"] != "CRITICAL" {
			t.Errorf("expected snap-public severity CRITICAL, got %s", sevByResourceAndRule["snap-public:ec2_ebs_public_snapshot"])
		}
	})

	t.Run("API errors propagated", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeImagesErr: errors.New("DescribeImages failed"),
		}
		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-west-2")
		_, err := sc.Scan(context.Background())
		if err == nil {
			t.Fatal("expected DescribeImages error, got nil")
		}

		mockAPISnap := &mockEC2Api{
			describeSnapshotsErr: errors.New("DescribeSnapshots failed"),
		}
		scSnap := secaas.NewEC2ScannerWithClient(mockAPISnap, "us-west-2")
		_, err = scSnap.Scan(context.Background())
		if err == nil {
			t.Fatal("expected DescribeSnapshots error, got nil")
		}
	})
}

func TestEC2Scanner_17OpenPortChecks(t *testing.T) {
	all17RuleIDs := []string{
		"ec2_instance_port_ssh_exposed_to_internet",
		"ec2_instance_port_rdp_exposed_to_internet",
		"ec2_instance_port_mysql_exposed_to_internet",
		"ec2_instance_port_postgresql_exposed_to_internet",
		"ec2_instance_port_mongodb_exposed_to_internet",
		"ec2_instance_port_redis_exposed_to_internet",
		"ec2_instance_port_elasticsearch_kibana_exposed_to_internet",
		"ec2_instance_port_sqlserver_exposed_to_internet",
		"ec2_instance_port_oracle_exposed_to_internet",
		"ec2_instance_port_cassandra_exposed_to_internet",
		"ec2_instance_port_kafka_exposed_to_internet",
		"ec2_instance_port_memcached_exposed_to_internet",
		"ec2_instance_port_ldap_exposed_to_internet",
		"ec2_instance_port_kerberos_exposed_to_internet",
		"ec2_instance_port_ftp_exposed_to_internet",
		"ec2_instance_port_telnet_exposed_to_internet",
		"ec2_instance_port_cifs_exposed_to_internet",
	}

	t.Run("compliant - private instance with open SG passes all 17 checks", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-private-open-sg"),
								PublicIpAddress: nil, // private instance
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-wide-open")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-wide-open"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("-1"),
								IpRanges: []ec2types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resultByRule := make(map[string]string)
		for _, r := range results {
			if r.ResourceID == "i-private-open-sg" {
				resultByRule[r.RuleID] = r.Status
			}
		}

		for _, ruleID := range all17RuleIDs {
			status, ok := resultByRule[ruleID]
			if !ok {
				t.Errorf("missing check %s in results", ruleID)
			} else if status != "PASS" {
				t.Errorf("expected %s to PASS for private instance, got %s", ruleID, status)
			}
		}
	})

	t.Run("compliant - public instance with restrictive SG passes all 17 checks", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-public-restrictive-sg"),
								PublicIpAddress: aws.String("52.1.2.3"),
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-web-only")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-web-only"),
						IpPermissions: []ec2types.IpPermission{
							// Port 80 open to public
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(80),
								ToPort:     aws.Int32(80),
								IpRanges: []ec2types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
							// Port 443 open to public
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(443),
								ToPort:     aws.Int32(443),
								IpRanges: []ec2types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
							// SSH open only internally
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(22),
								ToPort:     aws.Int32(22),
								IpRanges: []ec2types.IpRange{
									{CidrIp: aws.String("10.0.0.0/8")},
								},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		resultByRule := make(map[string]string)
		for _, r := range results {
			if r.ResourceID == "i-public-restrictive-sg" {
				resultByRule[r.RuleID] = r.Status
			}
		}

		for _, ruleID := range all17RuleIDs {
			status, ok := resultByRule[ruleID]
			if !ok {
				t.Errorf("missing check %s in results", ruleID)
			} else if status != "PASS" {
				t.Errorf("expected %s to PASS for restrictive SG, got %s", ruleID, status)
			}
		}
	})

	t.Run("non-compliant - public instance with specific open ports fails affected checks only", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-public-specific-open"),
								PublicIpAddress: aws.String("54.1.2.3"),
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-specific")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-specific"),
						IpPermissions: []ec2types.IpPermission{
							// SSH (22) open to 0.0.0.0/0
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(22),
								ToPort:     aws.Int32(22),
								IpRanges: []ec2types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
							// PostgreSQL (5432) open to 0.0.0.0/0
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(5432),
								ToPort:     aws.Int32(5432),
								IpRanges: []ec2types.IpRange{
									{CidrIp: aws.String("0.0.0.0/0")},
								},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		statusByRule := make(map[string]string)
		sevByRule := make(map[string]string)
		for _, r := range results {
			if r.ResourceID == "i-public-specific-open" {
				statusByRule[r.RuleID] = r.Status
				sevByRule[r.RuleID] = r.Severity
			}
		}

		// SSH and PostgreSQL should FAIL with CRITICAL
		if statusByRule["ec2_instance_port_ssh_exposed_to_internet"] != "FAIL" || sevByRule["ec2_instance_port_ssh_exposed_to_internet"] != "CRITICAL" {
			t.Errorf("expected SSH to FAIL (CRITICAL), got %s (%s)", statusByRule["ec2_instance_port_ssh_exposed_to_internet"], sevByRule["ec2_instance_port_ssh_exposed_to_internet"])
		}
		if statusByRule["ec2_instance_port_postgresql_exposed_to_internet"] != "FAIL" || sevByRule["ec2_instance_port_postgresql_exposed_to_internet"] != "CRITICAL" {
			t.Errorf("expected PostgreSQL to FAIL (CRITICAL), got %s (%s)", statusByRule["ec2_instance_port_postgresql_exposed_to_internet"], sevByRule["ec2_instance_port_postgresql_exposed_to_internet"])
		}

		// The other 15 checks should PASS with INFO
		for _, ruleID := range all17RuleIDs {
			if ruleID == "ec2_instance_port_ssh_exposed_to_internet" || ruleID == "ec2_instance_port_postgresql_exposed_to_internet" {
				continue
			}
			if statusByRule[ruleID] != "PASS" || sevByRule[ruleID] != "INFO" {
				t.Errorf("expected %s to PASS (INFO), got %s (%s)", ruleID, statusByRule[ruleID], sevByRule[ruleID])
			}
		}
	})

	t.Run("non-compliant - public via ENI Association with IPv6 open rule", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-public-via-eni"),
								PublicIpAddress: nil,
								NetworkInterfaces: []ec2types.InstanceNetworkInterface{
									{
										Association: &ec2types.InstanceNetworkInterfaceAssociation{
											PublicIp: aws.String("54.2.3.4"),
										},
										Groups: []ec2types.GroupIdentifier{
											{GroupId: aws.String("sg-rdp-ipv6")},
										},
									},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-rdp-ipv6"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(3389),
								ToPort:     aws.Int32(3389),
								Ipv6Ranges: []ec2types.Ipv6Range{
									{CidrIpv6: aws.String("::/0")},
								},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		statusByRule := make(map[string]string)
		sevByRule := make(map[string]string)
		for _, r := range results {
			if r.ResourceID == "i-public-via-eni" {
				statusByRule[r.RuleID] = r.Status
				sevByRule[r.RuleID] = r.Severity
			}
		}

		if statusByRule["ec2_instance_port_rdp_exposed_to_internet"] != "FAIL" || sevByRule["ec2_instance_port_rdp_exposed_to_internet"] != "CRITICAL" {
			t.Errorf("expected RDP to FAIL (CRITICAL) via ENI IPv6 rule, got %s (%s)", statusByRule["ec2_instance_port_rdp_exposed_to_internet"], sevByRule["ec2_instance_port_rdp_exposed_to_internet"])
		}
	})

	t.Run("non-compliant - every canonical port check triggers when exposed", func(t *testing.T) {
		openPermissions := []ec2types.IpPermission{
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(22), ToPort: aws.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},       // SSH
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(3389), ToPort: aws.Int32(3389), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // RDP
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(3306), ToPort: aws.Int32(3306), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // MySQL
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(5432), ToPort: aws.Int32(5432), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // PostgreSQL
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(27018), ToPort: aws.Int32(27018), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}, // MongoDB (secondary port 27018)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(6379), ToPort: aws.Int32(6379), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // Redis
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(5601), ToPort: aws.Int32(5601), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // Kibana (5601)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(1434), ToPort: aws.Int32(1434), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // SQL Server (1434)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(2483), ToPort: aws.Int32(2483), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // Oracle (2483)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(9160), ToPort: aws.Int32(9160), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // Cassandra (9160)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(9092), ToPort: aws.Int32(9092), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},   // Kafka (9092)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(11211), ToPort: aws.Int32(11211), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}}, // Memcached (11211)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(636), ToPort: aws.Int32(636), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},     // LDAPS (636)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(88), ToPort: aws.Int32(88), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},       // Kerberos (88)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(21), ToPort: aws.Int32(21), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},       // FTP (21)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(23), ToPort: aws.Int32(23), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},       // Telnet (23)
			{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(445), ToPort: aws.Int32(445), IpRanges: []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}}},     // CIFS (445)
		}

		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-all-17-exposed"),
								PublicIpAddress: aws.String("1.2.3.4"),
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-all-17")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId:       aws.String("sg-all-17"),
						IpPermissions: openPermissions,
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		statusByRule := make(map[string]string)
		sevByRule := make(map[string]string)
		resTypeByRule := make(map[string]string)
		for _, r := range results {
			if r.ResourceID == "i-all-17-exposed" {
				statusByRule[r.RuleID] = r.Status
				sevByRule[r.RuleID] = r.Severity
				resTypeByRule[r.RuleID] = r.ResourceType
			}
		}

		for _, ruleID := range all17RuleIDs {
			if statusByRule[ruleID] != "FAIL" {
				t.Errorf("expected %s to FAIL, got %s", ruleID, statusByRule[ruleID])
			}
			if sevByRule[ruleID] != "CRITICAL" {
				t.Errorf("expected %s severity to be CRITICAL, got %s", ruleID, sevByRule[ruleID])
			}
			if resTypeByRule[ruleID] != "SecaaS-EC2" {
				t.Errorf("expected %s ResourceType to be SecaaS-EC2, got %s", ruleID, resTypeByRule[ruleID])
			}
		}
	})

	t.Run("DescribeSecurityGroups API error propagated", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeSecurityGroupsErr: errors.New("DescribeSecurityGroups failed"),
		}
		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-west-2")
		_, err := sc.Scan(context.Background())
		if err == nil {
			t.Fatal("expected DescribeSecurityGroups error, got nil")
		}
	})
}

func TestEC2Scanner_ConfidentialWorkloadHostChecks(t *testing.T) {
	t.Run("non-enclave instance passes both checks", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-non-enclave-nil"),
								PublicIpAddress: aws.String("54.1.1.1"),
								EnclaveOptions:  nil,
								MetadataOptions: nil,
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-open-all")},
								},
							},
							{
								InstanceId:      aws.String("i-non-enclave-disabled"),
								PublicIpAddress: aws.String("54.1.1.2"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(false),
								},
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens: ec2types.HttpTokensStateOptional,
								},
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-open-all")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-open-all"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("-1"),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedExt := "Instance is not configured as a confidential-workload host (Nitro Enclaves disabled)."
		testedInstances := map[string]bool{"i-non-enclave-nil": true, "i-non-enclave-disabled": true}
		ruleFound := make(map[string]int)

		for _, r := range results {
			if !testedInstances[r.ResourceID] {
				continue
			}
			if r.RuleID == "ec2_confidential_workload_host_imdsv2_not_enforced" || r.RuleID == "ec2_confidential_workload_host_unrestricted_ingress" {
				ruleFound[r.ResourceID+":"+r.RuleID]++
				if r.Status != "PASS" {
					t.Errorf("instance %s expected %s to PASS, got %s", r.ResourceID, r.RuleID, r.Status)
				}
				if r.Severity != "INFO" {
					t.Errorf("instance %s expected %s severity INFO, got %s", r.ResourceID, r.RuleID, r.Severity)
				}
				metrics, ok := r.Metrics.(map[string]interface{})
				if !ok || metrics["StatusExtended"] != expectedExt {
					t.Errorf("instance %s expected StatusExtended %q, got %v", r.ResourceID, expectedExt, r.Metrics)
				}
			}
		}

		if len(ruleFound) != 4 {
			t.Fatalf("expected 4 confidential workload host check results, got %d", len(ruleFound))
		}
	})

	t.Run("enclave instance with IMDSv2 optional or missing fails imdsv2 check", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId: aws.String("i-enclave-optional"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens:   ec2types.HttpTokensStateOptional,
									HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
								},
							},
							{
								InstanceId: aws.String("i-enclave-missing-metadata"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								MetadataOptions: nil,
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedRec := "Enforce IMDSv2 on confidential-workload (Nitro Enclave) hosts by setting HttpTokens to required."
		testedInstances := map[string]bool{"i-enclave-optional": true, "i-enclave-missing-metadata": true}

		for _, r := range results {
			if testedInstances[r.ResourceID] && r.RuleID == "ec2_confidential_workload_host_imdsv2_not_enforced" {
				if r.Status != "FAIL" {
					t.Errorf("instance %s expected IMDSv2 check to FAIL, got %s", r.ResourceID, r.Status)
				}
				if r.Severity != "HIGH" {
					t.Errorf("instance %s expected IMDSv2 check severity HIGH, got %s", r.ResourceID, r.Severity)
				}
				metrics, ok := r.Metrics.(map[string]interface{})
				if !ok || metrics["Recommendation"] != expectedRec {
					t.Errorf("instance %s expected recommendation %q, got %v", r.ResourceID, expectedRec, r.Metrics)
				}
			}
		}
	})

	t.Run("enclave instance with IMDSv2 required passes imdsv2 check", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId: aws.String("i-enclave-required"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
									HttpTokens:   ec2types.HttpTokensStateRequired,
									HttpEndpoint: ec2types.InstanceMetadataEndpointStateEnabled,
								},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedExt := "Confidential-workload host enforces IMDSv2."
		found := false
		for _, r := range results {
			if r.ResourceID == "i-enclave-required" && r.RuleID == "ec2_confidential_workload_host_imdsv2_not_enforced" {
				found = true
				if r.Status != "PASS" {
					t.Errorf("expected IMDSv2 check to PASS, got %s", r.Status)
				}
				if r.Severity != "INFO" {
					t.Errorf("expected IMDSv2 check severity INFO, got %s", r.Severity)
				}
				metrics, ok := r.Metrics.(map[string]interface{})
				if !ok || metrics["StatusExtended"] != expectedExt {
					t.Errorf("expected StatusExtended %q, got %v", expectedExt, r.Metrics)
				}
			}
		}
		if !found {
			t.Fatal("expected ec2_confidential_workload_host_imdsv2_not_enforced result for i-enclave-required")
		}
	})

	t.Run("public enclave instance with security group open to port 8080 or port -1 fails unrestricted ingress check", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-enclave-port-8080"),
								PublicIpAddress: aws.String("54.10.20.30"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-port-8080")},
								},
							},
							{
								InstanceId:      aws.String("i-enclave-port-all"),
								PublicIpAddress: aws.String("54.10.20.31"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-port-all")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-port-8080"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(8080),
								ToPort:     aws.Int32(8080),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
						},
					},
					{
						GroupId: aws.String("sg-port-all"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("-1"),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedRec := "Restrict confidential-workload host ingress to standard ports (22, 80, 443) only."
		testedInstances := map[string]bool{"i-enclave-port-8080": true, "i-enclave-port-all": true}

		for _, r := range results {
			if testedInstances[r.ResourceID] && r.RuleID == "ec2_confidential_workload_host_unrestricted_ingress" {
				if r.Status != "FAIL" {
					t.Errorf("instance %s expected ingress check to FAIL, got %s", r.ResourceID, r.Status)
				}
				if r.Severity != "HIGH" {
					t.Errorf("instance %s expected ingress check severity HIGH, got %s", r.ResourceID, r.Severity)
				}
				metrics, ok := r.Metrics.(map[string]interface{})
				if !ok || metrics["Recommendation"] != expectedRec {
					t.Errorf("instance %s expected recommendation %q, got %v", r.ResourceID, expectedRec, r.Metrics)
				}
			}
		}
	})

	t.Run("public enclave instance with security group open only to port 443 passes unrestricted ingress check", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-enclave-port-443-only"),
								PublicIpAddress: aws.String("54.10.20.40"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-port-443")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-port-443"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(443),
								ToPort:     aws.Int32(443),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, r := range results {
			if r.ResourceID == "i-enclave-port-443-only" && r.RuleID == "ec2_confidential_workload_host_unrestricted_ingress" {
				found = true
				if r.Status != "PASS" {
					t.Errorf("expected ingress check to PASS, got %s", r.Status)
				}
				if r.Severity != "INFO" {
					t.Errorf("expected ingress check severity INFO, got %s", r.Severity)
				}
			}
		}
		if !found {
			t.Fatal("expected ec2_confidential_workload_host_unrestricted_ingress result for i-enclave-port-443-only")
		}
	})

	t.Run("public enclave instance with standard ports 22, 80, 443 and IPv6 passes unrestricted ingress check", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-enclave-standard-ports"),
								PublicIpAddress: aws.String("54.10.20.50"),
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-standard-ports")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-standard-ports"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(22),
								ToPort:     aws.Int32(22),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(80),
								ToPort:     aws.Int32(80),
								Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: aws.String("::/0")}},
							},
							{
								IpProtocol: aws.String("tcp"),
								FromPort:   aws.Int32(443),
								ToPort:     aws.Int32(443),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, r := range results {
			if r.ResourceID == "i-enclave-standard-ports" && r.RuleID == "ec2_confidential_workload_host_unrestricted_ingress" {
				found = true
				if r.Status != "PASS" {
					t.Errorf("expected ingress check to PASS, got %s", r.Status)
				}
				if r.Severity != "INFO" {
					t.Errorf("expected ingress check severity INFO, got %s", r.Severity)
				}
			}
		}
		if !found {
			t.Fatal("expected ec2_confidential_workload_host_unrestricted_ingress result for i-enclave-standard-ports")
		}
	})

	t.Run("private enclave instance with open security group passes unrestricted ingress check", func(t *testing.T) {
		mockAPI := &mockEC2Api{
			describeInstancesOutput: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{
					{
						Instances: []ec2types.Instance{
							{
								InstanceId:      aws.String("i-enclave-private-open-sg"),
								PublicIpAddress: nil,
								EnclaveOptions: &ec2types.EnclaveOptions{
									Enabled: aws.Bool(true),
								},
								SecurityGroups: []ec2types.GroupIdentifier{
									{GroupId: aws.String("sg-wide-open")},
								},
							},
						},
					},
				},
			},
			describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []ec2types.SecurityGroup{
					{
						GroupId: aws.String("sg-wide-open"),
						IpPermissions: []ec2types.IpPermission{
							{
								IpProtocol: aws.String("-1"),
								IpRanges:   []ec2types.IpRange{{CidrIp: aws.String("0.0.0.0/0")}},
							},
						},
					},
				},
			},
		}

		sc := secaas.NewEC2ScannerWithClient(mockAPI, "us-east-1")
		results, err := sc.Scan(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, r := range results {
			if r.ResourceID == "i-enclave-private-open-sg" && r.RuleID == "ec2_confidential_workload_host_unrestricted_ingress" {
				found = true
				if r.Status != "PASS" {
					t.Errorf("expected private instance to PASS ingress check, got %s", r.Status)
				}
				if r.Severity != "INFO" {
					t.Errorf("expected private instance severity INFO, got %s", r.Severity)
				}
			}
		}
		if !found {
			t.Fatal("expected ec2_confidential_workload_host_unrestricted_ingress result for i-enclave-private-open-sg")
		}
	})
}
