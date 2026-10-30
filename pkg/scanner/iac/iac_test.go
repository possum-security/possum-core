package iac

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertMetricsHaveFileAndLine(t *testing.T, findings []model.ScanResult) {
	t.Helper()
	for _, f := range findings {
		metrics, ok := f.Metrics.(map[string]interface{})
		require.True(t, ok, "finding %s (%s) must have Metrics map", f.RuleID, f.ResourceID)
		fileVal, hasFile := metrics["File"].(string)
		require.True(t, hasFile && fileVal != "", "finding %s must have non-empty File metric", f.RuleID)
		lineVal, hasLine := metrics["Line"].(int)
		require.True(t, hasLine && lineVal > 0, "finding %s must have Line > 0 metric, got %v", f.RuleID, metrics["Line"])
		expectedLoc := fmt.Sprintf("%s:%d", fileVal, lineVal)
		assert.True(t, strings.Contains(f.Description, expectedLoc) || strings.Contains(f.ResourceID, expectedLoc),
			"finding %s should include %s in Description (%q) or ResourceID (%q)", f.RuleID, expectedLoc, f.Description, f.ResourceID)
	}
}

func TestIaC_ScanPlanJSON(t *testing.T) {
	planJSON := `{
  "format_version": "1.0",
  "terraform_version": "1.7.0",
  "resource_changes": [
    {
      "address": "aws_s3_bucket.bad_bucket",
      "type": "aws_s3_bucket",
      "name": "bad_bucket",
      "change": {
        "actions": ["create"],
        "after": {
          "bucket": "my-unprotected-data"
        }
      }
    },
    {
      "address": "aws_security_group.allow_ssh",
      "type": "aws_security_group",
      "name": "allow_ssh",
      "change": {
        "actions": ["create"],
        "after": {
          "ingress": [
            {
              "cidr_blocks": ["0.0.0.0/0"],
              "from_port": 22,
              "to_port": 22,
              "protocol": "tcp"
            }
          ]
        }
      }
    },
    {
      "address": "aws_ebs_volume.data_vol",
      "type": "aws_ebs_volume",
      "name": "data_vol",
      "change": {
        "actions": ["create"],
        "after": {
          "size": 100,
          "encrypted": false
        }
      }
    }
  ]
}`

	scanner := NewScanner()
	findings, err := scanner.ScanPlan(strings.NewReader(planJSON))
	require.NoError(t, err)

	require.Len(t, findings, 3)
	assertMetricsHaveFileAndLine(t, findings)

	ruleIDs := []string{findings[0].RuleID, findings[1].RuleID, findings[2].RuleID}
	assert.Contains(t, ruleIDs, "s3_bucket_level_public_access_block")
	assert.Contains(t, ruleIDs, "ec2_security_group_open_to_world")
	assert.Contains(t, ruleIDs, "ebs_volume_encryption_enabled")

	// Verify cost waste estimation on EBS volume
	for _, f := range findings {
		if f.RuleID == "ebs_volume_encryption_enabled" {
			assert.InDelta(t, 8.0, f.CostWasteMo, 0.01) // 100GB * $0.08
		}
	}
}

func TestIaC_ScanTFFile(t *testing.T) {
	tfContent := `
resource "aws_s3_bucket" "public_site" {
  bucket = "static-assets"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
	tmpDir := t.TempDir()
	tfPath := filepath.Join(tmpDir, "main.tf")
	err := os.WriteFile(tfPath, []byte(tfContent), 0644)
	require.NoError(t, err)

	scanner := NewScanner()
	findings, err := scanner.ScanTFFile(tfPath)
	require.NoError(t, err)

	assert.NotEmpty(t, findings)
	assertMetricsHaveFileAndLine(t, findings)

	var foundS3, foundSG bool
	for _, f := range findings {
		if f.RuleID == "s3_bucket_level_public_access_block" {
			foundS3 = true
		}
		if f.RuleID == "ec2_security_group_open_to_world" {
			foundSG = true
		}
	}
	assert.True(t, foundS3, "Expected s3 public access finding")
	assert.True(t, foundSG, "Expected open security group finding")
}

func TestIaC_Terraform_Port2200AndEgressNotFlagged(t *testing.T) {
	tfContent := `
resource "aws_security_group" "custom_app" {
  name = "custom-app-sg"

  # Port 2200 should NOT match port 22
  ingress {
    from_port   = 2200
    to_port     = 2200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress 0.0.0.0/0 on all ports is standard and must NOT be flagged as open inbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "outbound_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-12345"
}

resource "aws_security_group" "ipv6_rdp_open" {
  name = "ipv6-rdp-sg"

  ingress {
    from_port        = 3380
    to_port          = 3390
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
`
	tmpDir := t.TempDir()
	tfPath := filepath.Join(tmpDir, "sg.tf")
	err := os.WriteFile(tfPath, []byte(tfContent), 0644)
	require.NoError(t, err)

	scanner := NewScanner()
	findings, err := scanner.ScanTFFile(tfPath)
	require.NoError(t, err)

	require.Len(t, findings, 1, "Only ipv6_rdp_open should be flagged; port 2200 and egress 0.0.0.0/0 must not trigger")
	assert.Equal(t, "aws_security_group.ipv6_rdp_open", findings[0].ResourceID)
	assert.Equal(t, "ec2_security_group_open_to_world", findings[0].RuleID)
	assertMetricsHaveFileAndLine(t, findings)
}

func TestIaC_Terraform_PlannedValuesAndTFJSON(t *testing.T) {
	plannedValuesJSON := `{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_security_group.safe_sg",
          "type": "aws_security_group",
          "name": "safe_sg",
          "values": {
            "ingress": [
              {
                "from_port": 2200,
                "to_port": 2200,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
              }
            ],
            "egress": [
              {
                "from_port": 0,
                "to_port": 0,
                "protocol": "-1",
                "cidr_blocks": ["0.0.0.0/0"]
              }
            ]
          }
        },
        {
          "address": "aws_ebs_volume.unencrypted_planned",
          "type": "aws_ebs_volume",
          "name": "unencrypted_planned",
          "values": {
            "size": 50,
            "encrypted": false
          }
        }
      ]
    }
  }
}`
	tmpDir := t.TempDir()
	planPath := filepath.Join(tmpDir, "tfplan.json")
	require.NoError(t, os.WriteFile(planPath, []byte(plannedValuesJSON), 0644))

	scanner := NewScanner()
	findings, err := scanner.ScanPath(planPath)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "aws_ebs_volume.unencrypted_planned", findings[0].ResourceID)
	assert.Equal(t, "ebs_volume_encryption_enabled", findings[0].RuleID)
	assertMetricsHaveFileAndLine(t, findings)
}

func TestIaC_CloudFormation_YAMLAndJSON(t *testing.T) {
	cfnYAML := `AWSTemplateFormatVersion: "2010-09-09"
Description: Insecure CloudFormation stack
Resources:
  InsecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-raw-bucket"

  OpenSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Open SSH to world
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0

  PublicUnencryptedRDS:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: postgres
      PubliclyAccessible: true
      StorageEncrypted: false

  UnencryptedVolume:
    Type: AWS::EC2::Volume
    Properties:
      Size: 100
      Encrypted: false
      AvailabilityZone: us-east-1a

  WildcardAdminRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: WildcardAdmin
      Policies:
        - PolicyName: AllowEverything
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
`
	cfnJSON := `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "JsonInsecureBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "json-bucket"
      }
    },
    "JsonOpenSG": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "SecurityGroupIngress": [
          {
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "CidrIpv6": "::/0"
          }
        ]
      }
    },
    "JsonUnencryptedEBS": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Size": 40,
        "Encrypted": false
      }
    }
  }
}`

	tmpDir := t.TempDir()
	yamlPath := filepath.Join(tmpDir, "template.yaml")
	jsonPath := filepath.Join(tmpDir, "template.json")
	require.NoError(t, os.WriteFile(yamlPath, []byte(cfnYAML), 0644))
	require.NoError(t, os.WriteFile(jsonPath, []byte(cfnJSON), 0644))

	scanner := NewScanner()

	// 1. Test YAML CloudFormation template
	yamlFindings, err := scanner.ScanPath(yamlPath)
	require.NoError(t, err)
	assert.NotEmpty(t, yamlFindings)
	assertMetricsHaveFileAndLine(t, yamlFindings)

	yamlRules := make(map[string]bool)
	for _, f := range yamlFindings {
		yamlRules[f.RuleID] = true
	}
	assert.True(t, yamlRules["s3_bucket_level_public_access_block"], "Expected S3 public access block finding")
	assert.True(t, yamlRules["s3_bucket_default_encryption"], "Expected S3 encryption finding")
	assert.True(t, yamlRules["ec2_security_group_open_to_world"], "Expected SG open to world finding")
	assert.True(t, yamlRules["rds_instance_no_public_access"], "Expected RDS public access finding")
	assert.True(t, yamlRules["rds_instance_storage_encrypted"], "Expected RDS storage encryption finding")
	assert.True(t, yamlRules["ebs_volume_encryption_enabled"], "Expected EBS encryption finding")
	assert.True(t, yamlRules["iam_policy_wildcard_action_resource"], "Expected IAM wildcard policy finding")

	// 2. Test JSON CloudFormation template
	jsonFindings, err := scanner.ScanPath(jsonPath)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonFindings)
	assertMetricsHaveFileAndLine(t, jsonFindings)

	jsonRules := make(map[string]bool)
	for _, f := range jsonFindings {
		jsonRules[f.RuleID] = true
	}
	assert.True(t, jsonRules["s3_bucket_level_public_access_block"])
	assert.True(t, jsonRules["s3_bucket_default_encryption"])
	assert.True(t, jsonRules["ec2_security_group_open_to_world"])
	assert.True(t, jsonRules["ebs_volume_encryption_enabled"])
}

func TestIaC_Kubernetes_Manifests(t *testing.T) {
	k8sYAML := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-web
spec:
  replicas: 2
  template:
    metadata:
      labels:
        app: web
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app-container
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
---
apiVersion: v1
kind: Pod
metadata:
  name: compliant-pod
spec:
  hostNetwork: false
  hostPID: false
  containers:
    - name: worker
      image: busybox:1.36
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 1000
      resources:
        limits:
          cpu: "500m"
          memory: "256Mi"
`
	tmpDir := t.TempDir()
	k8sPath := filepath.Join(tmpDir, "k8s.yaml")
	require.NoError(t, os.WriteFile(k8sPath, []byte(k8sYAML), 0644))

	scanner := NewScanner()
	findings, err := scanner.ScanPath(k8sPath)
	require.NoError(t, err)
	require.Len(t, findings, 4, "Expected 4 findings on insecure-web and 0 on compliant-pod")
	assertMetricsHaveFileAndLine(t, findings)

	k8sRules := make(map[string]model.Severity)
	for _, f := range findings {
		k8sRules[f.RuleID] = f.Severity
	}
	assert.Equal(t, model.SeverityCritical, k8sRules["k8s_container_privileged"])
	assert.Equal(t, model.SeverityHigh, k8sRules["k8s_container_run_as_root"])
	assert.Equal(t, model.SeverityMedium, k8sRules["k8s_container_missing_resource_limits"])
	assert.Equal(t, model.SeverityHigh, k8sRules["k8s_pod_host_network_or_pid"])

	// Directory scan should also pick up all IaC files
	dirFindings, err := scanner.ScanPath(tmpDir)
	require.NoError(t, err)
	assert.Len(t, dirFindings, 4)
}
