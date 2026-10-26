package secaas

import (
	"context"
	"fmt"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2Api defines the interface for EC2 instance, EBS encryption, AMI, and snapshot operations.
type EC2Api interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	GetEbsEncryptionByDefault(ctx context.Context, params *ec2.GetEbsEncryptionByDefaultInput, optFns ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
	DescribeImages(ctx context.Context, params *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeSnapshots(ctx context.Context, params *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeSnapshotAttribute(ctx context.Context, params *ec2.DescribeSnapshotAttributeInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotAttributeOutput, error)
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

// EC2Scanner audits EC2 instance posture and EBS encryption configurations.
type EC2Scanner struct {
	client EC2Api
	region string
}

func NewEC2Scanner(cfg aws.Config) *EC2Scanner {
	return &EC2Scanner{
		client: ec2.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

func NewEC2ScannerWithClient(client EC2Api, region string) *EC2Scanner {
	return &EC2Scanner{
		client: client,
		region: region,
	}
}

func (s *EC2Scanner) Name() string {
	return "EC2-SecaaS-Scanner"
}

func (s *EC2Scanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	// 1. Check account-level default EBS encryption (CIS 2.2.1)
	ebsEncOut, err := s.client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	isEbsEncrypted := err == nil && ebsEncOut != nil && aws.ToBool(ebsEncOut.EbsEncryptionByDefault)
	ebsStatus := "PASS"
	ebsSev := "INFO"
	ebsExt := fmt.Sprintf("EBS default volume encryption is enabled in region %s.", region)
	if !isEbsEncrypted {
		ebsStatus = "FAIL"
		ebsSev = "HIGH"
		ebsExt = fmt.Sprintf("EBS default volume encryption is disabled in region %s.", region)
	}

	resIDEbs := fmt.Sprintf("ebs-encryption-by-default-%s", region)
	results = append(results, scanner.ScanResult{
		ResourceID:   resIDEbs,
		ResourceType: "SecaaS-EBS",
		Region:       region,
		Status:       ebsStatus,
		RuleID:       "ec2_ebs_volume_encryption",
		Severity:     ebsSev,
		Metrics: map[string]interface{}{
			"Region":         region,
			"StatusExtended": ebsExt,
			"Recommendation": "Enable EBS encryption by default in all active regions.",
		},
		Nodes: []graph.Node{
			{
				ID:       resIDEbs,
				NodeType: "SecaaS-EBS",
			},
		},
	})

	// 2. Fetch all security groups in the region via DescribeSecurityGroups and index them by GroupId
	sgMap := make(map[string]ec2types.SecurityGroup)
	sgPaginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})
	for sgPaginator.HasMorePages() {
		sgPage, err := sgPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, sg := range sgPage.SecurityGroups {
			if sg.GroupId != nil {
				sgMap[*sg.GroupId] = sg
			}
		}
	}

	// 3. Scan EC2 Instances for IAM Instance Profile, IMDSv2, and Port Exposure checks
	paginator := ec2.NewDescribeInstancesPaginator(s.client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, resv := range page.Reservations {
			for _, inst := range resv.Instances {
				if limit > 0 && processedCount >= limit {
					break
				}
				processedCount++

				instID := aws.ToString(inst.InstanceId)
				profileArn := ""
				if inst.IamInstanceProfile != nil {
					profileArn = aws.ToString(inst.IamInstanceProfile.Arn)
				}
				hasProfile := profileArn != ""

				pStatus := "PASS"
				pSev := "INFO"
				pExt := fmt.Sprintf("EC2 instance %s has IAM instance profile attached (%s).", instID, profileArn)
				if !hasProfile {
					pStatus = "FAIL"
					pSev = "HIGH"
					pExt = fmt.Sprintf("EC2 instance %s does not have an IAM instance profile attached.", instID)
				}

				results = append(results, scanner.ScanResult{
					ResourceID:   instID,
					ResourceType: "SecaaS-EC2",
					Region:       region,
					Status:       pStatus,
					RuleID:       "ec2_instance_profile_attached",
					Severity:     pSev,
					Metrics: map[string]interface{}{
						"InstanceId":     instID,
						"InstanceType":   string(inst.InstanceType),
						"StatusExtended": pExt,
						"Recommendation": "Attach an IAM role via an instance profile to EC2 instances to avoid embedding hardcoded credentials.",
					},
					Nodes: []graph.Node{
						{
							ID:       instID,
							NodeType: "SecaaS-EC2",
						},
					},
				})

				// Check IMDSv2 (CIS 5.6)
				imdsStatus := "FAIL"
				imdsSev := "HIGH"
				imdsExt := fmt.Sprintf("EC2 instance %s does not enforce IMDSv2.", instID)

				if inst.MetadataOptions != nil && inst.MetadataOptions.HttpEndpoint == ec2types.InstanceMetadataEndpointStateDisabled {
					imdsStatus = "PASS"
					imdsSev = "INFO"
					imdsExt = fmt.Sprintf("EC2 instance %s has metadata service disabled.", instID)
				} else if inst.MetadataOptions != nil && inst.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired {
					imdsStatus = "PASS"
					imdsSev = "INFO"
					imdsExt = fmt.Sprintf("EC2 instance %s has IMDSv2 enabled (HTTP tokens required).", instID)
				}

				imdsMetrics := map[string]interface{}{
					"InstanceId":     instID,
					"InstanceType":   string(inst.InstanceType),
					"StatusExtended": imdsExt,
				}
				if imdsStatus == "FAIL" {
					imdsMetrics["Recommendation"] = "Enforce IMDSv2 on EC2 instance by requiring HTTP tokens or disabling metadata service."
				}

				results = append(results, scanner.ScanResult{
					ResourceID:   instID,
					ResourceType: "SecaaS-EC2",
					Region:       region,
					Status:       imdsStatus,
					RuleID:       "ec2_instance_imdsv2_enabled",
					Severity:     imdsSev,
					Metrics:      imdsMetrics,
					Nodes: []graph.Node{
						{
							ID:       instID,
							NodeType: "SecaaS-EC2",
						},
					},
				})

				// Check 17 canonical port exposure checks
				isPublic := isEC2InstancePublic(inst)

				var attachedSGs []ec2types.SecurityGroup
				seenSG := make(map[string]bool)
				for _, sgRef := range inst.SecurityGroups {
					if sgRef.GroupId != nil {
						sgID := *sgRef.GroupId
						if !seenSG[sgID] {
							seenSG[sgID] = true
							if sg, ok := sgMap[sgID]; ok {
								attachedSGs = append(attachedSGs, sg)
							}
						}
					}
				}
				for _, ni := range inst.NetworkInterfaces {
					for _, sgRef := range ni.Groups {
						if sgRef.GroupId != nil {
							sgID := *sgRef.GroupId
							if !seenSG[sgID] {
								seenSG[sgID] = true
								if sg, ok := sgMap[sgID]; ok {
									attachedSGs = append(attachedSGs, sg)
								}
							}
						}
					}
				}

				for _, pc := range canonicalEC2PortChecks {
					allowsPublic := false
					if isPublic {
						for _, sg := range attachedSGs {
							if securityGroupAllowsPortCheck(sg, pc.ports) {
								allowsPublic = true
								break
							}
						}
					}

					portStatus := "PASS"
					portSev := "INFO"
					portExt := fmt.Sprintf("EC2 instance %s is not exposed to the Internet on %s port(s).", instID, pc.name)
					portRec := ""
					if isPublic && allowsPublic {
						portStatus = "FAIL"
						portSev = "CRITICAL"
						portExt = fmt.Sprintf("EC2 instance %s is public and exposes %s port(s) to the Internet.", instID, pc.name)
						portRec = fmt.Sprintf("Restrict ingress traffic from 0.0.0.0/0 or ::/0 to %s port(s) in attached security groups.", pc.name)
					}

					portMetrics := map[string]interface{}{
						"InstanceId":     instID,
						"InstanceType":   string(inst.InstanceType),
						"StatusExtended": portExt,
					}
					if portRec != "" {
						portMetrics["Recommendation"] = portRec
					}

					results = append(results, scanner.ScanResult{
						ResourceID:   instID,
						ResourceType: "SecaaS-EC2",
						Region:       region,
						Status:       portStatus,
						RuleID:       pc.ruleID,
						Severity:     portSev,
						Metrics:      portMetrics,
						Nodes: []graph.Node{
							{
								ID:       instID,
								NodeType: "SecaaS-EC2",
							},
						},
					})
				}

				// Check Confidential Workload Host IMDSv2 Enforcement (CIS 5.6)
				isNitroEnclave := inst.EnclaveOptions != nil && aws.ToBool(inst.EnclaveOptions.Enabled)
				confImdsStatus := "PASS"
				confImdsSev := "INFO"
				confImdsExt := "Instance is not configured as a confidential-workload host (Nitro Enclaves disabled)."
				confImdsRec := ""

				if isNitroEnclave {
					if inst.MetadataOptions == nil || inst.MetadataOptions.HttpTokens != ec2types.HttpTokensStateRequired {
						confImdsStatus = "FAIL"
						confImdsSev = "HIGH"
						confImdsExt = fmt.Sprintf("Confidential-workload host %s does not enforce IMDSv2.", instID)
						confImdsRec = "Enforce IMDSv2 on confidential-workload (Nitro Enclave) hosts by setting HttpTokens to required."
					} else {
						confImdsStatus = "PASS"
						confImdsSev = "INFO"
						confImdsExt = "Confidential-workload host enforces IMDSv2."
					}
				}

				confImdsMetrics := map[string]interface{}{
					"InstanceId":     instID,
					"InstanceType":   string(inst.InstanceType),
					"StatusExtended": confImdsExt,
				}
				if confImdsRec != "" {
					confImdsMetrics["Recommendation"] = confImdsRec
				}

				results = append(results, scanner.ScanResult{
					ResourceID:   instID,
					ResourceType: "SecaaS-EC2",
					Region:       region,
					Status:       confImdsStatus,
					RuleID:       "ec2_confidential_workload_host_imdsv2_not_enforced",
					Severity:     confImdsSev,
					Metrics:      confImdsMetrics,
					Nodes: []graph.Node{
						{
							ID:       instID,
							NodeType: "SecaaS-EC2",
						},
					},
				})

				// Check Confidential Workload Host Unrestricted Ingress (CIS 5.2 & 5.3)
				confIngressStatus := "PASS"
				confIngressSev := "INFO"
				confIngressExt := "Instance is not configured as a confidential-workload host (Nitro Enclaves disabled)."
				confIngressRec := ""

				if isNitroEnclave {
					if isPublic {
						hasNonStandardIngress := false
						for _, sg := range attachedSGs {
							if securityGroupAllowsNonStandardPublicIngress(sg) {
								hasNonStandardIngress = true
								break
							}
						}

						if hasNonStandardIngress {
							confIngressStatus = "FAIL"
							confIngressSev = "HIGH"
							confIngressExt = fmt.Sprintf("Confidential-workload host %s is public and exposes non-standard ports to the Internet.", instID)
							confIngressRec = "Restrict confidential-workload host ingress to standard ports (22, 80, 443) only."
						} else {
							confIngressStatus = "PASS"
							confIngressSev = "INFO"
							confIngressExt = fmt.Sprintf("Confidential-workload host %s ingress is restricted to standard ports.", instID)
						}
					} else {
						confIngressStatus = "PASS"
						confIngressSev = "INFO"
						confIngressExt = fmt.Sprintf("Confidential-workload host %s is not public.", instID)
					}
				}

				confIngressMetrics := map[string]interface{}{
					"InstanceId":     instID,
					"InstanceType":   string(inst.InstanceType),
					"StatusExtended": confIngressExt,
				}
				if confIngressRec != "" {
					confIngressMetrics["Recommendation"] = confIngressRec
				}

				results = append(results, scanner.ScanResult{
					ResourceID:   instID,
					ResourceType: "SecaaS-EC2",
					Region:       region,
					Status:       confIngressStatus,
					RuleID:       "ec2_confidential_workload_host_unrestricted_ingress",
					Severity:     confIngressSev,
					Metrics:      confIngressMetrics,
					Nodes: []graph.Node{
						{
							ID:       instID,
							NodeType: "SecaaS-EC2",
						},
					},
				})
			}
		}
	}

	// 4. Scan owned AMIs for public exposure (ec2_ami_public)
	imgPaginator := ec2.NewDescribeImagesPaginator(s.client, &ec2.DescribeImagesInput{
		Owners: []string{"self"},
	})
	for imgPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		imgPage, err := imgPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, img := range imgPage.Images {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			imgID := aws.ToString(img.ImageId)
			isPublic := aws.ToBool(img.Public)

			status := "PASS"
			sev := "INFO"
			ext := fmt.Sprintf("EC2 AMI %s is not public.", imgID)
			rec := ""
			if isPublic {
				status = "FAIL"
				sev = "CRITICAL"
				ext = fmt.Sprintf("EC2 AMI %s is public.", imgID)
				rec = "Modify the AMI launch permissions to make it private and remove public access."
			}

			metrics := map[string]interface{}{
				"ImageId":        imgID,
				"IsPublic":       isPublic,
				"StatusExtended": ext,
			}
			if img.Name != nil {
				metrics["ImageName"] = aws.ToString(img.Name)
			}
			if rec != "" {
				metrics["Recommendation"] = rec
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   imgID,
				ResourceType: "SecaaS-EC2",
				Region:       region,
				Status:       status,
				RuleID:       "ec2_ami_public",
				Severity:     sev,
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       imgID,
						NodeType: "SecaaS-EC2",
					},
				},
			})
		}
	}

	// 5. Scan EBS snapshots for public exposure (ec2_ebs_public_snapshot)
	snapPaginator := ec2.NewDescribeSnapshotsPaginator(s.client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})
	for snapPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		snapPage, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, snap := range snapPage.Snapshots {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			snapID := aws.ToString(snap.SnapshotId)

			attrOut, err := s.client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
				SnapshotId: snap.SnapshotId,
				Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
			})
			if err != nil {
				return nil, err
			}

			isPublic := false
			if attrOut != nil {
				for _, perm := range attrOut.CreateVolumePermissions {
					if perm.Group == ec2types.PermissionGroupAll || string(perm.Group) == "all" {
						isPublic = true
						break
					}
				}
			}

			status := "PASS"
			sev := "INFO"
			ext := fmt.Sprintf("EBS snapshot %s is not public.", snapID)
			rec := ""
			if isPublic {
				status = "FAIL"
				sev = "CRITICAL"
				ext = fmt.Sprintf("EBS snapshot %s is public (createVolumePermission contains 'all').", snapID)
				rec = "Remove 'all' permission from createVolumePermission on the EBS snapshot to make it private."
			}

			metrics := map[string]interface{}{
				"SnapshotId":     snapID,
				"IsPublic":       isPublic,
				"StatusExtended": ext,
			}
			if snap.VolumeId != nil {
				metrics["VolumeId"] = aws.ToString(snap.VolumeId)
			}
			if rec != "" {
				metrics["Recommendation"] = rec
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   snapID,
				ResourceType: "SecaaS-EBS",
				Region:       region,
				Status:       status,
				RuleID:       "ec2_ebs_public_snapshot",
				Severity:     sev,
				Metrics:      metrics,
				Nodes: []graph.Node{
					{
						ID:       snapID,
						NodeType: "SecaaS-EBS",
					},
				},
			})
		}
	}

	return results, nil
}

type ec2PortCheckDef struct {
	ruleID string
	name   string
	ports  []int32
}

var canonicalEC2PortChecks = []ec2PortCheckDef{
	{
		ruleID: "ec2_instance_port_ssh_exposed_to_internet",
		name:   "SSH",
		ports:  []int32{22},
	},
	{
		ruleID: "ec2_instance_port_rdp_exposed_to_internet",
		name:   "RDP",
		ports:  []int32{3389},
	},
	{
		ruleID: "ec2_instance_port_mysql_exposed_to_internet",
		name:   "MySQL",
		ports:  []int32{3306},
	},
	{
		ruleID: "ec2_instance_port_postgresql_exposed_to_internet",
		name:   "PostgreSQL",
		ports:  []int32{5432},
	},
	{
		ruleID: "ec2_instance_port_mongodb_exposed_to_internet",
		name:   "MongoDB",
		ports:  []int32{27017, 27018},
	},
	{
		ruleID: "ec2_instance_port_redis_exposed_to_internet",
		name:   "Redis",
		ports:  []int32{6379},
	},
	{
		ruleID: "ec2_instance_port_elasticsearch_kibana_exposed_to_internet",
		name:   "Elasticsearch/Kibana",
		ports:  []int32{9200, 9300, 5601},
	},
	{
		ruleID: "ec2_instance_port_sqlserver_exposed_to_internet",
		name:   "SQL Server",
		ports:  []int32{1433, 1434},
	},
	{
		ruleID: "ec2_instance_port_oracle_exposed_to_internet",
		name:   "Oracle",
		ports:  []int32{1521, 2483, 2484},
	},
	{
		ruleID: "ec2_instance_port_cassandra_exposed_to_internet",
		name:   "Cassandra",
		ports:  []int32{9042, 9160},
	},
	{
		ruleID: "ec2_instance_port_kafka_exposed_to_internet",
		name:   "Kafka",
		ports:  []int32{9092},
	},
	{
		ruleID: "ec2_instance_port_memcached_exposed_to_internet",
		name:   "Memcached",
		ports:  []int32{11211},
	},
	{
		ruleID: "ec2_instance_port_ldap_exposed_to_internet",
		name:   "LDAP",
		ports:  []int32{389, 636},
	},
	{
		ruleID: "ec2_instance_port_kerberos_exposed_to_internet",
		name:   "Kerberos",
		ports:  []int32{88},
	},
	{
		ruleID: "ec2_instance_port_ftp_exposed_to_internet",
		name:   "FTP",
		ports:  []int32{20, 21},
	},
	{
		ruleID: "ec2_instance_port_telnet_exposed_to_internet",
		name:   "Telnet",
		ports:  []int32{23},
	},
	{
		ruleID: "ec2_instance_port_cifs_exposed_to_internet",
		name:   "CIFS",
		ports:  []int32{139, 445},
	},
}

func isEC2InstancePublic(inst ec2types.Instance) bool {
	if inst.PublicIpAddress != nil && *inst.PublicIpAddress != "" {
		return true
	}
	for _, ni := range inst.NetworkInterfaces {
		if ni.Association != nil && ni.Association.PublicIp != nil && *ni.Association.PublicIp != "" {
			return true
		}
	}
	return false
}

func ipPermissionHasPublicRange(ipPerm ec2types.IpPermission) bool {
	for _, r := range ipPerm.IpRanges {
		if aws.ToString(r.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, r := range ipPerm.Ipv6Ranges {
		if aws.ToString(r.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

func ipPermissionAllowsPort(ipPerm ec2types.IpPermission, port int32) bool {
	if !ipPermissionHasPublicRange(ipPerm) {
		return false
	}

	proto := strings.ToLower(aws.ToString(ipPerm.IpProtocol))
	if proto == "-1" {
		return true
	}

	if proto == "tcp" || proto == "all" {
		fromPort := int32(0)
		toPort := int32(65535)
		if ipPerm.FromPort != nil {
			fromPort = *ipPerm.FromPort
			toPort = fromPort
		}
		if ipPerm.ToPort != nil {
			toPort = *ipPerm.ToPort
		}
		if fromPort <= port && toPort >= port {
			return true
		}
	}

	return false
}

func securityGroupAllowsPortCheck(sg ec2types.SecurityGroup, ports []int32) bool {
	for _, ipPerm := range sg.IpPermissions {
		for _, port := range ports {
			if ipPermissionAllowsPort(ipPerm, port) {
				return true
			}
		}
	}
	return false
}

func ipPermissionAllowsNonStandardPublicIngress(ipPerm ec2types.IpPermission) bool {
	if !ipPermissionHasPublicRange(ipPerm) {
		return false
	}

	proto := strings.ToLower(aws.ToString(ipPerm.IpProtocol))
	if proto == "-1" || proto == "all" {
		return true
	}

	fromPort := int32(0)
	toPort := int32(65535)
	if ipPerm.FromPort != nil {
		fromPort = *ipPerm.FromPort
		toPort = fromPort
	}
	if ipPerm.ToPort != nil {
		toPort = *ipPerm.ToPort
	}

	if fromPort == toPort && (fromPort == 22 || fromPort == 80 || fromPort == 443) {
		return false
	}

	return true
}

func securityGroupAllowsNonStandardPublicIngress(sg ec2types.SecurityGroup) bool {
	for _, ipPerm := range sg.IpPermissions {
		if ipPermissionAllowsNonStandardPublicIngress(ipPerm) {
			return true
		}
	}
	return false
}
