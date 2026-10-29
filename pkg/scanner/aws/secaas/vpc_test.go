package secaas_test

import (
	"context"
	"testing"

	"github.com/possum-security/possum-core/pkg/scanner"
	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type mockVpcApi struct {
	describeSecurityGroupsOutput *ec2.DescribeSecurityGroupsOutput
	describeSecurityGroupsErr    error
	describeVpcEndpointsOutput   *ec2.DescribeVpcEndpointsOutput
	describeSubnetsOutput        *ec2.DescribeSubnetsOutput
	describeSubnetsErr           error
	describeNetworkAclsOutput    *ec2.DescribeNetworkAclsOutput
	describeNetworkAclsErr       error
	describeRouteTablesOutput    *ec2.DescribeRouteTablesOutput
	describeRouteTablesErr       error
}

func (m *mockVpcApi) DescribeRouteTables(ctx context.Context, params *ec2.DescribeRouteTablesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	if m.describeRouteTablesOutput == nil {
		return &ec2.DescribeRouteTablesOutput{}, m.describeRouteTablesErr
	}
	return m.describeRouteTablesOutput, m.describeRouteTablesErr
}

func (m *mockVpcApi) DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	if m.describeSecurityGroupsOutput == nil {
		return &ec2.DescribeSecurityGroupsOutput{}, m.describeSecurityGroupsErr
	}
	return m.describeSecurityGroupsOutput, m.describeSecurityGroupsErr
}

func (m *mockVpcApi) DescribeVpcEndpoints(ctx context.Context, params *ec2.DescribeVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if m.describeVpcEndpointsOutput == nil {
		return &ec2.DescribeVpcEndpointsOutput{}, nil
	}
	return m.describeVpcEndpointsOutput, nil
}

func (m *mockVpcApi) DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	if m.describeSubnetsOutput == nil {
		return &ec2.DescribeSubnetsOutput{}, m.describeSubnetsErr
	}
	return m.describeSubnetsOutput, m.describeSubnetsErr
}

func (m *mockVpcApi) DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	if m.describeNetworkAclsOutput == nil {
		return &ec2.DescribeNetworkAclsOutput{}, m.describeNetworkAclsErr
	}
	return m.describeNetworkAclsOutput, m.describeNetworkAclsErr
}

func TestVPCScanner_Scan(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name             string
		mockAPI          *mockVpcApi
		expectedRuleID   string
		expectedSeverity string
		expectVulnerable bool
	}{
		{
			name: "Unrestricted SSH",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-001"),
							GroupName: aws.String("ssh-open"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int32(22),
									ToPort:     aws.Int32(22),
									IpRanges: []types.IpRange{
										{CidrIp: aws.String("0.0.0.0/0")},
									},
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "Unrestricted SSH Specific Rule",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-001-ssh"),
							GroupName: aws.String("ssh-open"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int32(22),
									ToPort:     aws.Int32(22),
									IpRanges: []types.IpRange{
										{CidrIp: aws.String("0.0.0.0/0")},
									},
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "Unrestricted RDP",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-002"),
							GroupName: aws.String("rdp-open"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int32(3389),
									ToPort:     aws.Int32(3389),
									IpRanges: []types.IpRange{
										{CidrIp: aws.String("0.0.0.0/0")},
									},
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "Unrestricted RDP Specific Rule",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-002-rdp"),
							GroupName: aws.String("rdp-open"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int32(3389),
									ToPort:     aws.Int32(3389),
									IpRanges: []types.IpRange{
										{CidrIp: aws.String("0.0.0.0/0")},
									},
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "Unrestricted All Ports",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-003"),
							GroupName: aws.String("all-open"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("-1"),
									IpRanges: []types.IpRange{
										{CidrIp: aws.String("0.0.0.0/0")},
									},
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
			expectedSeverity: "CRITICAL",
			expectVulnerable: true,
		},
		{
			name: "Default Security Group Ingress",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-default"),
							GroupName: aws.String("default"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int32(80),
									ToPort:     aws.Int32(80),
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_securitygroup_default_restrict_traffic",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "Subnet MapPublicIpOnLaunch",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{},
				describeSubnetsOutput: &ec2.DescribeSubnetsOutput{
					Subnets: []types.Subnet{
						{
							SubnetId:            aws.String("subnet-public"),
							MapPublicIpOnLaunch: aws.Bool(true),
							AvailabilityZone:    aws.String("us-east-1a"),
						},
					},
				},
			},
			expectedRuleID:   "vpc_subnet_no_public_ip_by_default",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "NACL Open Ingress Port 22",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{},
				describeNetworkAclsOutput: &ec2.DescribeNetworkAclsOutput{
					NetworkAcls: []types.NetworkAcl{
						{
							NetworkAclId: aws.String("acl-001"),
							Entries: []types.NetworkAclEntry{
								{
									RuleNumber: aws.Int32(100),
									RuleAction: types.RuleActionAllow,
									Egress:     aws.Bool(false),
									CidrBlock:  aws.String("0.0.0.0/0"),
									Protocol:   aws.String("6"), // TCP
									PortRange: &types.PortRange{
										From: aws.Int32(22),
										To:   aws.Int32(22),
									},
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_networkacl_allow_ingress_tcp_port_22",
			expectedSeverity: "HIGH",
			expectVulnerable: true,
		},
		{
			name: "NACL Open Ingress Any Port",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{},
				describeNetworkAclsOutput: &ec2.DescribeNetworkAclsOutput{
					NetworkAcls: []types.NetworkAcl{
						{
							NetworkAclId: aws.String("acl-002"),
							Entries: []types.NetworkAclEntry{
								{
									RuleNumber: aws.Int32(100),
									RuleAction: types.RuleActionAllow,
									Egress:     aws.Bool(false),
									CidrBlock:  aws.String("0.0.0.0/0"),
									Protocol:   aws.String("-1"),
								},
							},
						},
					},
				},
			},
			expectedRuleID:   "ec2_networkacl_allow_ingress_any_port",
			expectedSeverity: "CRITICAL",
			expectVulnerable: true,
		},
		{
			name: "Compliant VPC and Security Group",
			mockAPI: &mockVpcApi{
				describeSecurityGroupsOutput: &ec2.DescribeSecurityGroupsOutput{
					SecurityGroups: []types.SecurityGroup{
						{
							GroupId:   aws.String("sg-safe"),
							GroupName: aws.String("app-sg"),
							IpPermissions: []types.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int32(443),
									ToPort:     aws.Int32(443),
									IpRanges: []types.IpRange{
										{CidrIp: aws.String("10.0.0.0/8")},
									},
								},
							},
						},
					},
				},
				describeSubnetsOutput: &ec2.DescribeSubnetsOutput{
					Subnets: []types.Subnet{
						{
							SubnetId:            aws.String("subnet-safe"),
							MapPublicIpOnLaunch: aws.Bool(false),
						},
					},
				},
				describeNetworkAclsOutput: &ec2.DescribeNetworkAclsOutput{
					NetworkAcls: []types.NetworkAcl{
						{
							NetworkAclId: aws.String("acl-safe"),
							Entries: []types.NetworkAclEntry{
								{
									RuleNumber: aws.Int32(100),
									RuleAction: types.RuleActionAllow,
									Egress:     aws.Bool(false),
									CidrBlock:  aws.String("10.0.0.0/8"),
									Protocol:   aws.String("-1"),
								},
							},
						},
					},
				},
			},
			expectVulnerable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := secaas.NewVPCScannerWithClient(tt.mockAPI)
			results, err := s.Scan(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tt.expectVulnerable {
				if len(results) > 0 {
					t.Errorf("expected 0 results, got %d: %+v", len(results), results)
				}
				return
			}

			var matchedResult *scanner.ScanResult
			for _, r := range results {
				if r.RuleID == tt.expectedRuleID && r.Severity == tt.expectedSeverity {
					res := r
					matchedResult = &res
					break
				}
			}

			if matchedResult == nil {
				t.Fatalf("expected finding with RuleID %s and Severity %s, but none matched from %d results", tt.expectedRuleID, tt.expectedSeverity, len(results))
			}
		})
	}
}

func TestVPCScanner_VPCPeeringRouteTables(t *testing.T) {
	ctx := context.Background()

	t.Run("Non-compliant broad 0.0.0.0/0 route", func(t *testing.T) {
		mockAPI := &mockVpcApi{
			describeRouteTablesOutput: &ec2.DescribeRouteTablesOutput{
				RouteTables: []types.RouteTable{
					{
						RouteTableId: aws.String("rtb-12345"),
						Routes: []types.Route{
							{
								DestinationCidrBlock:   aws.String("0.0.0.0/0"),
								VpcPeeringConnectionId: aws.String("pcx-11223344"),
							},
						},
					},
				},
			},
		}

		s := secaas.NewVPCScannerWithClient(mockAPI)
		results, err := s.Scan(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, r := range results {
			if r.RuleID == "vpc_peering_routing_tables_with_least_privilege" {
				found = true
				if r.Status != "FAIL" {
					t.Errorf("expected FAIL status, got %s", r.Status)
				}
				if r.Severity != "MEDIUM" {
					t.Errorf("expected MEDIUM severity, got %s", r.Severity)
				}
			}
		}
		if !found {
			t.Errorf("expected finding for vpc_peering_routing_tables_with_least_privilege")
		}
	})

	t.Run("Compliant specific subnet route", func(t *testing.T) {
		mockAPI := &mockVpcApi{
			describeRouteTablesOutput: &ec2.DescribeRouteTablesOutput{
				RouteTables: []types.RouteTable{
					{
						RouteTableId: aws.String("rtb-67890"),
						Routes: []types.Route{
							{
								DestinationCidrBlock:   aws.String("10.1.0.0/24"),
								VpcPeeringConnectionId: aws.String("pcx-11223344"),
							},
						},
					},
				},
			},
		}

		s := secaas.NewVPCScannerWithClient(mockAPI)
		results, err := s.Scan(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		found := false
		for _, r := range results {
			if r.RuleID == "vpc_peering_routing_tables_with_least_privilege" {
				found = true
				if r.Status != "PASS" {
					t.Errorf("expected PASS status, got %s", r.Status)
				}
			}
		}
		if !found {
			t.Errorf("expected PASS finding for vpc_peering_routing_tables_with_least_privilege")
		}
	})
}
