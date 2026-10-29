package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type EC2VpcApi interface {
	DescribeSecurityGroups(ctx context.Context, params *ec2.DescribeSecurityGroupsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcEndpoints(ctx context.Context, params *ec2.DescribeVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	DescribeSubnets(ctx context.Context, params *ec2.DescribeSubnetsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeNetworkAcls(ctx context.Context, params *ec2.DescribeNetworkAclsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeRouteTables(ctx context.Context, params *ec2.DescribeRouteTablesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
}

type VPCScanner struct {
	client EC2VpcApi
}

func NewVPCScanner(cfg aws.Config) *VPCScanner {
	return &VPCScanner{
		client: ec2.NewFromConfig(cfg),
	}
}

func NewVPCScannerWithClient(client EC2VpcApi) *VPCScanner {
	return &VPCScanner{
		client: client,
	}
}

func (s *VPCScanner) Name() string {
	return "VPC-SecurityGroup-SecaaS-Scanner"
}

func (s *VPCScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// 1. Scan Security Groups
	paginator := ec2.NewDescribeSecurityGroupsPaginator(s.client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, sg := range page.SecurityGroups {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			sgID := aws.ToString(sg.GroupId)
			sgName := aws.ToString(sg.GroupName)

			var openPorts []int32
			isVulnerable := false

			for _, ipPerm := range sg.IpPermissions {
				fromPort := aws.ToInt32(ipPerm.FromPort)
				toPort := aws.ToInt32(ipPerm.ToPort)
				ipProtocol := aws.ToString(ipPerm.IpProtocol)

				// If IpProtocol is -1, it means all ports and protocols
				if ipProtocol == "-1" {
					for _, ipRange := range ipPerm.IpRanges {
						if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
							isVulnerable = true
							openPorts = append(openPorts, -1) // -1 indicates all ports
							break
						}
					}
					continue
				}

				if ipProtocol == "tcp" || ipProtocol == "udp" {
					var sensitivePorts = []int32{22, 3389, 5432}
					var foundPort int32 = -1
					for _, port := range sensitivePorts {
						// Check if the port range covers the sensitive port
						if fromPort <= port && toPort >= port {
							foundPort = port
							break
						}
					}

					if foundPort != -1 {
						for _, ipRange := range ipPerm.IpRanges {
							if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
								isVulnerable = true
								openPorts = append(openPorts, foundPort)
								break
							}
						}
					}
				}
			}

			// 1a. Default Security Group Check (ec2_securitygroup_default_restrict_traffic - HIGH)
			if sgName == "default" && len(sg.IpPermissions) > 0 {
				defaultSgMetrics := map[string]interface{}{
					"SecurityGroupName": sgName,
					"VpcId":             aws.ToString(sg.VpcId),
					"StatusExtended":    fmt.Sprintf("Default security group %s (%s) has active inbound rules allowing network traffic.", sgName, sgID),
					"SecurityIssues":    []string{"Default security group has active inbound rules allowing network traffic"},
					"Recommendation":    "Default security group should have no inbound or outbound rules; create dedicated security groups instead.",
				}
				var defaultSgNodes []graph.Node
				var defaultSgEdges []graph.Edge
				defaultSgNodes = append(defaultSgNodes, graph.Node{ID: sgID, NodeType: "SecaaS-SecurityGroup"})
				if sg.VpcId != nil {
					defaultSgEdges = append(defaultSgEdges, graph.Edge{From: sgID, To: aws.ToString(sg.VpcId), Relation: "IN_VPC"})
				}
				results = append(results, scanner.ScanResult{
					ResourceID:   sgID,
					ResourceType: "SecaaS-SecurityGroup",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "ec2_securitygroup_default_restrict_traffic",
					Severity:     "HIGH",
					Metrics:      defaultSgMetrics,
					Nodes:        defaultSgNodes,
					Edges:        defaultSgEdges,
				})
			}

			// 1b. Open Ingress Check (ec2_securitygroup_allow_ingress_from_internet_to_any_port - HIGH)
			if isVulnerable {
				var portStrs []string
				for _, p := range openPorts {
					if p == -1 {
						portStrs = append(portStrs, "ALL Ports (-1)")
					} else {
						portStrs = append(portStrs, fmt.Sprintf("%d", p))
					}
				}
				metrics := map[string]interface{}{
					"SecurityGroupName": sgName,
					"VpcId":             aws.ToString(sg.VpcId),
					"IsVulnerable":      isVulnerable,
					"OpenPorts":         fmt.Sprintf("%v", openPorts),
					"StatusExtended":    fmt.Sprintf("Security Group %s (%s) allows unrestricted 0.0.0.0/0 inbound access on ports: %s", sgName, sgID, strings.Join(portStrs, ", ")),
					"SecurityIssues":    []string{fmt.Sprintf("Security Group allows unrestricted 0.0.0.0/0 inbound access on ports: %s", strings.Join(portStrs, ", "))},
					"Recommendation":    "Restrict 0.0.0.0/0 ingress on sensitive ports (e.g. 22, 3389, 5432) to known IP ranges or private CIDRs.",
				}

				var nodes []graph.Node
				var edges []graph.Edge
				nodes = append(nodes, graph.Node{ID: sgID, NodeType: "SecaaS-SecurityGroup"})
				if sg.VpcId != nil {
					edges = append(edges, graph.Edge{From: sgID, To: aws.ToString(sg.VpcId), Relation: "IN_VPC"})
				}
				results = append(results, scanner.ScanResult{
					ResourceID:   sgID,
					ResourceType: "SecaaS-SecurityGroup",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
					Severity:     "HIGH",
					IsOrphaned:   isVulnerable,
					Metrics:      metrics,
					Nodes:        nodes,
					Edges:        edges,
				})

				// Specific port checks for CIS 5.2
				for _, p := range openPorts {
					if p == -1 {
						results = append(results, scanner.ScanResult{
							ResourceID:   sgID,
							ResourceType: "SecaaS-SecurityGroup",
							Region:       "global",
							Status:       "FAIL",
							RuleID:       "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
							Severity:     "CRITICAL",
							Metrics: map[string]interface{}{
								"SecurityGroupName": sgName,
								"VpcId":             aws.ToString(sg.VpcId),
								"StatusExtended":    fmt.Sprintf("Security group %s (%s) allows unrestricted ingress from 0.0.0.0/0 to all ports.", sgName, sgID),
								"SecurityIssues":    []string{"Security group allows ingress from internet to all ports"},
								"Recommendation":    "Restrict inbound rules to only necessary ports and specific IP ranges.",
							},
							Nodes: nodes,
							Edges: edges,
						})
					} else if p == 22 {
						results = append(results, scanner.ScanResult{
							ResourceID:   sgID,
							ResourceType: "SecaaS-SecurityGroup",
							Region:       "global",
							Status:       "FAIL",
							RuleID:       "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
							Severity:     "HIGH",
							Metrics: map[string]interface{}{
								"SecurityGroupName": sgName,
								"VpcId":             aws.ToString(sg.VpcId),
								"StatusExtended":    fmt.Sprintf("Security group %s (%s) allows unrestricted ingress from 0.0.0.0/0 to port 22 (SSH).", sgName, sgID),
								"SecurityIssues":    []string{"Security group allows port 22 ingress from 0.0.0.0/0"},
								"Recommendation":    "Restrict port 22 ingress to private CIDRs or corporate bastion hosts.",
							},
							Nodes: nodes,
							Edges: edges,
						})
					} else if p == 3389 {
						results = append(results, scanner.ScanResult{
							ResourceID:   sgID,
							ResourceType: "SecaaS-SecurityGroup",
							Region:       "global",
							Status:       "FAIL",
							RuleID:       "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
							Severity:     "HIGH",
							Metrics: map[string]interface{}{
								"SecurityGroupName": sgName,
								"VpcId":             aws.ToString(sg.VpcId),
								"StatusExtended":    fmt.Sprintf("Security group %s (%s) allows unrestricted ingress from 0.0.0.0/0 to port 3389 (RDP).", sgName, sgID),
								"SecurityIssues":    []string{"Security group allows port 3389 ingress from 0.0.0.0/0"},
								"Recommendation":    "Restrict port 3389 ingress to private CIDRs or corporate VPNs.",
							},
							Nodes: nodes,
							Edges: edges,
						})
					}
				}
			}
		}
	}

	// 2. Subnets Check (vpc_subnet_no_public_ip_by_default - HIGH)
	subnetsOut, err := s.client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{})
	if err == nil && subnetsOut != nil {
		for _, subnet := range subnetsOut.Subnets {
			subnetID := aws.ToString(subnet.SubnetId)
			if aws.ToBool(subnet.MapPublicIpOnLaunch) {
				results = append(results, scanner.ScanResult{
					ResourceID:   subnetID,
					ResourceType: "SecaaS-Subnet",
					Region:       aws.ToString(subnet.AvailabilityZone),
					Status:       "FAIL",
					RuleID:       "vpc_subnet_no_public_ip_by_default",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"SubnetId":       subnetID,
						"VpcId":          aws.ToString(subnet.VpcId),
						"StatusExtended": fmt.Sprintf("VPC Subnet %s has MapPublicIpOnLaunch enabled by default.", subnetID),
						"SecurityIssues": []string{"Subnet automatically assigns public IP addresses to instances on launch"},
						"Recommendation": "Ensure VPC subnets do not automatically assign public IP addresses on launch.",
					},
					Nodes: []graph.Node{
						{
							ID:       subnetID,
							NodeType: "SecaaS-Subnet",
						},
					},
				})
			}
		}
	}

	// 3. Network ACLs Ingress Checks (CIS 5.1)
	naclsOut, naclErr := s.client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{})
	if naclErr == nil && naclsOut != nil {
		for _, nacl := range naclsOut.NetworkAcls {
			naclID := aws.ToString(nacl.NetworkAclId)
			for _, entry := range nacl.Entries {
				if entry.RuleAction == ec2types.RuleActionAllow && !aws.ToBool(entry.Egress) {
					cidr := aws.ToString(entry.CidrBlock)
					if cidr == "0.0.0.0/0" {
						proto := aws.ToString(entry.Protocol)
						// All ports (-1 or "all")
						if proto == "-1" || proto == "all" || (entry.PortRange != nil && entry.PortRange.From != nil && entry.PortRange.To != nil && *entry.PortRange.From <= 1 && *entry.PortRange.To >= 65535) {
							results = append(results, scanner.ScanResult{
								ResourceID:   naclID,
								ResourceType: "SecaaS-NetworkACL",
								Region:       "global",
								Status:       "FAIL",
								RuleID:       "ec2_networkacl_allow_ingress_any_port",
								Severity:     "CRITICAL",
								Metrics: map[string]interface{}{
									"NetworkAclId":   naclID,
									"RuleNumber":     aws.ToInt32(entry.RuleNumber),
									"StatusExtended": fmt.Sprintf("NACL %s rule #%d allows ingress traffic from 0.0.0.0/0 across all ports.", naclID, aws.ToInt32(entry.RuleNumber)),
									"SecurityIssues": []string{"NACL allows unrestricted 0.0.0.0/0 ingress across all ports"},
									"Recommendation": "Restrict NACL ingress rules to specific IP CIDRs and required ports.",
								},
								Nodes: []graph.Node{{ID: naclID, NodeType: "SecaaS-NetworkACL"}},
							})
						}
						// Port 22 (SSH)
						if entry.PortRange != nil && entry.PortRange.From != nil && entry.PortRange.To != nil && *entry.PortRange.From <= 22 && *entry.PortRange.To >= 22 {
							results = append(results, scanner.ScanResult{
								ResourceID:   naclID,
								ResourceType: "SecaaS-NetworkACL",
								Region:       "global",
								Status:       "FAIL",
								RuleID:       "ec2_networkacl_allow_ingress_tcp_port_22",
								Severity:     "HIGH",
								Metrics: map[string]interface{}{
									"NetworkAclId":   naclID,
									"RuleNumber":     aws.ToInt32(entry.RuleNumber),
									"StatusExtended": fmt.Sprintf("NACL %s rule #%d allows ingress traffic from 0.0.0.0/0 on port 22 (SSH).", naclID, aws.ToInt32(entry.RuleNumber)),
									"SecurityIssues": []string{"NACL allows ingress from 0.0.0.0/0 on port 22"},
									"Recommendation": "Restrict port 22 ingress to trusted IP ranges.",
								},
								Nodes: []graph.Node{{ID: naclID, NodeType: "SecaaS-NetworkACL"}},
							})
						}
						// Port 3389 (RDP)
						if entry.PortRange != nil && entry.PortRange.From != nil && entry.PortRange.To != nil && *entry.PortRange.From <= 3389 && *entry.PortRange.To >= 3389 {
							results = append(results, scanner.ScanResult{
								ResourceID:   naclID,
								ResourceType: "SecaaS-NetworkACL",
								Region:       "global",
								Status:       "FAIL",
								RuleID:       "ec2_networkacl_allow_ingress_tcp_port_3389",
								Severity:     "HIGH",
								Metrics: map[string]interface{}{
									"NetworkAclId":   naclID,
									"RuleNumber":     aws.ToInt32(entry.RuleNumber),
									"StatusExtended": fmt.Sprintf("NACL %s rule #%d allows ingress traffic from 0.0.0.0/0 on port 3389 (RDP).", naclID, aws.ToInt32(entry.RuleNumber)),
									"SecurityIssues": []string{"NACL allows ingress from 0.0.0.0/0 on port 3389"},
									"Recommendation": "Restrict port 3389 ingress to trusted IP ranges.",
								},
								Nodes: []graph.Node{{ID: naclID, NodeType: "SecaaS-NetworkACL"}},
							})
						}
					}
				}
			}
		}
	}

	// 4. Scan Route Tables for VPC Peering Least Privilege (CIS 5.4)
	rtPaginator := ec2.NewDescribeRouteTablesPaginator(s.client, &ec2.DescribeRouteTablesInput{})
	for rtPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := rtPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, rt := range page.RouteTables {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			rtID := aws.ToString(rt.RouteTableId)
			hasPeeringRoute := false
			broadPeering := false
			var violatingDestinations []string

			for _, route := range rt.Routes {
				if route.VpcPeeringConnectionId != nil && *route.VpcPeeringConnectionId != "" {
					hasPeeringRoute = true
					destV4 := aws.ToString(route.DestinationCidrBlock)
					destV6 := aws.ToString(route.DestinationIpv6CidrBlock)

					if destV4 == "0.0.0.0/0" || destV6 == "::/0" {
						broadPeering = true
						violatingDestinations = append(violatingDestinations, destV4)
					}
				}
			}

			if hasPeeringRoute {
				if broadPeering {
					results = append(results, scanner.ScanResult{
						ResourceID:   rtID,
						ResourceType: "SecaaS-RouteTable",
						Region:       "global",
						Status:       "FAIL",
						RuleID:       "vpc_peering_routing_tables_with_least_privilege",
						Severity:     "MEDIUM",
						Metrics: map[string]interface{}{
							"RouteTableId":   rtID,
							"StatusExtended": fmt.Sprintf("Route table %s has broad 0.0.0.0/0 route to VPC peering connection.", rtID),
							"SecurityIssues": violatingDestinations,
							"Recommendation": "Restrict VPC peering route table destinations to specific subnets rather than 0.0.0.0/0.",
						},
						Nodes: []graph.Node{{ID: rtID, NodeType: "SecaaS-RouteTable"}},
					})
				} else {
					results = append(results, scanner.ScanResult{
						ResourceID:   rtID,
						ResourceType: "SecaaS-RouteTable",
						Region:       "global",
						Status:       "PASS",
						RuleID:       "vpc_peering_routing_tables_with_least_privilege",
						Severity:     "INFO",
						Metrics: map[string]interface{}{
							"RouteTableId":   rtID,
							"StatusExtended": fmt.Sprintf("Route table %s complies with least-privilege VPC peering routing.", rtID),
						},
						Nodes: []graph.Node{{ID: rtID, NodeType: "SecaaS-RouteTable"}},
					})
				}
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *VPCScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "vpc-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "vpc",
		CheckIDs:      []string{"ec2_networkacl_allow_ingress_any_port", "ec2_networkacl_allow_ingress_tcp_port_22", "ec2_networkacl_allow_ingress_tcp_port_3389", "ec2_securitygroup_allow_ingress_from_internet_to_all_ports", "ec2_securitygroup_allow_ingress_from_internet_to_any_port", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389", "ec2_securitygroup_default_restrict_traffic", "vpc_peering_routing_tables_with_least_privilege", "vpc_subnet_no_public_ip_by_default"},
	}
}
