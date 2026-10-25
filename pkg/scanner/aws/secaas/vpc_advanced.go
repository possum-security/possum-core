package secaas

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type VPCAdvancedScanner struct {
	client *ec2.Client
}

func NewVPCAdvancedScanner(cfg aws.Config) *VPCAdvancedScanner {
	return &VPCAdvancedScanner{
		client: ec2.NewFromConfig(cfg),
	}
}

func (s *VPCAdvancedScanner) Name() string {
	return "VPC-Advanced-SecaaS-Scanner"
}

func (s *VPCAdvancedScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// List VPCs
	paginator := ec2.NewDescribeVpcsPaginator(s.client, &ec2.DescribeVpcsInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, vpc := range page.Vpcs {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			vpcID := aws.ToString(vpc.VpcId)

			isVulnerable := false
			var issues []string

			// Check Flow Logs
			flowLogsOut, err := s.client.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
				Filter: []types.Filter{
					{
						Name:   aws.String("resource-id"),
						Values: []string{vpcID},
					},
				},
			})
			if err != nil {
				return nil, err
			}

			if len(flowLogsOut.FlowLogs) == 0 {
				isVulnerable = true
				issues = append(issues, "VPC Flow Logs are not enabled")
			}

			// Check Network ACLs
			naclsOut, err := s.client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
				Filters: []types.Filter{
					{
						Name:   aws.String("vpc-id"),
						Values: []string{vpcID},
					},
				},
			})
			if err != nil {
				return nil, err
			}

			for _, nacl := range naclsOut.NetworkAcls {
				for _, entry := range nacl.Entries {
					// We only care about Inbound rules (Egress == false)
					if entry.Egress != nil && *entry.Egress {
						continue
					}
					// We care about Allow rules
					if entry.RuleAction != types.RuleActionAllow {
						continue
					}

					// Check for 0.0.0.0/0
					if entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0" {
						protocol := "-1"
						if entry.Protocol != nil {
							protocol = *entry.Protocol
						}

						// Protocol "6" is TCP, "17" is UDP, "-1" is ALL
						if protocol == "-1" {
							isVulnerable = true
							issues = append(issues, fmt.Sprintf("NACL %s allows unrestricted inbound access to all ports (including 22 and 3389)", aws.ToString(nacl.NetworkAclId)))
						} else if protocol == "6" || protocol == "17" {
							if entry.PortRange != nil {
								fromPort := aws.ToInt32(entry.PortRange.From)
								toPort := aws.ToInt32(entry.PortRange.To)

								if (fromPort <= 22 && toPort >= 22) || (fromPort <= 3389 && toPort >= 3389) {
									isVulnerable = true
									issues = append(issues, fmt.Sprintf("NACL %s allows unrestricted inbound access on port 22 or 3389", aws.ToString(nacl.NetworkAclId)))
								}
							}
						}
					}
				}
			}

			metrics := map[string]interface{}{
				"VpcId": vpcID,
			}

			severity := "INFO"
			status := "PASS"
			if isVulnerable {
				metrics["SecurityIssues"] = issues
				metrics["Issues"] = issues
				metrics["StatusExtended"] = fmt.Sprintf("VPC %s does not have Flow Logs enabled or has unrestricted Network ACL entries.", vpcID)
				metrics["Recommendation"] = "Enable VPC Flow Logs and restrict 0.0.0.0/0 access on Network ACLs for ports 22 and 3389."
				severity = "MEDIUM"
				status = "FAIL"
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("VPC %s has Flow Logs enabled and secure Network ACLs.", vpcID)
				metrics["Recommendation"] = "Maintain VPC Flow Logs enabled."
			}

			var nodes []graph.Node
			var edges []graph.Edge
			nodes = append(nodes, graph.Node{ID: vpcID, NodeType: "SecaaS-VPCAdvanced"})
			results = append(results, scanner.ScanResult{
				ResourceID:   vpcID,
				ResourceType: "SecaaS-VPCAdvanced",
				Region:       "global",
				Status:       status,
				IsOrphaned:   isVulnerable,
				RuleID:       "vpc_flow_logs_enabled",
				Severity:     severity,
				Metrics:      metrics,
				Nodes:        nodes,
				Edges:        edges,
			})
		}
	}

	return results, nil
}
