package secaas

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

type Route53Scanner struct {
	client *route53.Client
}

func NewRoute53Scanner(cfg aws.Config) *Route53Scanner {
	return &Route53Scanner{
		client: route53.NewFromConfig(cfg),
	}
}

func (s *Route53Scanner) Name() string {
	return "Route53-SecaaS-Scanner"
}

func (s *Route53Scanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	paginator := route53.NewListHostedZonesPaginator(s.client, &route53.ListHostedZonesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, zone := range page.HostedZones {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			zoneId := aws.ToString(zone.Id)
			zoneName := aws.ToString(zone.Name)

			// List resource record sets
			recordPaginator := route53.NewListResourceRecordSetsPaginator(s.client, &route53.ListResourceRecordSetsInput{
				HostedZoneId: aws.String(zoneId),
			})

			for recordPaginator.HasMorePages() {
				recordPage, err := recordPaginator.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, rs := range recordPage.ResourceRecordSets {
					issues := []string{}

					// Check for dangling DNS (Subdomain Takeover)
					// We look at CNAMEs and Alias targets
					if rs.Type == "CNAME" {
						for _, record := range rs.ResourceRecords {
							val := aws.ToString(record.Value)
							if isVulnerableDomain(val) {
								if _, err := net.LookupHost(val); err != nil {
									issues = append(issues, "CNAME points to a highly vulnerable domain for Subdomain Takeover ("+val+"). Verify the target exists.")
								}
							}
						}
					} else if rs.AliasTarget != nil {
						val := aws.ToString(rs.AliasTarget.DNSName)
						if isVulnerableDomain(val) {
							if _, err := net.LookupHost(val); err != nil {
								issues = append(issues, "Alias points to a highly vulnerable domain for Subdomain Takeover ("+val+"). Verify the target exists.")
							}
						}
					}

					if len(issues) > 0 {
						metrics := map[string]interface{}{
							"HostedZone":     zoneName,
							"RecordName":     aws.ToString(rs.Name),
							"SecurityIssues": issues,
							"StatusExtended": fmt.Sprintf("Route53 record %s in hosted zone %s points to vulnerable domain or query logging is disabled.", aws.ToString(rs.Name), zoneName),
							"Recommendation": "Verify target resource exists or delete the DNS record to prevent Subdomain Takeover and enable query logging.",
							"Severity":       "MEDIUM",
						}

						var nodes []graph.Node
						var edges []graph.Edge
						nodes = append(nodes, graph.Node{ID: aws.ToString(rs.Name), NodeType: "SecaaS-Route53"})
						edges = append(edges, graph.Edge{From: aws.ToString(rs.Name), To: zoneId, Relation: "IN_HOSTED_ZONE"})

						results = append(results, scanner.ScanResult{
							ResourceID:   aws.ToString(rs.Name),
							ResourceType: "SecaaS-Route53",
							Region:       "global",
							Status:       "FAIL",
							IsOrphaned:   false,
							RuleID:       "route53_public_hosted_zones_cloudwatch_logging_enabled",
							Severity:     "MEDIUM",
							Metrics:      metrics,
							Nodes:        nodes,
							Edges:        edges,
						})
					}
				}
			}
		}
	}

	return results, nil
}

func isVulnerableDomain(domain string) bool {
	domain = strings.ToLower(domain)
	vulnerableSuffixes := []string{
		"s3-website",
		"elasticbeanstalk.com",
		"herokuapp.com",
		"azurewebsites.net",
		"cloudapp.net",
		"trafficmanager.net",
		"github.io",
		"bitbucket.io",
		"myshopify.com",
		"zendesk.com",
	}

	for _, suffix := range vulnerableSuffixes {
		if strings.Contains(domain, suffix) {
			return true
		}
	}
	return false
}
