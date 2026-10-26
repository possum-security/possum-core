package secaas

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// WAFv2ScannerApi defines the interface for AWS WAFv2 operations for mocking and testing.
type WAFv2ScannerApi interface {
	ListWebACLs(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	GetLoggingConfiguration(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error)
}

// WAFv2Scanner evaluates whether AWS WAFv2 WebACLs have logging enabled.
type WAFv2Scanner struct {
	client WAFv2ScannerApi
	region string
}

// NewWAFv2Scanner creates a new WAFv2Scanner with AWS config.
func NewWAFv2Scanner(cfg aws.Config) *WAFv2Scanner {
	return &WAFv2Scanner{
		client: wafv2.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewWAFv2ScannerWithClient creates a scanner with custom/mock client.
func NewWAFv2ScannerWithClient(client WAFv2ScannerApi, region string) *WAFv2Scanner {
	return &WAFv2Scanner{
		client: client,
		region: region,
	}
}

func (s *WAFv2Scanner) Name() string {
	return "WAFv2-SecaaS-Scanner"
}

// Scan checks wafv2_webacl_logging_enabled for all regional WAFv2 WebACLs.
func (s *WAFv2Scanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
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

	var nextMarker *string
	for {
		if limit > 0 && processedCount >= limit {
			break
		}

		out, err := s.client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope:      wafv2types.ScopeRegional,
			NextMarker: nextMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list WAFv2 web ACLs: %w", err)
		}

		for _, acl := range out.WebACLs {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			aclArn := aws.ToString(acl.ARN)
			aclName := aws.ToString(acl.Name)
			aclID := aws.ToString(acl.Id)

			resourceID := aclArn
			if resourceID == "" {
				resourceID = aclID
			}
			nodeID := aclArn
			if nodeID == "" {
				nodeID = aclID
			}

			logOut, logErr := s.client.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{
				ResourceArn: acl.ARN,
			})

			hasLogging := logErr == nil && logOut != nil && logOut.LoggingConfiguration != nil

			metrics := map[string]interface{}{
				"WebACLName": aclName,
				"WebACLId":   aclID,
				"WebACLArn":  aclArn,
			}

			var edges []graph.Edge
			if hasLogging {
				destinations := logOut.LoggingConfiguration.LogDestinationConfigs
				if len(destinations) > 0 {
					metrics["LogDestinationConfigs"] = destinations
					for _, dest := range destinations {
						edges = append(edges, graph.Edge{
							From:     nodeID,
							To:       dest,
							Relation: "LOGS_TO",
						})
					}
				}
				metrics["StatusExtended"] = fmt.Sprintf("WAFv2 WebACL %s has logging enabled.", aclName)
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-WAFv2",
					Region:       region,
					Status:       "PASS",
					RuleID:       "wafv2_webacl_logging_enabled",
					Severity:     "INFO",
					Metrics:      metrics,
					Nodes:        []graph.Node{{ID: nodeID, NodeType: "SecaaS-WAFv2"}},
					Edges:        edges,
				})
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("WAFv2 WebACL %s does not have logging enabled.", aclName)
				metrics["SecurityIssues"] = []string{"WAFv2 WebACL logging is not configured"}
				metrics["Recommendation"] = "Enable logging on WAFv2 WebACLs."
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-WAFv2",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "wafv2_webacl_logging_enabled",
					Severity:     "MEDIUM",
					Metrics:      metrics,
					Nodes:        []graph.Node{{ID: nodeID, NodeType: "SecaaS-WAFv2"}},
					Edges:        edges,
				})
			}
		}

		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		nextMarker = out.NextMarker
	}

	return results, nil
}
