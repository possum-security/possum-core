package secaas

import (
	"context"
	"fmt"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
)

// EFSApi defines the interface for Amazon EFS operations for mocking and testing.
type EFSApi interface {
	DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
}

// EFSScanner evaluates whether Amazon EFS file systems have encryption at rest enabled.
type EFSScanner struct {
	client EFSApi
	region string
}

// NewEFSScanner creates a new EFSScanner with AWS config.
func NewEFSScanner(cfg aws.Config) *EFSScanner {
	return &EFSScanner{
		client: efs.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewEFSScannerWithClient creates a scanner with custom/mock client.
func NewEFSScannerWithClient(client EFSApi, region string) *EFSScanner {
	return &EFSScanner{
		client: client,
		region: region,
	}
}

func (s *EFSScanner) Name() string {
	return "EFS-SecaaS-Scanner"
}

// Scan checks efs_encryption_at_rest_enabled (CIS 2.4.1) for all EFS file systems.
func (s *EFSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
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

	var marker *string
	for {
		if limit > 0 && processedCount >= limit {
			break
		}

		out, err := s.client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe EFS file systems: %w", err)
		}

		for _, fs := range out.FileSystems {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			fsID := aws.ToString(fs.FileSystemId)
			fsArn := aws.ToString(fs.FileSystemArn)
			resourceID := fsID
			if resourceID == "" {
				resourceID = fsArn
			}
			nodeID := fsArn
			if nodeID == "" {
				nodeID = fsID
			}

			isEncrypted := aws.ToBool(fs.Encrypted)

			var edges []graph.Edge
			if fs.KmsKeyId != nil && *fs.KmsKeyId != "" {
				edges = append(edges, graph.Edge{
					From:     nodeID,
					To:       aws.ToString(fs.KmsKeyId),
					Relation: "ENCRYPTED_WITH",
				})
			}

			metrics := map[string]interface{}{
				"FileSystemId":  fsID,
				"FileSystemArn": fsArn,
				"Encrypted":     isEncrypted,
			}
			if fs.Name != nil && *fs.Name != "" {
				metrics["Name"] = aws.ToString(fs.Name)
			}
			if fs.KmsKeyId != nil && *fs.KmsKeyId != "" {
				metrics["KmsKeyId"] = aws.ToString(fs.KmsKeyId)
			}

			if isEncrypted {
				metrics["StatusExtended"] = fmt.Sprintf("EFS file system %s has encryption at rest enabled.", resourceID)
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-EFS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "efs_encryption_at_rest_enabled",
					Severity:     "INFO",
					Metrics:      metrics,
					Nodes:        []graph.Node{{ID: nodeID, NodeType: "SecaaS-EFS"}},
					Edges:        edges,
				})
			} else {
				metrics["StatusExtended"] = fmt.Sprintf("EFS file system %s does not have encryption at rest enabled.", resourceID)
				metrics["SecurityIssues"] = []string{"EFS file system encryption at rest is disabled"}
				metrics["Recommendation"] = "Enable encryption at rest when creating EFS file systems."
				results = append(results, scanner.ScanResult{
					ResourceID:   resourceID,
					ResourceType: "SecaaS-EFS",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "efs_encryption_at_rest_enabled",
					Severity:     "HIGH",
					Metrics:      metrics,
					Nodes:        []graph.Node{{ID: nodeID, NodeType: "SecaaS-EFS"}},
					Edges:        edges,
				})
			}
		}

		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *EFSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "efs-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "efs",
		CheckIDs:      []string{"efs_encryption_at_rest_enabled"},
	}
}
