package secaas

import (
	"context"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
)

// RDSApi defines the interface for AWS RDS API operations.
type RDSApi interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBParameters(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error)
	DescribeDBSnapshots(ctx context.Context, params *rds.DescribeDBSnapshotsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeDBSnapshotAttributes(ctx context.Context, params *rds.DescribeDBSnapshotAttributesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSnapshotAttributesOutput, error)
}

// RDSClient is an alias for backward compatibility.
type RDSClient = RDSApi

type RDSScanner struct {
	client RDSApi
	region string
}

func NewRDSScanner(cfg aws.Config) *RDSScanner {
	return &RDSScanner{
		client: rds.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

func NewRDSScannerWithClient(client RDSApi, region string) *RDSScanner {
	return &RDSScanner{
		client: client,
		region: region,
	}
}

func (s *RDSScanner) Name() string {
	return "RDS-SecaaS-Scanner"
}

func (s *RDSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
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

	pgCache := make(map[string]bool)

	isParameterGroupEncrypted := func(pgName string, engine string) bool {
		if cached, ok := pgCache[pgName]; ok {
			return cached
		}

		out, err := s.client.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
			DBParameterGroupName: aws.String(pgName),
		})
		if err != nil {
			pgCache[pgName] = false
			return false
		}

		encrypted := false
		for _, param := range out.Parameters {
			pName := strings.ToLower(aws.ToString(param.ParameterName))
			pVal := strings.ToLower(aws.ToString(param.ParameterValue))

			if (pName == "rds.force_ssl" && (pVal == "1" || pVal == "true")) ||
				(pName == "require_secure_transport" && (pVal == "1" || pVal == "on" || pVal == "true")) {
				encrypted = true
				break
			}
		}

		pgCache[pgName] = encrypted
		return encrypted
	}

	instanceArns := make(map[string]string)
	paginator := rds.NewDescribeDBInstancesPaginator(s.client, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, instance := range page.DBInstances {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			instanceID := aws.ToString(instance.DBInstanceIdentifier)
			instanceArn := aws.ToString(instance.DBInstanceArn)
			instanceArns[instanceID] = instanceArn
			engine := strings.ToLower(aws.ToString(instance.Engine))

			var edges []graph.Edge
			for _, sg := range instance.VpcSecurityGroups {
				edges = append(edges, graph.Edge{
					From:     aws.ToString(sg.VpcSecurityGroupId),
					To:       instanceArn,
					Relation: "ATTACHED_TO",
				})
			}

			// 1. Check storage encryption (rds_instance_storage_encrypted - HIGH)
			if !aws.ToBool(instance.StorageEncrypted) {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "rds_instance_storage_encrypted",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"StatusExtended":       fmt.Sprintf("RDS instance %s does not have storage encryption enabled.", instanceID),
						"SecurityIssues":       []string{"Missing encryption at rest"},
						"Recommendation":       "Enable storage encryption at rest for the RDS DB instance.",
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "rds_instance_storage_encrypted",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"StatusExtended":       fmt.Sprintf("RDS instance %s has storage encryption enabled.", instanceID),
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			}

			// 2. Check automated backups (rds_instance_backup_enabled - MEDIUM)
			if instance.BackupRetentionPeriod == nil || aws.ToInt32(instance.BackupRetentionPeriod) == 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "rds_instance_backup_enabled",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"StatusExtended":       fmt.Sprintf("RDS instance %s does not have automated backups enabled.", instanceID),
						"SecurityIssues":       []string{"Automated backups are disabled (backup retention period is 0)"},
						"Recommendation":       "Enable automated backups with a retention period of at least 7 days.",
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "rds_instance_backup_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"RetentionPeriodDays":  aws.ToInt32(instance.BackupRetentionPeriod),
						"StatusExtended":       fmt.Sprintf("RDS instance %s has automated backups enabled (%d days retention).", instanceID, aws.ToInt32(instance.BackupRetentionPeriod)),
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			}

			// 3. Check transport encryption / SSL enforcement (rds_instance_transport_encrypted - CIS 2.3.1 - HIGH)
			tlsEnforced := false
			for _, pg := range instance.DBParameterGroups {
				pgName := aws.ToString(pg.DBParameterGroupName)
				if isParameterGroupEncrypted(pgName, engine) {
					tlsEnforced = true
					break
				}
			}

			if !tlsEnforced {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "rds_instance_transport_encrypted",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"StatusExtended":       fmt.Sprintf("RDS instance %s does not enforce SSL/TLS transport encryption in its parameter groups.", instanceID),
						"SecurityIssues":       []string{"Missing enforced transport encryption (SSL/TLS)"},
						"Recommendation":       "Configure the DB parameter group to enforce SSL/TLS (rds.force_ssl=1 or require_secure_transport=1).",
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "rds_instance_transport_encrypted",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"StatusExtended":       fmt.Sprintf("RDS instance %s enforces SSL/TLS transport encryption.", instanceID),
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			}

			// 4. Check public exposure (rds_instance_no_public_access - CIS 2.3.3 - CRITICAL)
			if aws.ToBool(instance.PubliclyAccessible) {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "rds_instance_no_public_access",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"PubliclyAccessible":   true,
						"StatusExtended":       fmt.Sprintf("RDS instance %s is publicly accessible.", instanceID),
						"SecurityIssues":       []string{"Public accessibility enabled"},
						"Recommendation":       "Disable public accessibility on the RDS instance.",
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "rds_instance_no_public_access",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier": instanceID,
						"PubliclyAccessible":   false,
						"StatusExtended":       fmt.Sprintf("RDS instance %s is not publicly accessible.", instanceID),
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			}

			// 5. Check auto minor version upgrade (rds_instance_minor_version_upgrade_enabled - CIS 2.3.2 - LOW)
			if aws.ToBool(instance.AutoMinorVersionUpgrade) {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "PASS",
					RuleID:       "rds_instance_minor_version_upgrade_enabled",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier":    instanceID,
						"AutoMinorVersionUpgrade": true,
						"StatusExtended":          fmt.Sprintf("RDS instance %s has auto minor version upgrade enabled.", instanceID),
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   instanceID,
					ResourceType: "SecaaS-RDS",
					Region:       region,
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "rds_instance_minor_version_upgrade_enabled",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"DBInstanceIdentifier":    instanceID,
						"AutoMinorVersionUpgrade": false,
						"StatusExtended":          fmt.Sprintf("RDS instance %s does not have auto minor version upgrade enabled.", instanceID),
						"SecurityIssues":          []string{"Auto minor version upgrade is disabled"},
						"Recommendation":          "Enable auto minor version upgrade for the RDS instance.",
					},
					Nodes: []graph.Node{{ID: instanceArn, NodeType: "SecaaS-RDS"}},
					Edges: edges,
				})
			}
		}
	}

	// 6. Audit RDS DB Snapshots for Public Access (rds_snapshots_public_access - CRITICAL)
	snapPaginator := rds.NewDescribeDBSnapshotsPaginator(s.client, &rds.DescribeDBSnapshotsInput{})
	for snapPaginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		snapPage, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to describe RDS snapshots: %w", err)
		}

		for _, snap := range snapPage.DBSnapshots {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			snapID := aws.ToString(snap.DBSnapshotIdentifier)
			if snapID == "" {
				continue
			}

			snapArn := aws.ToString(snap.DBSnapshotArn)
			if snapArn == "" {
				snapArn = fmt.Sprintf("arn:aws:rds:%s::snapshot:%s", region, snapID)
			}

			attrOut, err := s.client.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
				DBSnapshotIdentifier: snap.DBSnapshotIdentifier,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to describe attributes for RDS snapshot %s: %w", snapID, err)
			}

			isPublic := false
			if attrOut != nil && attrOut.DBSnapshotAttributesResult != nil {
				for _, attr := range attrOut.DBSnapshotAttributesResult.DBSnapshotAttributes {
					if strings.EqualFold(aws.ToString(attr.AttributeName), "restore") {
						for _, val := range attr.AttributeValues {
							if strings.EqualFold(val, "all") {
								isPublic = true
								break
							}
						}
						if isPublic {
							break
						}
					}
				}
			}

			snapNodes := []graph.Node{{ID: snapArn, NodeType: "SecaaS-RDS-Snapshot"}}
			var snapEdges []graph.Edge
			if snap.DBInstanceIdentifier != nil && aws.ToString(snap.DBInstanceIdentifier) != "" {
				instID := aws.ToString(snap.DBInstanceIdentifier)
				instArn, ok := instanceArns[instID]
				if !ok {
					instArn = fmt.Sprintf("arn:aws:rds:%s::db:%s", region, instID)
				}
				snapEdges = append(snapEdges, graph.Edge{
					From:     snapArn,
					To:       instArn,
					Relation: "SNAPSHOT_OF",
				})
			}

			if isPublic {
				results = append(results, scanner.ScanResult{
					ResourceID:   snapID,
					ResourceType: "SecaaS-RDS-Snapshot",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "rds_snapshots_public_access",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"DBSnapshotIdentifier": snapID,
						"Public":               true,
						"StatusExtended":       fmt.Sprintf("RDS snapshot %s is publicly accessible.", snapID),
						"SecurityIssues":       []string{"RDS snapshot allows public access"},
						"Recommendation":       "Remove public restore access from RDS snapshots.",
					},
					Nodes: snapNodes,
					Edges: snapEdges,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   snapID,
					ResourceType: "SecaaS-RDS-Snapshot",
					Region:       region,
					Status:       "PASS",
					RuleID:       "rds_snapshots_public_access",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"DBSnapshotIdentifier": snapID,
						"Public":               false,
						"StatusExtended":       fmt.Sprintf("RDS snapshot %s is not publicly accessible.", snapID),
					},
					Nodes: snapNodes,
					Edges: snapEdges,
				})
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *RDSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "rds-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "rds",
		CheckIDs:      []string{"rds_instance_backup_enabled", "rds_instance_minor_version_upgrade_enabled", "rds_instance_no_public_access", "rds_instance_storage_encrypted", "rds_instance_transport_encrypted", "rds_snapshots_public_access"},
	}
}
