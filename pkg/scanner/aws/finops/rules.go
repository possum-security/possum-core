package finops

import (
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"
)

// Canonical FinOps Rule IDs for Possum Core.
const (
	// EBS
	RuleEBSVolumeUnused     = "ebs_volume_unused_attached"
	RuleEBSSnapshotOrphaned = "ebs_snapshot_old_orphaned"

	// EC2
	RuleEC2InstanceIdle = "ec2_instance_idle"

	// EIP
	RuleEIPUnassigned = "ec2_elastic_ip_unassigned"

	// NAT Gateway
	RuleNATGatewayIdle = "natgateway_idle"

	// RDS
	RuleRDSInstanceIdle = "rds_instance_idle"

	// ELB
	RuleELBLoadBalancerIdle = "elb_load_balancer_idle"

	// Lambda
	RuleLambdaFunctionUnused = "lambda_function_unused"

	// ENI
	RuleENIDetachedUnused = "eni_detached_unused"

	// CloudFormation
	RuleCloudFormationStackFailedOrAbandoned = "cloudformation_stack_failed_or_abandoned"

	// DynamoDB
	RuleDynamoDBProvisionedCapacityUnused = "dynamodb_provisioned_capacity_unused"

	// Redshift
	RuleRedshiftClusterIdle = "redshift_cluster_idle"

	// CloudFront
	RuleCloudFrontDistributionUnused = "cloudfront_distribution_unused"

	// S3
	RuleS3BucketLifecycleMissing = "s3_bucket_lifecycle_missing"

	// Cost Explorer
	RuleCostExplorerSpendTracked = "cost_explorer_spend_tracked"

	// ECR
	RuleECRImageUntaggedOrStale = "ecr_image_untagged_or_stale"

	// ECS
	RuleECSServiceIdle = "ecs_service_idle"
)

// FinOpsResultParams defines parameters to construct a canonical FinOps model.ScanResult.
type FinOpsResultParams struct {
	ResourceID   string
	ResourceType string
	Region       string
	RuleID       string
	DisplayName  string
	IsOrphaned   bool
	Cost         float64
	Severity     model.Severity // Optional override; defaults to SeverityMedium when orphaned, SeverityInfo when passing
	Title        string
	Description  string
	Remediation  string
	Metrics      map[string]interface{}
	Nodes        []model.Node
	Edges        []model.Edge
	Metadata     map[string]interface{}
}

// BuildFinOpsResult constructs a canonical ScanResult adhering to Possum FinOps conventions.
func BuildFinOpsResult(p FinOpsResultParams) scanner.ScanResult {
	if p.Metrics == nil {
		p.Metrics = make(map[string]interface{})
	}

	// Ensure DisplayName is always set for human readability
	if p.DisplayName != "" {
		p.Metrics["DisplayName"] = p.DisplayName
	} else if _, exists := p.Metrics["DisplayName"]; !exists {
		p.Metrics["DisplayName"] = p.ResourceID
	}

	res := scanner.ScanResult{
		ResourceID:   p.ResourceID,
		ResourceType: p.ResourceType,
		Region:       p.Region,
		RuleID:       p.RuleID,
		Category:     model.CategoryFinOps,
		IsOrphaned:   p.IsOrphaned,
		EvaluatedAt:  time.Now(),
		Metrics:      p.Metrics,
		Nodes:        p.Nodes,
		Edges:        p.Edges,
		Metadata:     p.Metadata,
	}

	if p.IsOrphaned {
		res.Status = model.StatusFail
		res.CostWasteMo = p.Cost
		if p.Severity != "" {
			res.Severity = p.Severity
		} else {
			res.Severity = model.SeverityMedium
		}
		res.Title = p.Title
		res.Description = p.Description
		res.Remediation = p.Remediation
	} else {
		res.Status = model.StatusPass
		res.CostWasteMo = 0.0
		res.Severity = model.SeverityInfo
		res.Title = p.Title
		res.Description = p.Description
		res.Remediation = ""
	}

	return res
}
