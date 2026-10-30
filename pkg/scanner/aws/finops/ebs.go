package finops

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EBSClient defines the EC2 API subset needed by EBSScanner.
type EBSClient interface {
	ec2.DescribeVolumesAPIClient
	ec2.DescribeSnapshotsAPIClient
}

// EBSScanner checks for unattached EBS volumes and orphaned EBS Snapshots (AMIs).
type EBSScanner struct {
	client EBSClient
	region string
}

// Ensure EBSScanner satisfies MetaScanner at compile time.
var _ scanner.MetaScanner = (*EBSScanner)(nil)

func NewEBSScanner(cfg aws.Config) *EBSScanner {
	return &EBSScanner{
		client: ec2.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewEBSScannerWithClient allows injecting a custom or mock EC2 client.
func NewEBSScannerWithClient(client EBSClient, region ...string) *EBSScanner {
	r := ""
	if len(region) > 0 {
		r = region[0]
	}
	return &EBSScanner{
		client: client,
		region: r,
	}
}

func (s *EBSScanner) Name() string {
	return "EBS-and-Snapshot-Scanner"
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *EBSScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "ebs-and-snapshot-scanner",
		Name:          s.Name(),
		Category:      model.CategoryFinOps,
		Scope:         model.ScopeRegional,
		ExecutionCost: scanner.CostLight,
		Description:   "Checks for unattached EBS volumes and orphaned EBS snapshots",
		Service:       "ec2",
		CheckIDs:      []string{RuleEBSVolumeUnused, RuleEBSSnapshotOrphaned},
	}
}

func (s *EBSScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// --- 1. Scan for Orphaned EBS Volumes ---
	volPaginator := ec2.NewDescribeVolumesPaginator(s.client, &ec2.DescribeVolumesInput{})
	for volPaginator.HasMorePages() {
		page, err := volPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, volume := range page.Volumes {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			isOrphaned := volume.State == types.VolumeStateAvailable
			volID := aws.ToString(volume.VolumeId)

			sizeGB := float64(aws.ToInt32(volume.Size))
			cost := sizeGB * 0.08 // Generic $0.08/GB for gp2/gp3

			metrics := map[string]interface{}{
				"DisplayName":          volID,
				"SizeGB":               sizeGB,
				"VolumeType":           string(volume.VolumeType),
				"State":                string(volume.State),
				"EstimatedMonthlyCost": cost,
			}

			var title, desc, remediation string
			if isOrphaned {
				title = "Unattached EBS Volume"
				desc = fmt.Sprintf("EBS volume %s is in available state and not attached to any EC2 instance.", volID)
				remediation = "Delete the unattached volume or snapshot and delete it to prevent recurring charges."
				metrics["Recommendation"] = "Delete Unattached Volume"
			} else {
				title = "Active EBS Volume"
				desc = fmt.Sprintf("EBS volume %s is attached and in use.", volID)
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   volID,
				ResourceType: "EBS_VOLUME",
				Region:       regionFromAZ(s.region, aws.ToString(volume.AvailabilityZone)),
				RuleID:       RuleEBSVolumeUnused,
				DisplayName:  volID,
				IsOrphaned:   isOrphaned,
				Cost:         cost,
				Title:        title,
				Description:  desc,
				Remediation:  remediation,
				Metrics:      metrics,
			}))
		}
	}

	// --- 2. Scan for Orphaned EBS Snapshots (AMIs) ---
	// We only want to scan snapshots owned by this account (not public ones)
	snapPaginator := ec2.NewDescribeSnapshotsPaginator(s.client, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})

	for snapPaginator.HasMorePages() {
		page, err := snapPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, snap := range page.Snapshots {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			desc := aws.ToString(snap.Description)
			snapID := aws.ToString(snap.SnapshotId)

			// A common FinOps pattern: If the snapshot was created by an AMI (starts with "Created by CreateImage"),
			// but it's not currently being used, it's a candidate for deletion.
			// Here we simply flag them as "Review Needed" if they are older than 90 days.
			isOrphaned := false

			if snap.StartTime != nil {
				daysOld := int(time.Since(*snap.StartTime).Hours() / 24)
				if daysOld > 90 {
					isOrphaned = true // Over 90 days old is a classic FinOps flag for snapshot cleanup
				}
			}

			// Some snapshots are specifically tied to AMI deregistration issues
			if strings.Contains(desc, "CreateImage") && isOrphaned {
				desc = "Likely orphaned AMI Snapshot. " + desc
			}

			sizeGB := float64(aws.ToInt32(snap.VolumeSize))
			cost := sizeGB * 0.05 // Generic $0.05/GB for snapshots

			metrics := map[string]interface{}{
				"DisplayName":          snapID,
				"SizeGB":               sizeGB,
				"Description":          desc,
				"EstimatedMonthlyCost": cost,
			}

			var title, description, remediation string
			if isOrphaned {
				title = "Old Orphaned EBS Snapshot"
				description = fmt.Sprintf("EBS snapshot %s is older than 90 days (%s).", snapID, desc)
				remediation = "Audit snapshot age and delete obsolete snapshots that are no longer required."
				metrics["Recommendation"] = "Review and Delete Old Snapshot"
			} else {
				title = "Active EBS Snapshot"
				description = fmt.Sprintf("EBS snapshot %s is within retention period.", snapID)
			}

			results = append(results, BuildFinOpsResult(FinOpsResultParams{
				ResourceID:   snapID,
				ResourceType: "EBS_SNAPSHOT",
				Region:       resolveRegion(s.region, "regional"),
				RuleID:       RuleEBSSnapshotOrphaned,
				DisplayName:  snapID,
				IsOrphaned:   isOrphaned,
				Cost:         cost,
				Title:        title,
				Description:  description,
				Remediation:  remediation,
				Metrics:      metrics,
			}))
		}
	}

	return results, nil
}
