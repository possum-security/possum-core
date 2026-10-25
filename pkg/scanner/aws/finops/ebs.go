package finops

import (
	"context"
	"strings"
	"time"

	"github.com/possum-sec/possum/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EBSScanner checks for unattached EBS volumes and orphaned EBS Snapshots (AMIs).
type EBSScanner struct {
	client *ec2.Client
}

func NewEBSScanner(cfg aws.Config) *EBSScanner {
	return &EBSScanner{
		client: ec2.NewFromConfig(cfg),
	}
}

func (s *EBSScanner) Name() string {
	return "EBS-and-Snapshot-Scanner"
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

			sizeGB := float64(aws.ToInt32(volume.Size))
			cost := sizeGB * 0.08 // Generic $0.08/GB for gp2/gp3

			metrics := map[string]interface{}{
				"SizeGB":               sizeGB,
				"VolumeType":           string(volume.VolumeType),
				"State":                string(volume.State),
				"EstimatedMonthlyCost": cost,
			}
			if isOrphaned {
				metrics["Recommendation"] = "Delete Unattached Volume"
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   aws.ToString(volume.VolumeId),
				ResourceType: "EBS_VOLUME",
				Region:       aws.ToString(volume.AvailabilityZone),
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
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

			desc := aws.ToString(snap.Description)

			// A common FinOps pattern: If the snapshot was created by an AMI (starts with "Created by CreateImage"),
			// but it's not currently being used, it's a candidate for deletion.
			// For MVP, we flag snapshots that aren't tied to active AMIs or are just generally extremely old backups.
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
				"SizeGB":               sizeGB,
				"Description":          desc,
				"EstimatedMonthlyCost": cost,
			}
			if isOrphaned {
				metrics["Recommendation"] = "Review and Delete Old Snapshot"
			}

			results = append(results, scanner.ScanResult{
				ResourceID:   aws.ToString(snap.SnapshotId),
				ResourceType: "EBS_SNAPSHOT",
				Region:       "global", // Snapshots are regional, but not bound to an AZ like volumes
				IsOrphaned:   isOrphaned,
				Metrics:      metrics,
			})
		}
	}

	return results, nil
}
