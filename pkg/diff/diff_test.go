package diff

import (
	"bytes"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiff_Compare(t *testing.T) {
	baseline := []model.ScanResult{
		{
			RuleID:      "s3_bucket_level_public_access_block",
			ResourceID:  "old-bucket",
			Region:      "us-east-1",
			Status:      model.StatusFail,
			Severity:    model.SeverityHigh,
			CostWasteMo: 0,
		},
		{
			RuleID:      "ebs_volume_unused_attached",
			ResourceID:  "vol-persistent-unattached",
			Region:      "us-east-1",
			Status:      model.StatusFail,
			Severity:    model.SeverityMedium,
			CostWasteMo: 10.0,
		},
	}

	head := []model.ScanResult{
		{
			// Unchanged
			RuleID:      "ebs_volume_unused_attached",
			ResourceID:  "vol-persistent-unattached",
			Region:      "us-east-1",
			Status:      model.StatusFail,
			Severity:    model.SeverityMedium,
			CostWasteMo: 10.0,
		},
		{
			// New finding
			RuleID:      "ec2_security_group_open_to_world",
			ResourceID:  "sg-new-leak",
			Region:      "us-east-1",
			Status:      model.StatusFail,
			Severity:    model.SeverityCritical,
			CostWasteMo: 0,
		},
		{
			// New FinOps waste
			RuleID:      "ec2_elastic_ip_unassigned",
			ResourceID:  "eipalloc-orphan",
			Region:      "us-east-1",
			Status:      model.StatusFail,
			Severity:    model.SeverityLow,
			CostWasteMo: 3.65,
		},
	}

	report := Compare(baseline, head)

	assert.Equal(t, 2, report.BaselineCount)
	assert.Equal(t, 3, report.HeadCount)
	assert.Len(t, report.NewFindings, 2)
	assert.Len(t, report.ResolvedFindings, 1)
	assert.Len(t, report.UnchangedFindings, 1)

	assert.Equal(t, "s3_bucket_level_public_access_block", report.ResolvedFindings[0].RuleID)
	assert.Equal(t, 10.0, report.BaselineWaste)
	assert.InDelta(t, 13.65, report.HeadWaste, 0.001)
	assert.InDelta(t, 3.65, report.NetWasteDelta, 0.001)

	var buf bytes.Buffer
	err := report.FormatMarkdownPR(&buf)
	require.NoError(t, err)
	md := buf.String()

	assert.Contains(t, md, "Possum Cloud Security & FinOps PR Delta")
	assert.Contains(t, md, "sg-new-leak")
	assert.Contains(t, md, "old-bucket")
	assert.Contains(t, md, "+$3.65/mo waste")
}
