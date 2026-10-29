package tui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTUI_NavigationAndFiltering(t *testing.T) {
	findings := []model.ScanResult{
		{
			RuleID:     "s3_bucket_level_public_access_block",
			ResourceID: "my-public-bucket",
			Severity:   model.SeverityCritical,
			Status:     model.StatusFail,
			Title:      "Public S3 Bucket",
		},
		{
			RuleID:      "ebs_volume_unused_attached",
			ResourceID:  "vol-0123456789",
			Severity:    model.SeverityMedium,
			Status:      model.StatusFail,
			CostWasteMo: 20.0,
			Title:       "Unattached EBS Volume",
		},
	}

	model := NewModel(findings)
	assert.Equal(t, 2, len(model.Filtered))

	// Move down
	model.MoveDown()
	assert.Equal(t, 1, model.SelectedIndex)
	assert.Equal(t, "vol-0123456789", model.SelectedItem().ResourceID)

	// Move up
	model.MoveUp()
	assert.Equal(t, 0, model.SelectedIndex)

	// Filter CRITICAL
	model.ApplyFilter("CRITICAL")
	assert.Equal(t, 1, len(model.Filtered))
	assert.Equal(t, "my-public-bucket", model.SelectedItem().ResourceID)

	// Toggle Detail
	model.ToggleDetail()
	assert.True(t, model.ViewingDetail)

	var buf bytes.Buffer
	model.Render(&buf)
	rendered := buf.String()
	assert.Contains(t, rendered, "[DETAIL VIEW]")
	assert.Contains(t, rendered, "my-public-bucket")
	assert.Contains(t, rendered, "Public S3 Bucket")
}

func TestTUI_InteractiveInput(t *testing.T) {
	findings := []model.ScanResult{
		{RuleID: "rule1", ResourceID: "res1", Severity: "HIGH"},
		{RuleID: "rule2", ResourceID: "res2", Severity: "LOW"},
	}

	model := NewModel(findings)
	input := "j\nenter\nq\n"
	var out bytes.Buffer

	err := model.RunInteractive(strings.NewReader(input), &out)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Possum Interactive Terminal Inspector")
}
