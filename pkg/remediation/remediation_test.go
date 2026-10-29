package remediation

import (
	"bytes"
	"testing"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemediation_ExtractActionsAndGenerateScript(t *testing.T) {
	results := []model.ScanResult{
		{
			RuleID:     "s3_bucket_level_public_access_block",
			ResourceID: "public-bucket-prod",
			Region:     "us-east-1",
			Status:     model.StatusFail,
			Severity:   model.SeverityHigh,
			Title:      "Ensure S3 public access block is enabled",
		},
		{
			RuleID:      "ebs_volume_unused_attached",
			ResourceID:  "vol-0987654321",
			Region:      "us-west-2",
			Status:      model.StatusFail,
			Severity:    model.SeverityMedium,
			CostWasteMo: 15.0,
		},
		{
			// Already passing finding - should not generate action
			RuleID:     "iam_root_mfa_enabled",
			ResourceID: "RootAccount",
			Status:     model.StatusPass,
			Severity:   model.SeverityInfo,
		},
	}

	gen := NewGenerator()
	actions := gen.ExtractActions(results)

	require.Len(t, actions, 2)
	assert.Equal(t, "s3_bucket_level_public_access_block", actions[0].RuleID)
	assert.Contains(t, actions[0].CLICommand, "aws s3api put-public-access-block")
	assert.Contains(t, actions[0].CLICommand, "public-bucket-prod")

	assert.Equal(t, "ebs_volume_unused_attached", actions[1].RuleID)
	assert.Contains(t, actions[1].CLICommand, "aws ec2 delete-volume --volume-id vol-0987654321")

	var buf bytes.Buffer
	err := gen.GenerateScript(&buf, actions, ScriptOptions{
		DryRun:      true,
		ConfirmEach: true,
	})
	require.NoError(t, err)

	script := buf.String()
	assert.Contains(t, script, "#!/usr/bin/env bash")
	assert.Contains(t, script, "DRY_RUN=true")
	assert.Contains(t, script, "Apply this remediation? [y/N]")
	assert.Contains(t, script, "vol-0987654321")
}
