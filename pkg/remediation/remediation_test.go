package remediation

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
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
	assert.Contains(t, actions[0].CLICommand, "'public-bucket-prod'")

	assert.Equal(t, "ebs_volume_unused_attached", actions[1].RuleID)
	assert.Contains(t, actions[1].CLICommand, "aws ec2 delete-volume --volume-id 'vol-0987654321'")

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
	assert.NotContains(t, script, "eval ")
}

func TestRemediation_PreventsShellInjection(t *testing.T) {
	tmpDir := t.TempDir()
	pwnedCmdSub := filepath.Join(tmpDir, "pwned_cmdsub")
	pwnedBacktick := filepath.Join(tmpDir, "pwned_backtick")
	pwnedQuote := filepath.Join(tmpDir, "pwned_quote")
	pwnedFreeText := filepath.Join(tmpDir, "pwned_freetext")
	awsLogFile := filepath.Join(tmpDir, "aws_args.log")

	// Create a stub aws executable in tmpDir so the script's `command -v aws` check succeeds
	// and we can run the full bash script in both DryRun: true and DryRun: false.
	mockAWS := filepath.Join(tmpDir, "aws")
	mockAWSScript := "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> " + shellQuote(awsLogFile) + "\n"
	require.NoError(t, os.WriteFile(mockAWS, []byte(mockAWSScript), 0755))

	results := []model.ScanResult{
		{
			RuleID:     "s3_bucket_level_public_access_block",
			ResourceID: "x$(touch " + pwnedCmdSub + ")",
			Region:     "us-east-1$(touch " + pwnedCmdSub + ")",
			Status:     model.StatusFail,
			Severity:   model.SeverityHigh,
		},
		{
			RuleID:     "ebs_volume_unused_attached",
			ResourceID: "x`touch " + pwnedBacktick + "`",
			Region:     "us-west-2",
			Status:     model.StatusFail,
			Severity:   model.SeverityMedium,
		},
		{
			RuleID:     "cloudtrail_multi_region_logging",
			ResourceID: "trail'; touch " + pwnedQuote + " #",
			Region:     "us-east-1",
			Status:     model.StatusFail,
			Severity:   model.SeverityHigh,
		},
		{
			// Untrusted free-text Remediation field must NOT be extracted as an executable command
			RuleID:      "custom_untrusted_rule",
			ResourceID:  "some-resource",
			Status:      model.StatusFail,
			Severity:    model.SeverityHigh,
			Remediation: "aws s3 ls; touch " + pwnedFreeText,
		},
	}

	gen := NewGenerator()
	actions := gen.ExtractActions(results)
	// Only the 3 known rule templates should produce actions; free-text rule must be ignored.
	require.Len(t, actions, 3)

	for _, dryRun := range []bool{true, false} {
		var buf bytes.Buffer
		err := gen.GenerateScript(&buf, actions, ScriptOptions{
			DryRun:      dryRun,
			ConfirmEach: false,
			AccountID:   "123456789012\ntouch " + pwnedCmdSub,
		})
		require.NoError(t, err)

		scriptPath := filepath.Join(tmpDir, "remediate.sh")
		require.NoError(t, os.WriteFile(scriptPath, buf.Bytes(), 0755))

		// Verify syntax with bash -n
		checkCmd := exec.Command("bash", "-n", scriptPath)
		out, err := checkCmd.CombinedOutput()
		require.NoError(t, err, "bash -n failed: %s", string(out))

		// Execute the script with mock aws in PATH
		runCmd := exec.Command("bash", scriptPath)
		runCmd.Dir = tmpDir
		runCmd.Env = append(os.Environ(), "PATH="+tmpDir+":"+os.Getenv("PATH"))
		out, err = runCmd.CombinedOutput()
		require.NoError(t, err, "script execution failed (dryRun=%v): %s", dryRun, string(out))

		// Verify none of the injection payloads executed
		assert.NoFileExists(t, pwnedCmdSub, "command substitution $(...) must not execute (dryRun=%v)", dryRun)
		assert.NoFileExists(t, pwnedBacktick, "backtick substitution must not execute (dryRun=%v)", dryRun)
		assert.NoFileExists(t, pwnedQuote, "single-quote breakout must not execute (dryRun=%v)", dryRun)
		assert.NoFileExists(t, pwnedFreeText, "free-text remediation must not execute (dryRun=%v)", dryRun)
	}

	// In DryRun=false, mock aws should have been invoked with literal arguments
	awsLog, err := os.ReadFile(awsLogFile)
	require.NoError(t, err)
	assert.Contains(t, string(awsLog), "x$(touch "+pwnedCmdSub+")")
	assert.Contains(t, string(awsLog), "x`touch "+pwnedBacktick+"`")
}
