package suppression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuppression_YAMLLoading(t *testing.T) {
	yamlData := `
suppressions:
  - rule_id: s3_bucket_level_public_access_block
    resource_id: "my-static-assets-bucket"
    reason: "Public static website assets bucket"
    expires_at: "2030-12-31"
  - rule_id: iam_root_mfa_enabled
    resource_id: "RootAccount"
    reason: "Hardware token registered separately"
`
	loader := NewLoader()
	supps, err := loader.Load(strings.NewReader(yamlData))
	require.NoError(t, err)
	require.Len(t, supps, 2)

	assert.Equal(t, "s3_bucket_level_public_access_block", supps[0].RuleID)
	assert.Equal(t, "my-static-assets-bucket", supps[0].ResourceID)
	assert.Equal(t, "Public static website assets bucket", supps[0].Reason)
	assert.Equal(t, "2030-12-31", supps[0].ExpiresAt)
}

func TestSuppression_TextLoading(t *testing.T) {
	textData := `
# Possum ignore file
s3_bucket_level_public_access_block my-static-assets-bucket 2030-12-31 Public bucket exception
ec2_security_group_open_to_world * 2020-01-01 Expired legacy exception # inline comment
`
	loader := NewLoader()
	supps, err := loader.Load(strings.NewReader(textData))
	require.NoError(t, err)
	require.Len(t, supps, 2)

	assert.Equal(t, "s3_bucket_level_public_access_block", supps[0].RuleID)
	assert.Equal(t, "my-static-assets-bucket", supps[0].ResourceID)
	assert.Equal(t, "2030-12-31", supps[0].ExpiresAt)
	assert.Equal(t, "Public bucket exception", supps[0].Reason)

	assert.Equal(t, "ec2_security_group_open_to_world", supps[1].RuleID)
	assert.Equal(t, "*", supps[1].ResourceID)
	assert.Equal(t, "2020-01-01", supps[1].ExpiresAt)
}

func TestSuppression_MatchingAndExpiry(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	activeSupp := Suppression{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "my-bucket-*",
		Reason:     "Approved exception",
		ExpiresAt:  "2026-12-31",
	}

	expiredSupp := Suppression{
		RuleID:     "ec2_security_group_open_to_world",
		ResourceID: "*",
		Reason:     "Temporary dev bypass",
		ExpiresAt:  "2026-01-01",
	}

	assert.False(t, activeSupp.IsExpired(now))
	assert.True(t, expiredSupp.IsExpired(now))

	results := []model.ScanResult{
		{
			RuleID:     "s3_bucket_level_public_access_block",
			ResourceID: "my-bucket-logs",
			Status:     model.StatusFail,
			Severity:   model.SeverityHigh,
		},
		{
			RuleID:     "ec2_security_group_open_to_world",
			ResourceID: "sg-12345",
			Status:     model.StatusFail,
			Severity:   model.SeverityCritical,
		},
		{
			RuleID:     "iam_root_mfa_enabled",
			ResourceID: "RootAccount",
			Status:     model.StatusFail,
			Severity:   model.SeverityCritical,
		},
	}

	filtered := ApplySuppressionsAt(results, []Suppression{activeSupp, expiredSupp}, now)

	// First finding matches active suppression -> SUPPRESSED
	assert.Equal(t, model.StatusSuppressed, filtered[0].Status)
	assert.Equal(t, "Approved exception", filtered[0].SuppressedReason)

	// Second finding matches expired suppression -> Remains FAIL
	assert.Equal(t, model.StatusFail, filtered[1].Status)

	// Third finding has no suppression -> Remains FAIL
	assert.Equal(t, model.StatusFail, filtered[2].Status)
}

func TestSuppression_NoSubstringFallbackAndARNSuffixMatching(t *testing.T) {
	// "prod" must NOT match resources merely containing "prod" as a substring
	prodSupp := Suppression{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "prod",
		Reason:     "Should only match exact 'prod'",
	}
	assert.False(t, prodSupp.Matches(model.ScanResult{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "arn:aws:s3:::my-prod-bucket",
		Metrics:    map[string]interface{}{"DisplayName": "my-prod-bucket"},
	}))
	assert.False(t, prodSupp.Matches(model.ScanResult{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "prod-logs-bucket",
	}))
	assert.True(t, prodSupp.Matches(model.ScanResult{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "arn:aws:s3:::prod",
	}))

	// ARN suffix matching after ':' or '/'
	ec2Result := model.ScanResult{
		RuleID:     "ec2_instance_public_ip",
		ResourceID: "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
	}
	assert.True(t, (Suppression{RuleID: "ec2_instance_public_ip", ResourceID: "i-123", Reason: "ok"}).Matches(ec2Result))
	assert.True(t, (Suppression{RuleID: "ec2_instance_public_ip", ResourceID: "instance/i-123", Reason: "ok"}).Matches(ec2Result))
	assert.False(t, (Suppression{RuleID: "ec2_instance_public_ip", ResourceID: "i-12", Reason: "ok"}).Matches(ec2Result))

	// DisplayName exact match
	dnResult := model.ScanResult{
		RuleID:     "rds_public",
		ResourceID: "arn:aws:rds:us-east-1:123456789012:db:mydb-instance-1",
		Metrics:    map[string]interface{}{"DisplayName": "mydb-display"},
	}
	assert.True(t, (Suppression{RuleID: "rds_public", ResourceID: "mydb-display", Reason: "ok"}).Matches(dnResult))
}

func TestSuppression_InvalidExpiresAtAndEmptyReason(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	// Unparseable expires_at must be treated as expired
	badExpirySupp := Suppression{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "*",
		Reason:     "Testing bad expiry",
		ExpiresAt:  "not-a-valid-date",
	}
	assert.True(t, badExpirySupp.IsExpired(now))

	loader := NewLoader()

	// Malformed expires_at in Load returns error
	_, err := loader.Load(strings.NewReader(`
suppressions:
  - rule_id: s3_bucket_level_public_access_block
    resource_id: "my-bucket"
    reason: "Valid reason"
    expires_at: "2026-99-99"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expires_at")

	// Empty reason in Load returns error
	_, err = loader.Load(strings.NewReader(`
suppressions:
  - rule_id: s3_bucket_level_public_access_block
    resource_id: "my-bucket"
`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reason")
}

func TestSuppression_YAMLArrayList(t *testing.T) {
	yamlList := `
- rule_id: "iam_root_mfa"
  resource_id: "*"
  reason: "Root account isolated"
`
	loader := NewLoader()
	supps, err := loader.Load(strings.NewReader(yamlList))
	require.NoError(t, err)
	require.Len(t, supps, 1)
	assert.Equal(t, "iam_root_mfa", supps[0].RuleID)
}

func TestSuppression_EmptyInput(t *testing.T) {
	loader := NewLoader()
	supps, err := loader.Load(strings.NewReader("   \n\t"))
	require.NoError(t, err)
	assert.Empty(t, supps)
}

func TestSuppression_FileLoadingAndDiscovery(t *testing.T) {
	loader := NewLoader()
	tmpDir := t.TempDir()

	// 1. LoadFile valid
	validFile := filepath.Join(tmpDir, ".possumignore")
	require.NoError(t, os.WriteFile(validFile, []byte("s3_public * 2030-01-01 Test exception\n"), 0600))
	supps, err := loader.LoadFile(validFile)
	require.NoError(t, err)
	require.Len(t, supps, 1)

	// 2. LoadFile missing
	_, err = loader.LoadFile(filepath.Join(tmpDir, "nonexistent"))
	require.Error(t, err)

	// 3. DiscoverAndLoad found
	foundSupps, path, err := loader.DiscoverAndLoad(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, validFile, path)
	assert.Len(t, foundSupps, 1)

	// 4. DiscoverAndLoad empty directory
	emptyDir := filepath.Join(tmpDir, "empty")
	require.NoError(t, os.Mkdir(emptyDir, 0700))
	noneSupps, emptyPath, err := loader.DiscoverAndLoad(emptyDir)
	require.NoError(t, err)
	assert.Empty(t, emptyPath)
	assert.Empty(t, noneSupps)
}

func TestSuppression_DatetimeFormats(t *testing.T) {
	// RFC3339 format
	supp1 := Suppression{
		RuleID:     "rule_1",
		ResourceID: "*",
		Reason:     "RFC3339 expiry",
		ExpiresAt:  "2030-01-01T12:00:00Z",
	}
	exp1, err := supp1.ParseExpiry()
	require.NoError(t, err)
	assert.Equal(t, 2030, exp1.Year())

	// Datetime format "2006-01-02 15:04:05"
	supp2 := Suppression{
		RuleID:     "rule_2",
		ResourceID: "*",
		Reason:     "DateTime format",
		ExpiresAt:  "2030-05-20 18:30:00",
	}
	exp2, err := supp2.ParseExpiry()
	require.NoError(t, err)
	assert.Equal(t, 2030, exp2.Year())
	assert.Equal(t, time.May, exp2.Month())
}

func TestSuppression_PassStatusSkipped(t *testing.T) {
	passResult := model.ScanResult{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "my-secure-bucket",
		Status:     model.StatusPass,
	}

	supp := Suppression{
		RuleID:     "s3_bucket_level_public_access_block",
		ResourceID: "*",
		Reason:     "Should not apply to PASS findings",
	}

	results := ApplySuppressionsAt([]model.ScanResult{passResult}, []Suppression{supp}, time.Now())
	assert.Equal(t, model.StatusPass, results[0].Status)
	assert.Empty(t, results[0].SuppressedReason)
}

func TestSuppression_MetadataDisplayNameAndGlobSlash(t *testing.T) {
	// Metadata display name
	res := model.ScanResult{
		RuleID:     "test_rule",
		ResourceID: "arn:aws:iam::123456789012:role/service-role/my-role",
		Status:     model.StatusFail,
		Metadata: map[string]interface{}{
			"display_name": "friendly-role-name",
		},
	}

	suppByDisplayName := Suppression{
		RuleID:     "test_rule",
		ResourceID: "friendly-role-name",
		Reason:     "Match by metadata display_name",
	}
	assert.True(t, suppByDisplayName.Matches(res))

	// Glob matching across slashes
	suppGlobSlash := Suppression{
		RuleID:     "test_rule",
		ResourceID: "*service-role*",
		Reason:     "Match wildcard inside path",
	}
	assert.True(t, suppGlobSlash.Matches(res))
}
