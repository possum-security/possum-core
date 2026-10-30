package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Load(t *testing.T) {
	yamlContent := `
version: "1"
scan:
  regions: ["us-east-1", "eu-west-1"]
  services: ["s3", "iam", "ec2"]
  fail_on: "HIGH"
  fail_on_error: true
  workers: 15
  timeout: "15m"
  compliance: "cis-3.0"
output:
  format: "sarif"
  output_file: "results.sarif"
finops:
  ecr_retention_days: 90
`
	cfg, err := Load(strings.NewReader(yamlContent))
	require.NoError(t, err)
	assert.Equal(t, "1", cfg.Version)
	assert.Equal(t, []string{"us-east-1", "eu-west-1"}, cfg.Scan.Regions)
	assert.Equal(t, []string{"s3", "iam", "ec2"}, cfg.Scan.Services)
	assert.Equal(t, "HIGH", cfg.Scan.FailOn)
	assert.True(t, cfg.Scan.FailOnError)
	assert.Equal(t, 15, cfg.Scan.Workers)
	assert.Equal(t, 15*time.Minute, cfg.Scan.TimeoutDuration(time.Minute))
	assert.Equal(t, "cis-3.0", cfg.Scan.Compliance)
	assert.Equal(t, "sarif", cfg.Output.Format)
	assert.Equal(t, "results.sarif", cfg.Output.OutputFile)
	assert.Equal(t, 90, cfg.FinOps.ECRRetentionDays)
}

func TestConfig_EmptyReader(t *testing.T) {
	cfg, err := Load(strings.NewReader("   \n\t  "))
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 180, cfg.FinOps.ECRRetentionDays)
	assert.True(t, cfg.FinOps.FlagUntaggedECR)
}

func TestConfig_TimeoutDuration(t *testing.T) {
	defaultDur := 10 * time.Minute

	// Empty string fallback
	scEmpty := ScanConfig{Timeout: ""}
	assert.Equal(t, defaultDur, scEmpty.TimeoutDuration(defaultDur))

	// Invalid string fallback
	scInvalid := ScanConfig{Timeout: "invalid-duration-123"}
	assert.Equal(t, defaultDur, scInvalid.TimeoutDuration(defaultDur))

	// Valid string
	scValid := ScanConfig{Timeout: "45m"}
	assert.Equal(t, 45*time.Minute, scValid.TimeoutDuration(defaultDur))
}

func TestConfig_LoadFile(t *testing.T) {
	tmpDir := t.TempDir()
	validPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(validPath, []byte("version: '1'\nscan:\n  workers: 4\n"), 0600))

	cfg, err := LoadFile(validPath)
	require.NoError(t, err)
	assert.Equal(t, 4, cfg.Scan.Workers)

	// Non-existent file
	_, err = LoadFile(filepath.Join(tmpDir, "nonexistent.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open config file")
}

func TestConfig_DiscoverExplicit(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "custom.yaml")
	err := os.WriteFile(cfgPath, []byte("version: '1'\nscan:\n  workers: 8\n"), 0644)
	require.NoError(t, err)

	cfg, path, err := Discover(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, cfgPath, path)
	assert.Equal(t, 8, cfg.Scan.Workers)
	assert.Equal(t, 180, cfg.FinOps.ECRRetentionDays)
	assert.True(t, cfg.FinOps.FlagUntaggedECR)

	// Non-existent explicit path
	_, _, err = Discover(filepath.Join(tmpDir, "missing.yaml"))
	require.Error(t, err)
}

func TestConfig_DiscoverCwd(t *testing.T) {
	origWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(origWd)
	}()

	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))

	// Neither file present
	cfg, path, err := Discover("")
	require.NoError(t, err)
	assert.Nil(t, cfg)
	assert.Empty(t, path)

	// .possum.yaml in cwd
	yamlPath := filepath.Join(tmpDir, ".possum.yaml")
	require.NoError(t, os.WriteFile(yamlPath, []byte("version: '1'\nscan:\n  workers: 12\n"), 0600))

	cfg, path, err = Discover("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, yamlPath, path)
	assert.Equal(t, 12, cfg.Scan.Workers)
}

func TestConfig_DiscoverUserHome(t *testing.T) {
	origWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(origWd)
	}()

	tmpDir := t.TempDir()
	emptyWd := filepath.Join(tmpDir, "cwd")
	require.NoError(t, os.Mkdir(emptyWd, 0700))
	require.NoError(t, os.Chdir(emptyWd))

	fakeHome := filepath.Join(tmpDir, "home")
	configDir := filepath.Join(fakeHome, ".config", "possum")
	require.NoError(t, os.MkdirAll(configDir, 0700))
	configPath := filepath.Join(configDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("version: '1'\nscan:\n  workers: 20\n"), 0600))

	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)
	os.Setenv("HOME", fakeHome)

	cfg, path, err := Discover("")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, configPath, path)
	assert.Equal(t, 20, cfg.Scan.Workers)
}

func TestConfig_RejectsUnknownFields(t *testing.T) {
	yamlContent := `
version: "1"
scan:
  unknown_key: true
`
	_, err := Load(strings.NewReader(yamlContent))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_key")
}

func TestConfig_FinOpsFlagUntaggedECR(t *testing.T) {
	yamlContent := `
version: "1"
finops:
  ecr_retention_days: 60
  flag_untagged_ecr: false
`
	cfg, err := Load(strings.NewReader(yamlContent))
	require.NoError(t, err)
	assert.Equal(t, 60, cfg.FinOps.ECRRetentionDays)
	assert.False(t, cfg.FinOps.FlagUntaggedECR)
}
