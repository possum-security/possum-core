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

func TestConfig_DiscoverExplicit(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "custom.yaml")
	err := os.WriteFile(cfgPath, []byte("version: '1'\nscan:\n  workers: 8\n"), 0644)
	require.NoError(t, err)

	cfg, path, err := Discover(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, cfgPath, path)
	assert.Equal(t, 8, cfg.Scan.Workers)
}
