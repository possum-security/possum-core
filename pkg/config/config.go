package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFileNames lists candidate config files in working directory.
var DefaultConfigFileNames = []string{
	".possum.yaml",
	".possum.yml",
}

// Config represents the complete Possum configuration schema.
type Config struct {
	Version string       `yaml:"version" json:"version"`
	Scan    ScanConfig   `yaml:"scan" json:"scan"`
	Output  OutputConfig `yaml:"output" json:"output"`
	FinOps  FinOpsConfig `yaml:"finops" json:"finops"`
}

// ScanConfig specifies scanning parameters.
type ScanConfig struct {
	Regions     []string `yaml:"regions" json:"regions"`
	AllRegions  bool     `yaml:"all_regions" json:"all_regions"`
	Services    []string `yaml:"services" json:"services"`
	Checks      []string `yaml:"checks" json:"checks"`
	Compliance  string   `yaml:"compliance" json:"compliance"`
	FailOn      string   `yaml:"fail_on" json:"fail_on"`
	FailOnError bool     `yaml:"fail_on_error" json:"fail_on_error"`
	Workers     int      `yaml:"workers" json:"workers"`
	Timeout     string   `yaml:"timeout" json:"timeout"`
	Mode        string   `yaml:"mode" json:"mode"`
	IgnoreFile  string   `yaml:"ignore_file" json:"ignore_file"`
}

// OutputConfig specifies output formatting and destination.
type OutputConfig struct {
	Format     string `yaml:"format" json:"format"`
	OutputFile string `yaml:"output_file" json:"output_file"`
	NoColor    bool   `yaml:"no_color" json:"no_color"`
}

// FinOpsConfig specifies FinOps heuristics and thresholds.
type FinOpsConfig struct {
	ECRRetentionDays int     `yaml:"ecr_retention_days" json:"ecr_retention_days"`
	IdleCPUThreshold float64 `yaml:"idle_cpu_threshold" json:"idle_cpu_threshold"`
}

// TimeoutDuration parses ScanConfig.Timeout into time.Duration.
func (s ScanConfig) TimeoutDuration(defaultTimeout time.Duration) time.Duration {
	if s.Timeout == "" {
		return defaultTimeout
	}
	d, err := time.ParseDuration(s.Timeout)
	if err != nil {
		return defaultTimeout
	}
	return d
}

// Load reads and parses configuration from an io.Reader.
func Load(r io.Reader) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode configuration yaml: %w", err)
	}
	return &cfg, nil
}

// LoadFile reads and parses configuration from a file path.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %s: %w", path, err)
	}
	defer f.Close()
	return Load(f)
}

// Discover finds and loads configuration checking:
// 1. Explicit path (if provided)
// 2. Working directory (.possum.yaml, .possum.yml)
// 3. User config directory (~/.config/possum/config.yaml)
// Returns nil and empty path if no configuration file is found.
func Discover(explicitPath string) (*Config, string, error) {
	if explicitPath != "" {
		cfg, err := LoadFile(explicitPath)
		if err != nil {
			return nil, explicitPath, err
		}
		return cfg, explicitPath, nil
	}

	// Check current directory
	cwd, err := os.Getwd()
	if err == nil {
		for _, name := range DefaultConfigFileNames {
			p := filepath.Join(cwd, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				cfg, err := LoadFile(p)
				if err != nil {
					return nil, p, err
				}
				return cfg, p, nil
			}
		}
	}

	// Check ~/.config/possum/config.yaml
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		userCfg := filepath.Join(home, ".config", "possum", "config.yaml")
		if fi, err := os.Stat(userCfg); err == nil && !fi.IsDir() {
			cfg, err := LoadFile(userCfg)
			if err != nil {
				return nil, userCfg, err
			}
			return cfg, userCfg, nil
		}
	}

	return nil, "", nil
}
