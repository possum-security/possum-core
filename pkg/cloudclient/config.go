package cloudclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents persistent user settings for Possum Cloud SecaaS connection.
type Config struct {
	APIKey    string `json:"api_key"`
	APIURL    string `json:"api_url"`
	AccountID string `json:"account_id,omitempty"`
}

// ConfigFilePath returns the absolute path to ~/.possum/config.json.
func ConfigFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine user home directory: %w", err)
	}
	return filepath.Join(home, ".possum", "config.json"), nil
}

// LoadConfig reads the credentials from ~/.possum/config.json.
func LoadConfig() (*Config, error) {
	path, err := ConfigFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{APIURL: "https://app.possum.io"}, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if cfg.APIURL == "" {
		cfg.APIURL = "https://app.possum.io"
	}

	return &cfg, nil
}

// SaveConfig persists the credentials into ~/.possum/config.json with restrictive permissions (0600).
func SaveConfig(cfg *Config) error {
	path, err := ConfigFilePath()
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config to %s: %w", path, err)
	}

	return nil
}

// ClearConfig removes stored credentials.
func ClearConfig() error {
	path, err := ConfigFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %w", err)
	}
	return nil
}
