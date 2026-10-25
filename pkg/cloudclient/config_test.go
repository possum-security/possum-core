package cloudclient

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfg := &Config{
		APIKey:    "test-key-12345",
		APIURL:    "http://localhost:8080",
		AccountID: "112233445566",
	}

	err := SaveConfig(cfg)
	require.NoError(t, err)

	loaded, err := LoadConfig()
	require.NoError(t, err)
	assert.Equal(t, cfg.APIKey, loaded.APIKey)
	assert.Equal(t, cfg.APIURL, loaded.APIURL)
	assert.Equal(t, cfg.AccountID, loaded.AccountID)

	// Check file permissions
	path, _ := ConfigFilePath()
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Test ClearConfig
	err = ClearConfig()
	require.NoError(t, err)

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))

	// Load empty config after clear
	empty, err := LoadConfig()
	require.NoError(t, err)
	assert.Empty(t, empty.APIKey)
	assert.Equal(t, "https://app.possum.io", empty.APIURL)
	_ = filepath.Separator
}
