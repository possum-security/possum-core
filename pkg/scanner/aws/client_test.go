package aws

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientConfig(t *testing.T) {
	origMock := os.Getenv("AWS_MOCK_MODE")
	origEndpoint := os.Getenv("AWS_ENDPOINT_URL")
	defer func() {
		os.Setenv("AWS_MOCK_MODE", origMock)
		os.Setenv("AWS_ENDPOINT_URL", origEndpoint)
	}()

	os.Setenv("AWS_MOCK_MODE", "true")
	os.Setenv("AWS_ENDPOINT_URL", "http://localhost:4566")

	ctx := context.Background()
	opts := ClientOptions{
		Region:    "us-west-2",
		AccountID: "123456789012",
	}

	cfg, err := NewClientConfig(ctx, opts)
	require.NoError(t, err)
	assert.Equal(t, "us-west-2", cfg.Region)
	assert.NotNil(t, cfg.Credentials)

	creds, err := cfg.Credentials.Retrieve(ctx)
	require.NoError(t, err)
	assert.Equal(t, "MOCK_AWS_KEY", creds.AccessKeyID)
}
