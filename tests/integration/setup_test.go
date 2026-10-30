//go:build integration

package integration

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func getEndpointURL() string {
	endpoint := os.Getenv("AWS_ENDPOINT_URL")
	if endpoint == "" {
		endpoint = "http://localhost:4566"
	}
	return endpoint
}

// setupLocalStack initializes AWS SDK config pointing to LocalStack.
// It verifies LocalStack reachability via HTTP health check, skipping if unavailable.
func setupLocalStack(t *testing.T, ctx context.Context) aws.Config {
	t.Helper()

	endpointURL := getEndpointURL()

	// HTTP health check
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(endpointURL + "/_localstack/health")
	if err != nil {
		t.Skipf("LocalStack not running, skipping integration tests: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Skipf("LocalStack not running, skipping integration tests (HTTP %d)", resp.StatusCode)
	}

	// Set standard test environment variables
	_ = os.Setenv("AWS_ENDPOINT_URL", endpointURL)
	_ = os.Setenv("AWS_S3_USE_PATH_STYLE", "true")
	if os.Getenv("AWS_REGION") == "" {
		_ = os.Setenv("AWS_REGION", "us-east-1")
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		_ = os.Setenv("AWS_ACCESS_KEY_ID", "test")
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		_ = os.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithBaseEndpoint(endpointURL),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
	)
	if err != nil {
		t.Fatalf("failed to load AWS config for LocalStack: %v", err)
	}

	return cfg
}
