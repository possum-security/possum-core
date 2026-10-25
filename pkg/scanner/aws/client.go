package aws

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ClientOptions configures AWS SDK client initialization.
type ClientOptions struct {
	Region     string
	RoleARN    string
	ExternalID string
	Profile    string
	AccountID  string
}

// NewClientConfig creates an AWS SDK v2 config with adaptive retry, caching, and rate throttling.
func NewClientConfig(ctx context.Context, opts ClientOptions) (aws.Config, error) {
	var loadOpts []func(*config.LoadOptions) error

	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}

	// Caching & Throttled Queueing HTTP Client layer
	accountKey := opts.AccountID
	if accountKey == "" {
		accountKey = "default"
	}

	var baseTransport http.RoundTripper = http.DefaultTransport
	if os.Getenv("AWS_DISABLE_CACHE") != "true" {
		baseTransport = GetSharedAWSCache().ForAccount(accountKey)
	}
	throttledTransport := NewThrottledTransport(baseTransport, accountKey, GetSharedAPITelemetry())
	loadOpts = append(loadOpts, config.WithHTTPClient(&http.Client{
		Transport: throttledTransport,
		Timeout:   45 * time.Second,
	}))

	// Adaptive Retryer: Client-side token rate adaptation and exponential backoff
	loadOpts = append(loadOpts, config.WithRetryer(func() aws.Retryer {
		return retry.NewAdaptiveMode(func(o *retry.AdaptiveModeOptions) {
			o.StandardOptions = []func(*retry.StandardOptions){
				func(so *retry.StandardOptions) {
					so.MaxAttempts = 5
				},
			}
		})
	}))

	// Support custom endpoint URL (e.g. LocalStack or mock AWS server)
	if endpointURL := os.Getenv("AWS_ENDPOINT_URL"); endpointURL != "" {
		loadOpts = append(loadOpts, config.WithBaseEndpoint(endpointURL))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return cfg, err
	}

	// Mock Mode for testing
	if os.Getenv("AWS_MOCK_MODE") == "true" {
		cfg.Credentials = aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider("MOCK_AWS_KEY", "MOCK_AWS_SECRET", "MOCK_SESSION_TOKEN"),
		)
		return cfg, nil
	}

	// AssumeRole if role ARN is specified
	if opts.RoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, opts.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if opts.ExternalID != "" {
				o.ExternalID = aws.String(opts.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return cfg, nil
}
