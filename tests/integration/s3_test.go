//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalStack_S3Scanner(t *testing.T) {
	ctx := context.Background()
	cfg := setupLocalStack(t, ctx)

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if os.Getenv("AWS_S3_USE_PATH_STYLE") == "true" || os.Getenv("AWS_ENDPOINT_URL") != "" {
			o.UsePathStyle = true
		}
	})

	bucketName := fmt.Sprintf("possum-test-s3-%d", time.Now().UnixNano()%100000000)

	// Create test bucket (unencrypted without public access block configuration)
	_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	require.NoError(t, err, "failed to create test bucket in LocalStack")

	t.Cleanup(func() {
		_, _ = s3Client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Run S3 SecaaS scanner
	s3Scanner := secaas.NewS3Scanner(cfg)
	results, err := s3Scanner.Scan(ctx)
	require.NoError(t, err, "S3 scanner failed to execute")

	var foundEncryptionRule, foundPublicAccessBlockRule bool
	for _, res := range results {
		if res.ResourceID == bucketName {
			if res.RuleID == "s3_bucket_default_encryption" {
				foundEncryptionRule = true
			}
			if res.RuleID == "s3_bucket_level_public_access_block" {
				foundPublicAccessBlockRule = true
			}
		}
	}

	assert.True(t, foundEncryptionRule, "expected s3_bucket_default_encryption finding for %s", bucketName)
	assert.True(t, foundPublicAccessBlockRule, "expected s3_bucket_level_public_access_block finding for %s", bucketName)
}
