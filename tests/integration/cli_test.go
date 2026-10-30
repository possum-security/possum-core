//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/possum-security/possum-core/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalStack_CLI_ScanAWS_S3_JSON(t *testing.T) {
	ctx := context.Background()
	cfg := setupLocalStack(t, ctx)

	endpointURL := getEndpointURL()

	// Seed test bucket in LocalStack
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if os.Getenv("AWS_S3_USE_PATH_STYLE") == "true" || os.Getenv("AWS_ENDPOINT_URL") != "" {
			o.UsePathStyle = true
		}
	})

	bucketName := fmt.Sprintf("possum-cli-test-%d", time.Now().UnixNano()%100000000)
	_, err := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	require.NoError(t, err, "failed to create test bucket in LocalStack")

	t.Cleanup(func() {
		_, _ = s3Client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucketName),
		})
	})

	// Locate or build possum binary
	binPath := filepath.Join(t.TempDir(), "possum")
	buildCmd := exec.Command("go", "build", "-o", binPath, "github.com/possum-security/possum-core/cmd/possum")
	buildOut, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "failed to build possum binary: %s", string(buildOut))

	// Execute: possum scan aws --services s3 --regions us-east-1 --format json
	cmd := exec.Command(binPath, "scan", "aws", "--services", "s3", "--regions", "us-east-1", "--format", "json")
	cmd.Env = append(os.Environ(),
		"AWS_ENDPOINT_URL="+endpointURL,
		"AWS_REGION=us-east-1",
		"AWS_ACCESS_KEY_ID=test",
		"AWS_SECRET_ACCESS_KEY=test",
		"AWS_S3_USE_PATH_STYLE=true",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	require.NoError(t, err, "CLI scan aws command failed. stderr: %s", stderr.String())

	// Validate JSON output structure
	var envelope output.JSONEnvelope
	err = json.Unmarshal(stdout.Bytes(), &envelope)
	require.NoError(t, err, "failed to parse CLI JSON output: %s", stdout.String())

	assert.Equal(t, "1.0", envelope.SchemaVersion)
	assert.NotEmpty(t, envelope.Results, "expected non-empty results array in JSON output")
	assert.Greater(t, envelope.Summary.TotalEvaluated, 0, "expected total evaluated > 0 in summary")

	// Ensure our seeded bucket appears in the findings
	var foundBucket bool
	for _, res := range envelope.Results {
		if res.ResourceID == bucketName || strings.Contains(res.ResourceID, bucketName) {
			foundBucket = true
			break
		}
	}
	assert.True(t, foundBucket, "expected seeded bucket %s in CLI scan results", bucketName)
}
