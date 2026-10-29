package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scannertypes "github.com/possum-security/possum-core/pkg/scanner"
)

type mockGlueClient struct {
	getDataCatalogEncryptionSettingsOutput *glue.GetDataCatalogEncryptionSettingsOutput
	getDataCatalogEncryptionSettingsErr    error

	getDevEndpointsOutput *glue.GetDevEndpointsOutput
	getDevEndpointsErr    error
	getDevEndpointsFunc   func(ctx context.Context, params *glue.GetDevEndpointsInput) (*glue.GetDevEndpointsOutput, error)
}

func (m *mockGlueClient) GetDataCatalogEncryptionSettings(ctx context.Context, params *glue.GetDataCatalogEncryptionSettingsInput, optFns ...func(*glue.Options)) (*glue.GetDataCatalogEncryptionSettingsOutput, error) {
	if m.getDataCatalogEncryptionSettingsErr != nil {
		return nil, m.getDataCatalogEncryptionSettingsErr
	}
	return m.getDataCatalogEncryptionSettingsOutput, nil
}

func (m *mockGlueClient) GetDevEndpoints(ctx context.Context, params *glue.GetDevEndpointsInput, optFns ...func(*glue.Options)) (*glue.GetDevEndpointsOutput, error) {
	if m.getDevEndpointsFunc != nil {
		return m.getDevEndpointsFunc(ctx, params)
	}
	if m.getDevEndpointsErr != nil {
		return nil, m.getDevEndpointsErr
	}
	return m.getDevEndpointsOutput, nil
}

func TestGlueScanner_Name(t *testing.T) {
	s := NewGlueScannerWithClient(&mockGlueClient{}, "us-east-1")
	assert.Equal(t, "Glue-SecaaS-Scanner", s.Name())
}

func TestGlueScanner_NewGlueScanner(t *testing.T) {
	cfg := aws.Config{Region: "us-west-2"}
	s := NewGlueScanner(cfg)
	assert.NotNil(t, s)
	assert.Equal(t, "us-west-2", s.region)
	assert.Equal(t, "Glue-SecaaS-Scanner", s.Name())
}

func TestGlueScanner_CompliantAll(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: &types.DataCatalogEncryptionSettings{
				EncryptionAtRest: &types.EncryptionAtRest{
					CatalogEncryptionMode: types.CatalogEncryptionModeSsekms,
					SseAwsKmsKeyId:        aws.String("arn:aws:kms:us-east-1:123456789012:key/test-key"),
				},
				ConnectionPasswordEncryption: &types.ConnectionPasswordEncryption{
					ReturnConnectionPasswordEncrypted: true,
					AwsKmsKeyId:                       aws.String("arn:aws:kms:us-east-1:123456789012:key/password-key"),
				},
			},
		},
		getDevEndpointsOutput: &glue.GetDevEndpointsOutput{
			DevEndpoints: []types.DevEndpoint{
				{
					EndpointName:          aws.String("my-dev-endpoint"),
					SecurityConfiguration: aws.String("my-security-config"),
				},
			},
		},
	}

	glueScanner := NewGlueScannerWithClient(mock, "us-east-1")
	results, err := glueScanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 6)

	resultsByRule := make(map[string]scannertypes.ScanResult)
	for _, r := range results {
		assert.Equal(t, "SecaaS-Glue", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)
		assert.NotEmpty(t, r.Nodes)
		resultsByRule[r.RuleID] = r
	}

	// Catalog Metadata encryption rules
	r1, ok := resultsByRule["glue_data_catalogs_metadata_encryption_enabled"]
	require.True(t, ok)
	assert.Equal(t, "glue-data-catalog-us-east-1", r1.ResourceID)

	r2, ok := resultsByRule["glue_data_catalogs_metadata_encryption_enabled"]
	require.True(t, ok)
	assert.Equal(t, "glue-data-catalog-us-east-1", r2.ResourceID)

	// Catalog Connection Password encryption rules
	r3, ok := resultsByRule["glue_data_catalogs_connection_passwords_encryption_enabled"]
	require.True(t, ok)
	assert.Equal(t, "glue-data-catalog-us-east-1", r3.ResourceID)

	r4, ok := resultsByRule["glue_data_catalogs_connection_passwords_encryption_enabled"]
	require.True(t, ok)
	assert.Equal(t, "glue-data-catalog-us-east-1", r4.ResourceID)

	// Dev Endpoint S3 encryption rules
	r5, ok := resultsByRule["glue_development_endpoints_s3_encryption_enabled"]
	require.True(t, ok)
	assert.Equal(t, "my-dev-endpoint", r5.ResourceID)

	r6, ok := resultsByRule["glue_development_endpoints_s3_encryption_enabled"]
	require.True(t, ok)
	assert.Equal(t, "my-dev-endpoint", r6.ResourceID)
}

func TestGlueScanner_NonCompliant_DisabledAndMissing(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: &types.DataCatalogEncryptionSettings{
				EncryptionAtRest: &types.EncryptionAtRest{
					CatalogEncryptionMode: types.CatalogEncryptionModeDisabled,
				},
				ConnectionPasswordEncryption: &types.ConnectionPasswordEncryption{
					ReturnConnectionPasswordEncrypted: false,
				},
			},
		},
		getDevEndpointsOutput: &glue.GetDevEndpointsOutput{
			DevEndpoints: []types.DevEndpoint{
				{
					EndpointName:          aws.String("unencrypted-dev-endpoint"),
					SecurityConfiguration: nil,
				},
			},
		},
	}

	glueScanner := NewGlueScannerWithClient(mock, "us-west-2")
	results, err := glueScanner.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 6)

	resultsByRule := make(map[string]scannertypes.ScanResult)
	for _, r := range results {
		assert.Equal(t, "SecaaS-Glue", r.ResourceType)
		assert.Equal(t, "us-west-2", r.Region)
		assert.Equal(t, "FAIL", r.Status)
		metrics, ok := r.Metrics.(map[string]interface{})
		require.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])
		assert.NotEmpty(t, metrics["SecurityIssues"])
		resultsByRule[r.RuleID] = r
	}

	// Catalog metadata encryption should be FAIL with HIGH severity
	r1 := resultsByRule["glue_data_catalogs_metadata_encryption_enabled"]
	assert.Equal(t, "HIGH", r1.Severity)
	assert.Equal(t, "glue-data-catalog-us-west-2", r1.ResourceID)

	r2 := resultsByRule["glue_data_catalogs_metadata_encryption_enabled"]
	assert.Equal(t, "HIGH", r2.Severity)

	// Catalog connection password encryption should be FAIL with HIGH severity
	r3 := resultsByRule["glue_data_catalogs_connection_passwords_encryption_enabled"]
	assert.Equal(t, "HIGH", r3.Severity)

	r4 := resultsByRule["glue_data_catalogs_connection_passwords_encryption_enabled"]
	assert.Equal(t, "HIGH", r4.Severity)

	// Dev endpoint S3 encryption should be FAIL with MEDIUM severity
	r5 := resultsByRule["glue_development_endpoints_s3_encryption_enabled"]
	assert.Equal(t, "MEDIUM", r5.Severity)
	assert.Equal(t, "unencrypted-dev-endpoint", r5.ResourceID)

	r6 := resultsByRule["glue_development_endpoints_s3_encryption_enabled"]
	assert.Equal(t, "MEDIUM", r6.Severity)
	assert.Equal(t, "unencrypted-dev-endpoint", r6.ResourceID)
}

func TestGlueScanner_DevEndpoint_EmptySecurityConfig(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: &types.DataCatalogEncryptionSettings{
				EncryptionAtRest: &types.EncryptionAtRest{
					CatalogEncryptionMode: types.CatalogEncryptionModeSsekms,
				},
				ConnectionPasswordEncryption: &types.ConnectionPasswordEncryption{
					ReturnConnectionPasswordEncrypted: true,
				},
			},
		},
		getDevEndpointsOutput: &glue.GetDevEndpointsOutput{
			DevEndpoints: []types.DevEndpoint{
				{
					EndpointName:          aws.String("empty-sec-config-endpoint"),
					SecurityConfiguration: aws.String(""),
				},
			},
		},
	}

	glueScanner := NewGlueScannerWithClient(mock, "eu-west-1")
	results, err := glueScanner.Scan(context.Background())
	require.NoError(t, err)

	var devEndpointResults []scannertypes.ScanResult
	for _, r := range results {
		if r.RuleID == "glue_development_endpoints_s3_encryption_enabled" {
			devEndpointResults = append(devEndpointResults, r)
		}
	}

	require.Len(t, devEndpointResults, 2)
	for _, r := range devEndpointResults {
		assert.Equal(t, "FAIL", r.Status)
		assert.Equal(t, "MEDIUM", r.Severity)
		assert.Equal(t, "empty-sec-config-endpoint", r.ResourceID)
	}
}

func TestGlueScanner_NoDevEndpoints_RegionalPass(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: &types.DataCatalogEncryptionSettings{
				EncryptionAtRest: &types.EncryptionAtRest{
					CatalogEncryptionMode: types.CatalogEncryptionModeSsekms,
				},
				ConnectionPasswordEncryption: &types.ConnectionPasswordEncryption{
					ReturnConnectionPasswordEncrypted: true,
				},
			},
		},
		getDevEndpointsOutput: &glue.GetDevEndpointsOutput{
			DevEndpoints: []types.DevEndpoint{},
		},
	}

	glueScanner := NewGlueScannerWithClient(mock, "ap-southeast-2")
	results, err := glueScanner.Scan(context.Background())
	require.NoError(t, err)

	var devEndpointResults []scannertypes.ScanResult
	for _, r := range results {
		if r.RuleID == "glue_development_endpoints_s3_encryption_enabled" {
			devEndpointResults = append(devEndpointResults, r)
		}
	}

	require.Len(t, devEndpointResults, 2)
	for _, r := range devEndpointResults {
		assert.Equal(t, "PASS", r.Status)
		assert.Equal(t, "INFO", r.Severity)
		assert.Equal(t, "glue-dev-endpoints-ap-southeast-2", r.ResourceID)
	}
}

func TestGlueScanner_NilCatalogSettings(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: nil,
		},
		getDevEndpointsOutput: &glue.GetDevEndpointsOutput{
			DevEndpoints: []types.DevEndpoint{},
		},
	}

	glueScanner := NewGlueScannerWithClient(mock, "us-east-1")
	results, err := glueScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "glue_data_catalogs_metadata_encryption_enabled" ||
			r.RuleID == "glue_data_catalogs_connection_passwords_encryption_enabled" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "HIGH", r.Severity)
		}
	}
}

func TestGlueScanner_CatalogApiError(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsErr: errors.New("EntityNotFoundException: Catalog not configured"),
		getDevEndpointsOutput: &glue.GetDevEndpointsOutput{
			DevEndpoints: []types.DevEndpoint{},
		},
	}

	glueScanner := NewGlueScannerWithClient(mock, "us-east-1")
	results, err := glueScanner.Scan(context.Background())
	require.NoError(t, err)

	for _, r := range results {
		if r.RuleID == "glue_data_catalogs_metadata_encryption_enabled" ||
			r.RuleID == "glue_data_catalogs_connection_passwords_encryption_enabled" {
			assert.Equal(t, "FAIL", r.Status)
			assert.Equal(t, "HIGH", r.Severity)
		}
	}
}

func TestGlueScanner_GetDevEndpointsError(t *testing.T) {
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: &types.DataCatalogEncryptionSettings{},
		},
		getDevEndpointsErr: errors.New("AccessDeniedException: not authorized"),
	}

	glueScanner := NewGlueScannerWithClient(mock, "us-east-1")
	_, err := glueScanner.Scan(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get Glue dev endpoints")
}

func TestGlueScanner_PaginationAndResourceLimit(t *testing.T) {
	callCount := 0
	mock := &mockGlueClient{
		getDataCatalogEncryptionSettingsOutput: &glue.GetDataCatalogEncryptionSettingsOutput{
			DataCatalogEncryptionSettings: &types.DataCatalogEncryptionSettings{
				EncryptionAtRest: &types.EncryptionAtRest{
					CatalogEncryptionMode: types.CatalogEncryptionModeSsekms,
				},
				ConnectionPasswordEncryption: &types.ConnectionPasswordEncryption{
					ReturnConnectionPasswordEncrypted: true,
				},
			},
		},
		getDevEndpointsFunc: func(ctx context.Context, params *glue.GetDevEndpointsInput) (*glue.GetDevEndpointsOutput, error) {
			callCount++
			if params.NextToken == nil {
				return &glue.GetDevEndpointsOutput{
					DevEndpoints: []types.DevEndpoint{
						{EndpointName: aws.String("endpoint-1"), SecurityConfiguration: aws.String("sec-1")},
						{EndpointName: aws.String("endpoint-2"), SecurityConfiguration: aws.String("sec-2")},
					},
					NextToken: aws.String("page2-token"),
				}, nil
			}
			return &glue.GetDevEndpointsOutput{
				DevEndpoints: []types.DevEndpoint{
					{EndpointName: aws.String("endpoint-3"), SecurityConfiguration: aws.String("sec-3")},
				},
				NextToken: nil,
			}, nil
		},
	}

	// With ResourceLimit = 2
	ctx := context.WithValue(context.Background(), "ResourceLimit", 2)
	glueScanner := NewGlueScannerWithClient(mock, "us-east-1")
	results, err := glueScanner.Scan(ctx)
	require.NoError(t, err)

	endpointResults := 0
	for _, r := range results {
		if r.RuleID == "glue_development_endpoints_s3_encryption_enabled" {
			endpointResults++
		}
	}
	assert.Equal(t, 4, endpointResults)
	assert.Equal(t, 1, callCount) // Should stop after first page reaches limit 2
}
