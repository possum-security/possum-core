package secaas

import (
	"context"
	"fmt"

	graph "github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/glue/types"
)

// GlueClient defines the mockable interface for AWS Glue API calls.
type GlueClient interface {
	GetDataCatalogEncryptionSettings(ctx context.Context, params *glue.GetDataCatalogEncryptionSettingsInput, optFns ...func(*glue.Options)) (*glue.GetDataCatalogEncryptionSettingsOutput, error)
	GetDevEndpoints(ctx context.Context, params *glue.GetDevEndpointsInput, optFns ...func(*glue.Options)) (*glue.GetDevEndpointsOutput, error)
}

// GlueScanner evaluates security posture for AWS Glue Data Catalog and Development Endpoints.
type GlueScanner struct {
	client GlueClient
	region string
}

// NewGlueScanner creates a new GlueScanner with AWS config.
func NewGlueScanner(cfg aws.Config) *GlueScanner {
	return &GlueScanner{
		client: glue.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewGlueScannerWithClient creates a scanner with custom/mock client.
func NewGlueScannerWithClient(client GlueClient, region string) *GlueScanner {
	return &GlueScanner{
		client: client,
		region: region,
	}
}

func (s *GlueScanner) Name() string {
	return "Glue-SecaaS-Scanner"
}

func (s *GlueScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}

	region := s.region
	if region == "" {
		region = "global"
	}

	var results []scanner.ScanResult
	catalogResourceID := fmt.Sprintf("glue-data-catalog-%s", region)
	catalogNode := []graph.Node{{ID: catalogResourceID, NodeType: "SecaaS-Glue"}}

	// 1. Data Catalog Encryption Settings
	var encSettings *types.DataCatalogEncryptionSettings
	encOut, err := s.client.GetDataCatalogEncryptionSettings(ctx, &glue.GetDataCatalogEncryptionSettingsInput{})
	if err == nil && encOut != nil {
		encSettings = encOut.DataCatalogEncryptionSettings
	}

	// 1a. Metadata Encryption: glue_data_catalogs_metadata_encryption_enabled & glue_data_catalogs_metadata_encryption_enabled
	metadataEncrypted := false
	var encMode string
	if encSettings != nil && encSettings.EncryptionAtRest != nil {
		mode := encSettings.EncryptionAtRest.CatalogEncryptionMode
		encMode = string(mode)
		if mode != "" && mode != types.CatalogEncryptionModeDisabled {
			metadataEncrypted = true
		}
	}

	if metadataEncrypted {
		passMetrics := map[string]interface{}{
			"CatalogEncryptionMode": encMode,
			"StatusExtended":        fmt.Sprintf("AWS Glue Data Catalog metadata encryption is enabled in region %s (mode: %s).", region, encMode),
		}
		results = append(results,
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "PASS",
				RuleID:       "glue_data_catalogs_metadata_encryption_enabled",
				Severity:     "INFO",
				Metrics:      passMetrics,
				Nodes:        catalogNode,
			},
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "PASS",
				RuleID:       "glue_data_catalogs_metadata_encryption_enabled",
				Severity:     "INFO",
				Metrics:      passMetrics,
				Nodes:        catalogNode,
			},
		)
	} else {
		failMetrics := map[string]interface{}{
			"StatusExtended": fmt.Sprintf("AWS Glue Data Catalog metadata encryption is not enabled in region %s.", region),
			"SecurityIssues": []string{"AWS Glue Data Catalog metadata encryption at rest is disabled"},
			"Recommendation": "Enable metadata encryption with SSE-KMS in Glue Data Catalog settings.",
		}
		results = append(results,
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "glue_data_catalogs_metadata_encryption_enabled",
				Severity:     "HIGH",
				Metrics:      failMetrics,
				Nodes:        catalogNode,
			},
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "glue_data_catalogs_metadata_encryption_enabled",
				Severity:     "HIGH",
				Metrics:      failMetrics,
				Nodes:        catalogNode,
			},
		)
	}

	// 1b. Connection Password Encryption: glue_data_catalogs_connection_passwords_encryption_enabled & glue_data_catalogs_connection_passwords_encryption_enabled
	connPassEncrypted := false
	if encSettings != nil && encSettings.ConnectionPasswordEncryption != nil {
		if encSettings.ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted {
			connPassEncrypted = true
		}
	}

	if connPassEncrypted {
		passMetrics := map[string]interface{}{
			"ReturnConnectionPasswordEncrypted": true,
			"StatusExtended":                    fmt.Sprintf("AWS Glue Data Catalog connection passwords encryption is enabled in region %s.", region),
		}
		results = append(results,
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "PASS",
				RuleID:       "glue_data_catalogs_connection_passwords_encryption_enabled",
				Severity:     "INFO",
				Metrics:      passMetrics,
				Nodes:        catalogNode,
			},
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "PASS",
				RuleID:       "glue_data_catalogs_connection_passwords_encryption_enabled",
				Severity:     "INFO",
				Metrics:      passMetrics,
				Nodes:        catalogNode,
			},
		)
	} else {
		failMetrics := map[string]interface{}{
			"ReturnConnectionPasswordEncrypted": false,
			"StatusExtended":                    fmt.Sprintf("AWS Glue Data Catalog connection passwords encryption is not enabled in region %s.", region),
			"SecurityIssues":                    []string{"AWS Glue Data Catalog connection password encryption is disabled"},
			"Recommendation":                    "Enable connection password encryption in the Glue Data Catalog with an AWS KMS key.",
		}
		results = append(results,
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "glue_data_catalogs_connection_passwords_encryption_enabled",
				Severity:     "HIGH",
				Metrics:      failMetrics,
				Nodes:        catalogNode,
			},
			scanner.ScanResult{
				ResourceID:   catalogResourceID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "FAIL",
				RuleID:       "glue_data_catalogs_connection_passwords_encryption_enabled",
				Severity:     "HIGH",
				Metrics:      failMetrics,
				Nodes:        catalogNode,
			},
		)
	}

	// 2. Development Endpoints S3 Encryption: glue_development_endpoints_s3_encryption_enabled & glue_development_endpoints_s3_encryption_enabled
	var devEndpoints []types.DevEndpoint
	var nextToken *string
	for {
		input := &glue.GetDevEndpointsInput{
			NextToken: nextToken,
		}
		out, err := s.client.GetDevEndpoints(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to get Glue dev endpoints: %w", err)
		}
		if out != nil {
			devEndpoints = append(devEndpoints, out.DevEndpoints...)
		}
		if limit > 0 && len(devEndpoints) >= limit {
			devEndpoints = devEndpoints[:limit]
			break
		}
		if out == nil || out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}

	if len(devEndpoints) == 0 {
		// Emit regional PASS posture if no development endpoints exist
		regionalEndpointID := fmt.Sprintf("glue-dev-endpoints-%s", region)
		passMetrics := map[string]interface{}{
			"StatusExtended": fmt.Sprintf("No Glue development endpoints found in region %s.", region),
		}
		regionalNode := []graph.Node{{ID: regionalEndpointID, NodeType: "SecaaS-Glue"}}
		results = append(results,
			scanner.ScanResult{
				ResourceID:   regionalEndpointID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "PASS",
				RuleID:       "glue_development_endpoints_s3_encryption_enabled",
				Severity:     "INFO",
				Metrics:      passMetrics,
				Nodes:        regionalNode,
			},
			scanner.ScanResult{
				ResourceID:   regionalEndpointID,
				ResourceType: "SecaaS-Glue",
				Region:       region,
				Status:       "PASS",
				RuleID:       "glue_development_endpoints_s3_encryption_enabled",
				Severity:     "INFO",
				Metrics:      passMetrics,
				Nodes:        regionalNode,
			},
		)
	} else {
		for _, ep := range devEndpoints {
			endpointName := aws.ToString(ep.EndpointName)
			if endpointName == "" {
				endpointName = "unknown-endpoint"
			}
			secConfig := aws.ToString(ep.SecurityConfiguration)
			endpointNode := []graph.Node{{ID: endpointName, NodeType: "SecaaS-Glue"}}

			if ep.SecurityConfiguration != nil && *ep.SecurityConfiguration != "" {
				passMetrics := map[string]interface{}{
					"EndpointName":          endpointName,
					"SecurityConfiguration": secConfig,
					"StatusExtended":        fmt.Sprintf("Glue development endpoint '%s' has security configuration '%s' attached for S3 encryption.", endpointName, secConfig),
				}
				results = append(results,
					scanner.ScanResult{
						ResourceID:   endpointName,
						ResourceType: "SecaaS-Glue",
						Region:       region,
						Status:       "PASS",
						RuleID:       "glue_development_endpoints_s3_encryption_enabled",
						Severity:     "INFO",
						Metrics:      passMetrics,
						Nodes:        endpointNode,
					},
					scanner.ScanResult{
						ResourceID:   endpointName,
						ResourceType: "SecaaS-Glue",
						Region:       region,
						Status:       "PASS",
						RuleID:       "glue_development_endpoints_s3_encryption_enabled",
						Severity:     "INFO",
						Metrics:      passMetrics,
						Nodes:        endpointNode,
					},
				)
			} else {
				failMetrics := map[string]interface{}{
					"EndpointName":   endpointName,
					"StatusExtended": fmt.Sprintf("Glue development endpoint '%s' does not have a security configuration attached for S3 encryption.", endpointName),
					"SecurityIssues": []string{fmt.Sprintf("Glue development endpoint '%s' lacks security configuration for S3 encryption", endpointName)},
					"Recommendation": "Attach a Glue security configuration with S3 encryption enabled to the development endpoint.",
				}
				results = append(results,
					scanner.ScanResult{
						ResourceID:   endpointName,
						ResourceType: "SecaaS-Glue",
						Region:       region,
						Status:       "FAIL",
						RuleID:       "glue_development_endpoints_s3_encryption_enabled",
						Severity:     "MEDIUM",
						Metrics:      failMetrics,
						Nodes:        endpointNode,
					},
					scanner.ScanResult{
						ResourceID:   endpointName,
						ResourceType: "SecaaS-Glue",
						Region:       region,
						Status:       "FAIL",
						RuleID:       "glue_development_endpoints_s3_encryption_enabled",
						Severity:     "MEDIUM",
						Metrics:      failMetrics,
						Nodes:        endpointNode,
					},
				)
			}
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *GlueScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "glue-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "glue",
		CheckIDs:      []string{"glue_data_catalogs_connection_passwords_encryption_enabled", "glue_data_catalogs_metadata_encryption_enabled", "glue_development_endpoints_s3_encryption_enabled"},
	}
}
