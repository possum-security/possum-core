package secaas

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/stretchr/testify/assert"
)

type mockOpenSearchClient struct {
	listDomainNamesOutput *opensearch.ListDomainNamesOutput
	describeDomainOutput  *opensearch.DescribeDomainOutput
	err                   error
}

func (m *mockOpenSearchClient) ListDomainNames(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.listDomainNamesOutput, nil
}

func (m *mockOpenSearchClient) DescribeDomain(ctx context.Context, params *opensearch.DescribeDomainInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.describeDomainOutput, nil
}

func TestOpenSearchScanner_Compliant(t *testing.T) {
	domain := "secure-analytics"
	mock := &mockOpenSearchClient{
		listDomainNamesOutput: &opensearch.ListDomainNamesOutput{
			DomainNames: []opensearchtypes.DomainInfo{
				{DomainName: aws.String(domain)},
			},
		},
		describeDomainOutput: &opensearch.DescribeDomainOutput{
			DomainStatus: &opensearchtypes.DomainStatus{
				ARN:        aws.String("arn:aws:es:us-east-1:123456789012:domain/secure-analytics"),
				DomainName: aws.String(domain),
				EncryptionAtRestOptions: &opensearchtypes.EncryptionAtRestOptions{
					Enabled: aws.Bool(true),
				},
				NodeToNodeEncryptionOptions: &opensearchtypes.NodeToNodeEncryptionOptions{
					Enabled: aws.Bool(true),
				},
				DomainEndpointOptions: &opensearchtypes.DomainEndpointOptions{
					EnforceHTTPS: aws.Bool(true),
				},
				VPCOptions: &opensearchtypes.VPCDerivedInfo{
					VPCId: aws.String("vpc-11223344"),
				},
				LogPublishingOptions: map[string]opensearchtypes.LogPublishingOption{
					string(opensearchtypes.LogTypeAuditLogs): {
						Enabled: aws.Bool(true),
					},
				},
				AdvancedSecurityOptions: &opensearchtypes.AdvancedSecurityOptions{
					Enabled: aws.Bool(true),
				},
			},
		},
	}

	scanner := NewOpenSearchScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 6)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status, "Expected PASS for %s", r.RuleID)
	}
}

func TestOpenSearchScanner_NonCompliant(t *testing.T) {
	domain := "legacy-search"
	mock := &mockOpenSearchClient{
		listDomainNamesOutput: &opensearch.ListDomainNamesOutput{
			DomainNames: []opensearchtypes.DomainInfo{
				{DomainName: aws.String(domain)},
			},
		},
		describeDomainOutput: &opensearch.DescribeDomainOutput{
			DomainStatus: &opensearchtypes.DomainStatus{
				ARN:        aws.String("arn:aws:es:us-east-1:123456789012:domain/legacy-search"),
				DomainName: aws.String(domain),
				EncryptionAtRestOptions: &opensearchtypes.EncryptionAtRestOptions{
					Enabled: aws.Bool(false),
				},
				NodeToNodeEncryptionOptions: &opensearchtypes.NodeToNodeEncryptionOptions{
					Enabled: aws.Bool(false),
				},
				DomainEndpointOptions: &opensearchtypes.DomainEndpointOptions{
					EnforceHTTPS: aws.Bool(false),
				},
				VPCOptions: nil, // Public / Not in VPC
				LogPublishingOptions: map[string]opensearchtypes.LogPublishingOption{
					string(opensearchtypes.LogTypeAuditLogs): {
						Enabled: aws.Bool(false),
					},
				},
				AdvancedSecurityOptions: &opensearchtypes.AdvancedSecurityOptions{
					Enabled: aws.Bool(false),
				},
			},
		},
	}

	scanner := NewOpenSearchScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 6)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "FAIL", statusMap["opensearch_service_domains_encryption_at_rest_enabled"])
	assert.Equal(t, "FAIL", statusMap["opensearch_service_domains_node_to_node_encryption_enabled"])
	assert.Equal(t, "FAIL", statusMap["opensearch_service_domains_https_communications_enforced"])
	assert.Equal(t, "FAIL", statusMap["opensearch_service_domains_not_publicly_accessible"])
	assert.Equal(t, "FAIL", statusMap["opensearch_service_domains_audit_logging_enabled"])
	assert.Equal(t, "FAIL", statusMap["opensearch_service_domains_access_control_enabled"])
}
