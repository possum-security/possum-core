package secaas

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockCloudFrontClient struct {
	listDistributionsOutput     *cloudfront.ListDistributionsOutput
	getDistributionConfigOutput map[string]*cloudfront.GetDistributionConfigOutput
	listErr                     error
	getConfigErr                error
}

func (m *mockCloudFrontClient) ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listDistributionsOutput, nil
}

func (m *mockCloudFrontClient) GetDistributionConfig(ctx context.Context, params *cloudfront.GetDistributionConfigInput, optFns ...func(*cloudfront.Options)) (*cloudfront.GetDistributionConfigOutput, error) {
	if m.getConfigErr != nil {
		return nil, m.getConfigErr
	}
	if m.getDistributionConfigOutput != nil {
		if out, ok := m.getDistributionConfigOutput[aws.ToString(params.Id)]; ok {
			return out, nil
		}
	}
	return &cloudfront.GetDistributionConfigOutput{
		DistributionConfig: &types.DistributionConfig{},
	}, nil
}

func TestCloudFrontScanner_Name(t *testing.T) {
	s := NewCloudFrontScannerWithClient(&mockCloudFrontClient{})
	assert.Equal(t, "CloudFront-SecaaS-Scanner", s.Name())
}

func TestCloudFrontScanner_Compliant(t *testing.T) {
	distID := "EDFDVBD632BHDS5"
	distARN := "arn:aws:cloudfront::123456789012:distribution/" + distID

	mock := &mockCloudFrontClient{
		listDistributionsOutput: &cloudfront.ListDistributionsOutput{
			DistributionList: &types.DistributionList{
				Items: []types.DistributionSummary{
					{
						Id:  aws.String(distID),
						ARN: aws.String(distARN),
						DefaultCacheBehavior: &types.DefaultCacheBehavior{
							ViewerProtocolPolicy: types.ViewerProtocolPolicyRedirectToHttps,
						},
						CacheBehaviors: &types.CacheBehaviors{
							Items: []types.CacheBehavior{
								{
									ViewerProtocolPolicy: types.ViewerProtocolPolicyHttpsOnly,
								},
							},
						},
						ViewerCertificate: &types.ViewerCertificate{
							MinimumProtocolVersion:       types.MinimumProtocolVersionTLSv122021,
							ACMCertificateArn:            aws.String("arn:aws:acm:us-east-1:123456789012:certificate/abc-123"),
							CloudFrontDefaultCertificate: aws.Bool(false),
						},
						Restrictions: &types.Restrictions{
							GeoRestriction: &types.GeoRestriction{
								RestrictionType: types.GeoRestrictionTypeWhitelist,
							},
						},
						OriginGroups: &types.OriginGroups{
							Quantity: aws.Int32(2),
						},
						WebACLId: aws.String("arn:aws:wafv2:us-east-1:123456789012:global/webacl/my-waf/123"),
					},
				},
			},
		},
		getDistributionConfigOutput: map[string]*cloudfront.GetDistributionConfigOutput{
			distID: {
				DistributionConfig: &types.DistributionConfig{
					Logging: &types.LoggingConfig{
						Enabled: aws.Bool(true),
						Bucket:  aws.String("my-logging-bucket.s3.amazonaws.com"),
					},
				},
			},
		},
	}

	scanner := NewCloudFrontScannerWithClient(mock)
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, results, 9)

	statusMap := make(map[string]string)
	severityMap := make(map[string]string)
	for _, r := range results {
		assert.Equal(t, distID, r.ResourceID)
		assert.Equal(t, "SecaaS-CloudFront", r.ResourceType)
		assert.Equal(t, "global", r.Region)
		assert.NotEmpty(t, r.Nodes)
		assert.Equal(t, distARN, r.Nodes[0].ID)
		assert.Equal(t, "SecaaS-CloudFront", r.Nodes[0].NodeType)

		metrics, ok := r.Metrics.(map[string]interface{})
		assert.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])

		statusMap[r.RuleID] = r.Status
		severityMap[r.RuleID] = r.Severity
	}

	expectedRules := []string{
		"cloudfront_distributions_https_enabled",
		"cloudfront_distributions_using_deprecated_ssl_protocols",
		"cloudfront_distributions_using_deprecated_ssl_protocols",
		"cloudfront_distributions_geo_restrictions_enabled",
		"cloudfront_distributions_custom_ssl_certificate",
		"cloudfront_distributions_multiple_origin_failover_configured",
		"cloudfront_distributions_multiple_origin_failover_configured",
		"cloudfront_distributions_using_waf",
		"cloudfront_distributions_logging_enabled",
	}

	for _, ruleID := range expectedRules {
		assert.Equal(t, "PASS", statusMap[ruleID], "Expected PASS for %s", ruleID)
		assert.Equal(t, "INFO", severityMap[ruleID], "Expected INFO severity for PASS rule %s", ruleID)
	}
}

func TestCloudFrontScanner_NonCompliant(t *testing.T) {
	distID := "NONCOMPLIANT123"

	mock := &mockCloudFrontClient{
		listDistributionsOutput: &cloudfront.ListDistributionsOutput{
			DistributionList: &types.DistributionList{
				Items: []types.DistributionSummary{
					{
						Id: aws.String(distID),
						DefaultCacheBehavior: &types.DefaultCacheBehavior{
							ViewerProtocolPolicy: types.ViewerProtocolPolicyAllowAll,
						},
						CacheBehaviors: &types.CacheBehaviors{
							Items: []types.CacheBehavior{
								{
									ViewerProtocolPolicy: types.ViewerProtocolPolicyAllowAll,
								},
							},
						},
						ViewerCertificate: &types.ViewerCertificate{
							MinimumProtocolVersion:       types.MinimumProtocolVersionTLSv1,
							CloudFrontDefaultCertificate: aws.Bool(true),
						},
						Restrictions: &types.Restrictions{
							GeoRestriction: &types.GeoRestriction{
								RestrictionType: types.GeoRestrictionTypeNone,
							},
						},
						OriginGroups: &types.OriginGroups{
							Quantity: aws.Int32(0),
						},
						WebACLId: nil,
					},
				},
			},
		},
		getDistributionConfigOutput: map[string]*cloudfront.GetDistributionConfigOutput{
			distID: {
				DistributionConfig: &types.DistributionConfig{
					Logging: &types.LoggingConfig{
						Enabled: aws.Bool(false),
					},
				},
			},
		},
	}

	scanner := NewCloudFrontScannerWithClient(mock)
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, results, 9)

	statusMap := make(map[string]string)
	severityMap := make(map[string]string)
	for _, r := range results {
		assert.Equal(t, distID, r.ResourceID)
		assert.Equal(t, "SecaaS-CloudFront", r.ResourceType)
		assert.Equal(t, "global", r.Region)
		assert.NotEmpty(t, r.Nodes)
		assert.Equal(t, "arn:aws:cloudfront:::distribution/"+distID, r.Nodes[0].ID)

		metrics, ok := r.Metrics.(map[string]interface{})
		assert.True(t, ok)
		assert.NotEmpty(t, metrics["StatusExtended"])
		assert.NotEmpty(t, metrics["Recommendation"])
		assert.NotEmpty(t, metrics["SecurityIssues"])

		statusMap[r.RuleID] = r.Status
		severityMap[r.RuleID] = r.Severity
	}

	expectedSeverities := map[string]string{
		"cloudfront_distributions_https_enabled":                       "HIGH",
		"cloudfront_distributions_using_deprecated_ssl_protocols":      "HIGH",
		"cloudfront_distributions_geo_restrictions_enabled":            "LOW",
		"cloudfront_distributions_custom_ssl_certificate":              "MEDIUM",
		"cloudfront_distributions_multiple_origin_failover_configured": "LOW",
		"cloudfront_distributions_using_waf":                           "HIGH",
		"cloudfront_distributions_logging_enabled":                     "LOW",
	}

	for ruleID, expectedSev := range expectedSeverities {
		assert.Equal(t, "FAIL", statusMap[ruleID], "Expected FAIL for %s", ruleID)
		assert.Equal(t, expectedSev, severityMap[ruleID], "Expected %s severity for FAIL rule %s", expectedSev, ruleID)
	}
}

func TestCloudFrontScanner_PartialCompliance(t *testing.T) {
	// Case 1: Additional cache behavior allows HTTP even if default redirects to HTTPS
	// Case 2: Custom IAM certificate satisfies custom SSL check
	// Case 3: TLS 1.3 satisfies TLS check
	distID := "PARTIAL123"

	mock := &mockCloudFrontClient{
		listDistributionsOutput: &cloudfront.ListDistributionsOutput{
			DistributionList: &types.DistributionList{
				Items: []types.DistributionSummary{
					{
						Id: aws.String(distID),
						DefaultCacheBehavior: &types.DefaultCacheBehavior{
							ViewerProtocolPolicy: types.ViewerProtocolPolicyRedirectToHttps,
						},
						CacheBehaviors: &types.CacheBehaviors{
							Items: []types.CacheBehavior{
								{
									ViewerProtocolPolicy: types.ViewerProtocolPolicyAllowAll,
								},
							},
						},
						ViewerCertificate: &types.ViewerCertificate{
							MinimumProtocolVersion: types.MinimumProtocolVersionTLSv132025,
							IAMCertificateId:       aws.String("IAMCERT987654321"),
						},
						Restrictions: &types.Restrictions{
							GeoRestriction: &types.GeoRestriction{
								RestrictionType: types.GeoRestrictionTypeBlacklist,
							},
						},
						OriginGroups: &types.OriginGroups{
							Quantity: aws.Int32(1),
						},
						WebACLId: aws.String("web-acl-id"),
					},
				},
			},
		},
		getDistributionConfigOutput: map[string]*cloudfront.GetDistributionConfigOutput{
			distID: {
				DistributionConfig: &types.DistributionConfig{
					Logging: nil,
				},
			},
		},
	}

	scanner := NewCloudFrontScannerWithClient(mock)
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, results, 9)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	// HTTPS fails due to cache behavior allow-all
	assert.Equal(t, "FAIL", statusMap["cloudfront_distributions_https_enabled"])
	// TLS passes due to TLS 1.3
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_using_deprecated_ssl_protocols"])
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_using_deprecated_ssl_protocols"])
	// Custom SSL passes due to IAM certificate
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_custom_ssl_certificate"])
	// Geo restrictions pass due to blacklist
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_geo_restrictions_enabled"])
	// Origin failover passes
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_multiple_origin_failover_configured"])
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_multiple_origin_failover_configured"])
	// WAF passes
	assert.Equal(t, "PASS", statusMap["cloudfront_distributions_using_waf"])
	// Logging fails (nil config)
	assert.Equal(t, "FAIL", statusMap["cloudfront_distributions_logging_enabled"])
}

func TestCloudFrontScanner_EmptyDistributions(t *testing.T) {
	mock := &mockCloudFrontClient{
		listDistributionsOutput: &cloudfront.ListDistributionsOutput{
			DistributionList: &types.DistributionList{
				Items: []types.DistributionSummary{},
			},
		},
	}

	scanner := NewCloudFrontScannerWithClient(mock)
	results, err := scanner.Scan(context.Background())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestCloudFrontScanner_ResourceLimit(t *testing.T) {
	mock := &mockCloudFrontClient{
		listDistributionsOutput: &cloudfront.ListDistributionsOutput{
			DistributionList: &types.DistributionList{
				Items: []types.DistributionSummary{
					{Id: aws.String("DIST-1")},
					{Id: aws.String("DIST-2")},
					{Id: aws.String("DIST-3")},
				},
			},
		},
	}

	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	scanner := NewCloudFrontScannerWithClient(mock)
	results, err := scanner.Scan(ctx)
	require.NoError(t, err)
	assert.Len(t, results, 9) // 1 distribution x 9 checks
}

func TestCloudFrontScanner_ListError(t *testing.T) {
	mock := &mockCloudFrontClient{
		listErr: errors.New("access denied listing distributions"),
	}

	scanner := NewCloudFrontScannerWithClient(mock)
	_, err := scanner.Scan(context.Background())
	assert.Error(t, err)
}

func TestCloudFrontScanner_GetConfigError(t *testing.T) {
	mock := &mockCloudFrontClient{
		listDistributionsOutput: &cloudfront.ListDistributionsOutput{
			DistributionList: &types.DistributionList{
				Items: []types.DistributionSummary{
					{Id: aws.String("DIST-1")},
				},
			},
		},
		getConfigErr: errors.New("error fetching config"),
	}

	scanner := NewCloudFrontScannerWithClient(mock)
	_, err := scanner.Scan(context.Background())
	assert.Error(t, err)
}
