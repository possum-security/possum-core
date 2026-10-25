package secaas_test

import (
	"context"
	"errors"
	"testing"

	"github.com/possum-sec/possum/pkg/scanner"
	"github.com/possum-sec/possum/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2Types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2Types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockELBv2API struct {
	describeLoadBalancersOutput          *elasticloadbalancingv2.DescribeLoadBalancersOutput
	describeLoadBalancersErr             error
	describeListenersOutput              map[string]*elasticloadbalancingv2.DescribeListenersOutput
	describeListenersErr                 error
	describeLoadBalancerAttributesOutput map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput
	describeLoadBalancerAttributesErr    error
}

func (m *mockELBv2API) DescribeLoadBalancers(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	if m.describeLoadBalancersErr != nil {
		return nil, m.describeLoadBalancersErr
	}
	if m.describeLoadBalancersOutput != nil {
		return m.describeLoadBalancersOutput, nil
	}
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{}, nil
}

func (m *mockELBv2API) DescribeListeners(ctx context.Context, params *elasticloadbalancingv2.DescribeListenersInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	if m.describeListenersErr != nil {
		return nil, m.describeListenersErr
	}
	if m.describeListenersOutput != nil {
		arn := aws.ToString(params.LoadBalancerArn)
		if out, ok := m.describeListenersOutput[arn]; ok {
			return out, nil
		}
	}
	return &elasticloadbalancingv2.DescribeListenersOutput{}, nil
}

func (m *mockELBv2API) DescribeLoadBalancerAttributes(ctx context.Context, params *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, optFns ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error) {
	if m.describeLoadBalancerAttributesErr != nil {
		return nil, m.describeLoadBalancerAttributesErr
	}
	if m.describeLoadBalancerAttributesOutput != nil {
		arn := aws.ToString(params.LoadBalancerArn)
		if out, ok := m.describeLoadBalancerAttributesOutput[arn]; ok {
			return out, nil
		}
	}
	return &elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{}, nil
}

type mockWAFv2API struct {
	getWebACLForResourceOutput map[string]*wafv2.GetWebACLForResourceOutput
	getWebACLForResourceErr    error
}

func (m *mockWAFv2API) GetWebACLForResource(ctx context.Context, params *wafv2.GetWebACLForResourceInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLForResourceOutput, error) {
	if m.getWebACLForResourceErr != nil {
		return nil, m.getWebACLForResourceErr
	}
	if m.getWebACLForResourceOutput != nil {
		arn := aws.ToString(params.ResourceArn)
		if out, ok := m.getWebACLForResourceOutput[arn]; ok {
			return out, nil
		}
	}
	return &wafv2.GetWebACLForResourceOutput{}, nil
}

func TestELBScanner_Name(t *testing.T) {
	s := secaas.NewELBScannerWithClient(&mockELBv2API{}, &mockWAFv2API{})
	assert.Equal(t, "ELB-SecaaS-Scanner", s.Name())
}

func TestELBScanner_CompliantALB_AllPass(t *testing.T) {
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/1234567890abcdef"
	albName := "prod-alb"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(albArn),
					LoadBalancerName: aws.String(albName),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
					VpcId:            aws.String("vpc-123456"),
					SecurityGroups:   []string{"sg-12345"},
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			albArn: {
				Listeners: []elbv2Types.Listener{
					{
						ListenerArn: aws.String(albArn + "/listener/443"),
						Protocol:    elbv2Types.ProtocolEnumHttps,
						Port:        aws.Int32(443),
						SslPolicy:   aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			albArn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			albArn: {
				WebACL: &wafv2Types.WebACL{
					ARN:  aws.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/prod-waf/abc-123"),
					Name: aws.String("prod-waf"),
				},
			},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF, "us-east-1")
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5, "Expected 5 distinct ScanResult controls for the ALB")

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsByRule[r.RuleID] = r
		assert.Equal(t, "PASS", r.Status, "Rule %s should PASS", r.RuleID)
		assert.Equal(t, "INFO", r.Severity, "Rule %s PASS should have INFO severity", r.RuleID)
		assert.Equal(t, albArn, r.ResourceID)
		assert.Equal(t, "SecaaS-ELB", r.ResourceType)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Len(t, r.Nodes, 1)
		assert.Equal(t, albArn, r.Nodes[0].ID)
		assert.Len(t, r.Edges, 2) // VPC and SG edges
	}

	assert.Contains(t, resultsByRule, "elbv2_ssl_listeners")
	assert.Contains(t, resultsByRule, "elbv2_insecure_ssl_ciphers")
	assert.Contains(t, resultsByRule, "elbv2_alb_drop_invalid_header_fields_enabled")
	assert.Contains(t, resultsByRule, "elbv2_logging_enabled")
	assert.Contains(t, resultsByRule, "elbv2_waf_acl_attached")
}

func TestELBScanner_NonCompliant_MissingHTTPS(t *testing.T) {
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/http-only-alb/abcdef123456"
	albName := "http-only-alb"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(albArn),
					LoadBalancerName: aws.String(albName),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			albArn: {
				Listeners: []elbv2Types.Listener{
					{
						ListenerArn: aws.String(albArn + "/listener/80"),
						Protocol:    elbv2Types.ProtocolEnumHttp,
						Port:        aws.Int32(80),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			albArn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			albArn: {
				WebACL: &wafv2Types.WebACL{ARN: aws.String("arn:aws:wafv2:us-east-1:123:regional/webacl/waf1/id")},
			},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 5)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsByRule[r.RuleID] = r
	}

	// elbv2_ssl_listeners must FAIL
	sslRes := resultsByRule["elbv2_ssl_listeners"]
	assert.Equal(t, "FAIL", sslRes.Status)
	assert.Equal(t, "HIGH", sslRes.Severity)

	// Other rules that are compliant should PASS
	assert.Equal(t, "PASS", resultsByRule["elbv2_insecure_ssl_ciphers"].Status)
	assert.Equal(t, "PASS", resultsByRule["elbv2_alb_drop_invalid_header_fields_enabled"].Status)
	assert.Equal(t, "PASS", resultsByRule["elbv2_logging_enabled"].Status)
	assert.Equal(t, "PASS", resultsByRule["elbv2_waf_acl_attached"].Status)
}

func TestELBScanner_NonCompliant_InsecureSSLCiphers(t *testing.T) {
	weakPolicies := []string{
		"ELBSecurityPolicy-2016-08",
		"ELBSecurityPolicy-TLS-1-0-2015-04",
		"ELBSecurityPolicy-TLS-1-1-2017-01",
		"ELBSecurityPolicy-2015-05",
	}

	for _, policy := range weakPolicies {
		t.Run("Policy_"+policy, func(t *testing.T) {
			albArn := "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/weak-cipher-alb/aabbccddeeff"
			albName := "weak-cipher-alb"

			mockELB := &mockELBv2API{
				describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
					LoadBalancers: []elbv2Types.LoadBalancer{
						{
							LoadBalancerArn:  aws.String(albArn),
							LoadBalancerName: aws.String(albName),
							Type:             elbv2Types.LoadBalancerTypeEnumApplication,
						},
					},
				},
				describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
					albArn: {
						Listeners: []elbv2Types.Listener{
							{
								ListenerArn: aws.String(albArn + "/listener/443"),
								Protocol:    elbv2Types.ProtocolEnumHttps,
								Port:        aws.Int32(443),
								SslPolicy:   aws.String(policy),
							},
						},
					},
				},
				describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
					albArn: {
						Attributes: []elbv2Types.LoadBalancerAttribute{
							{
								Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
								Value: aws.String("true"),
							},
							{
								Key:   aws.String("access_logs.s3.enabled"),
								Value: aws.String("true"),
							},
						},
					},
				},
			}

			mockWAF := &mockWAFv2API{
				getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
					albArn: {
						WebACL: &wafv2Types.WebACL{ARN: aws.String("arn:aws:wafv2:us-west-2:123:regional/webacl/waf/id")},
					},
				},
			}

			scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
			results, err := scannerInstance.Scan(context.Background())
			require.NoError(t, err)
			require.Len(t, results, 5)

			resultsByRule := make(map[string]scanner.ScanResult)
			for _, r := range results {
				resultsByRule[r.RuleID] = r
			}

			// HTTPS listener is present, so elbv2_ssl_listeners must PASS
			assert.Equal(t, "PASS", resultsByRule["elbv2_ssl_listeners"].Status)

			// But weak cipher policy must FAIL
			cipherRes := resultsByRule["elbv2_insecure_ssl_ciphers"]
			assert.Equal(t, "FAIL", cipherRes.Status)
			assert.Equal(t, "HIGH", cipherRes.Severity)
		})
	}
}

func TestELBScanner_NonCompliant_DropInvalidHeadersDisabled(t *testing.T) {
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-drop-disabled/112233445566"
	albName := "alb-drop-disabled"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(albArn),
					LoadBalancerName: aws.String(albName),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			albArn: {
				Listeners: []elbv2Types.Listener{
					{
						Protocol:  elbv2Types.ProtocolEnumHttps,
						Port:      aws.Int32(443),
						SslPolicy: aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			albArn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("false"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			albArn: {
				WebACL: &wafv2Types.WebACL{ARN: aws.String("arn:aws:wafv2:us-east-1:123:regional/webacl/waf/id")},
			},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsByRule[r.RuleID] = r
	}

	dropRes := resultsByRule["elbv2_alb_drop_invalid_header_fields_enabled"]
	assert.Equal(t, "FAIL", dropRes.Status)
	assert.Equal(t, "MEDIUM", dropRes.Severity)
}

func TestELBScanner_NonCompliant_LoggingDisabled(t *testing.T) {
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-logging-disabled/998877665544"
	albName := "alb-logging-disabled"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(albArn),
					LoadBalancerName: aws.String(albName),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			albArn: {
				Listeners: []elbv2Types.Listener{
					{
						Protocol:  elbv2Types.ProtocolEnumHttps,
						Port:      aws.Int32(443),
						SslPolicy: aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			albArn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("false"),
					},
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			albArn: {
				WebACL: &wafv2Types.WebACL{ARN: aws.String("arn:aws:wafv2:us-east-1:123:regional/webacl/waf/id")},
			},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsByRule[r.RuleID] = r
	}

	logRes := resultsByRule["elbv2_logging_enabled"]
	assert.Equal(t, "FAIL", logRes.Status)
	assert.Equal(t, "MEDIUM", logRes.Severity)
}

func TestELBScanner_NonCompliant_WAFNotAttached(t *testing.T) {
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-no-waf/554433221100"
	albName := "alb-no-waf"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(albArn),
					LoadBalancerName: aws.String(albName),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			albArn: {
				Listeners: []elbv2Types.Listener{
					{
						Protocol:  elbv2Types.ProtocolEnumHttps,
						Port:      aws.Int32(443),
						SslPolicy: aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			albArn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	// WebACL is nil or returns error
	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			albArn: {
				WebACL: nil,
			},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)

	resultsByRule := make(map[string]scanner.ScanResult)
	for _, r := range results {
		resultsByRule[r.RuleID] = r
	}

	wafRes := resultsByRule["elbv2_waf_acl_attached"]
	assert.Equal(t, "FAIL", wafRes.Status)
	assert.Equal(t, "HIGH", wafRes.Severity)
}

func TestELBScanner_NonCompliant_AllChecksFail(t *testing.T) {
	// ALB 1: Missing HTTPS, drop headers disabled, logging disabled, no WAF
	alb1Arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/bad-alb-1/111111111111"
	alb1Name := "bad-alb-1"

	// ALB 2: Weak cipher policy
	alb2Arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/bad-alb-2/222222222222"
	alb2Name := "bad-alb-2"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(alb1Arn),
					LoadBalancerName: aws.String(alb1Name),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
				{
					LoadBalancerArn:  aws.String(alb2Arn),
					LoadBalancerName: aws.String(alb2Name),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			alb1Arn: {
				Listeners: []elbv2Types.Listener{
					{
						Protocol: elbv2Types.ProtocolEnumHttp,
						Port:     aws.Int32(80),
					},
				},
			},
			alb2Arn: {
				Listeners: []elbv2Types.Listener{
					{
						Protocol:  elbv2Types.ProtocolEnumHttps,
						Port:      aws.Int32(443),
						SslPolicy: aws.String("ELBSecurityPolicy-2016-08"),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			alb1Arn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("false"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("false"),
					},
				},
			},
			alb2Arn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("false"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("false"),
					},
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			alb1Arn: {WebACL: nil},
			alb2Arn: {WebACL: nil},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 10, "Expected 5 results for each of the 2 ALBs")

	alb1Results := make(map[string]scanner.ScanResult)
	alb2Results := make(map[string]scanner.ScanResult)
	for _, r := range results {
		if r.ResourceID == alb1Arn {
			alb1Results[r.RuleID] = r
		} else if r.ResourceID == alb2Arn {
			alb2Results[r.RuleID] = r
		}
	}

	// Verify ALB 1 failures
	assert.Equal(t, "FAIL", alb1Results["elbv2_ssl_listeners"].Status)
	assert.Equal(t, "FAIL", alb1Results["elbv2_alb_drop_invalid_header_fields_enabled"].Status)
	assert.Equal(t, "FAIL", alb1Results["elbv2_logging_enabled"].Status)
	assert.Equal(t, "FAIL", alb1Results["elbv2_waf_acl_attached"].Status)

	// Verify ALB 2 failures
	assert.Equal(t, "PASS", alb2Results["elbv2_ssl_listeners"].Status)
	assert.Equal(t, "FAIL", alb2Results["elbv2_insecure_ssl_ciphers"].Status)
	assert.Equal(t, "FAIL", alb2Results["elbv2_alb_drop_invalid_header_fields_enabled"].Status)
	assert.Equal(t, "FAIL", alb2Results["elbv2_logging_enabled"].Status)
	assert.Equal(t, "FAIL", alb2Results["elbv2_waf_acl_attached"].Status)
}

func TestELBScanner_SkipsNonApplicationLoadBalancers(t *testing.T) {
	nlbArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/prod-nlb/333333333333"
	albArn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb/444444444444"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(nlbArn),
					LoadBalancerName: aws.String("prod-nlb"),
					Type:             elbv2Types.LoadBalancerTypeEnumNetwork,
				},
				{
					LoadBalancerArn:  aws.String(albArn),
					LoadBalancerName: aws.String("prod-alb"),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
		describeListenersOutput: map[string]*elasticloadbalancingv2.DescribeListenersOutput{
			albArn: {
				Listeners: []elbv2Types.Listener{
					{
						Protocol:  elbv2Types.ProtocolEnumHttps,
						Port:      aws.Int32(443),
						SslPolicy: aws.String("ELBSecurityPolicy-TLS13-1-2-2021-06"),
					},
				},
			},
		},
		describeLoadBalancerAttributesOutput: map[string]*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{
			albArn: {
				Attributes: []elbv2Types.LoadBalancerAttribute{
					{
						Key:   aws.String("routing.http.drop_invalid_header_fields.enabled"),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String("access_logs.s3.enabled"),
						Value: aws.String("true"),
					},
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{
		getWebACLForResourceOutput: map[string]*wafv2.GetWebACLForResourceOutput{
			albArn: {
				WebACL: &wafv2Types.WebACL{ARN: aws.String("arn:aws:wafv2:us-east-1:123:regional/webacl/waf/id")},
			},
		},
	}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	require.NoError(t, err)

	// Only ALB should be scanned, emitting 5 results (no NLB results)
	assert.Len(t, results, 5)
	for _, r := range results {
		assert.Equal(t, albArn, r.ResourceID)
	}
}

func TestELBScanner_ResourceLimit(t *testing.T) {
	alb1Arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-1/111"
	alb2Arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/alb-2/222"

	mockELB := &mockELBv2API{
		describeLoadBalancersOutput: &elasticloadbalancingv2.DescribeLoadBalancersOutput{
			LoadBalancers: []elbv2Types.LoadBalancer{
				{
					LoadBalancerArn:  aws.String(alb1Arn),
					LoadBalancerName: aws.String("alb-1"),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
				{
					LoadBalancerArn:  aws.String(alb2Arn),
					LoadBalancerName: aws.String("alb-2"),
					Type:             elbv2Types.LoadBalancerTypeEnumApplication,
				},
			},
		},
	}

	mockWAF := &mockWAFv2API{}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	ctx := context.WithValue(context.Background(), "ResourceLimit", 1)
	results, err := scannerInstance.Scan(ctx)
	require.NoError(t, err)

	// ResourceLimit of 1 means only 1 ALB processed, producing 5 results
	assert.Len(t, results, 5)
	for _, r := range results {
		assert.Equal(t, alb1Arn, r.ResourceID)
	}
}

func TestELBScanner_DescribeLoadBalancersError(t *testing.T) {
	expectedErr := errors.New("AWS API throttling error")
	mockELB := &mockELBv2API{
		describeLoadBalancersErr: expectedErr,
	}
	mockWAF := &mockWAFv2API{}

	scannerInstance := secaas.NewELBScannerWithClient(mockELB, mockWAF)
	results, err := scannerInstance.Scan(context.Background())
	assert.ErrorIs(t, err, expectedErr)
	assert.Nil(t, results)
}

func TestELBScanner_NilClient(t *testing.T) {
	scannerInstance := secaas.NewELBScannerWithClient(nil, nil)
	results, err := scannerInstance.Scan(context.Background())
	assert.NoError(t, err)
	assert.Nil(t, results)
}
