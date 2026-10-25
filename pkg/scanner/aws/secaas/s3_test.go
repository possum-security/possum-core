package secaas_test

import (
	"context"
	"errors"
	"testing"

	"github.com/possum-sec/possum/pkg/scanner"
	"github.com/possum-sec/possum/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
)

type mockS3API struct {
	listBucketsOutput          *s3.ListBucketsOutput
	listBucketsErr             error
	getPublicAccessBlockOutput *s3.GetPublicAccessBlockOutput
	getPublicAccessBlockErr    error
	getBucketEncryptionOutput  *s3.GetBucketEncryptionOutput
	getBucketEncryptionErr     error
	getBucketVersioningOutput  *s3.GetBucketVersioningOutput
	getBucketVersioningErr     error
	getBucketLoggingOutput     *s3.GetBucketLoggingOutput
	getBucketLoggingErr        error
	getBucketPolicyOutput      *s3.GetBucketPolicyOutput
	getBucketPolicyErr         error
	getBucketAclOutput         *s3.GetBucketAclOutput
	getBucketAclErr            error
}

func (m *mockS3API) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return m.listBucketsOutput, m.listBucketsErr
}

func (m *mockS3API) GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return m.getPublicAccessBlockOutput, m.getPublicAccessBlockErr
}

func (m *mockS3API) GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return m.getBucketEncryptionOutput, m.getBucketEncryptionErr
}

func (m *mockS3API) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if m.getBucketVersioningErr != nil {
		return nil, m.getBucketVersioningErr
	}
	if m.getBucketVersioningOutput != nil {
		out := *m.getBucketVersioningOutput
		if out.MFADelete == "" {
			out.MFADelete = types.MFADeleteStatusEnabled
		}
		return &out, nil
	}
	return &s3.GetBucketVersioningOutput{
		Status:    types.BucketVersioningStatusEnabled,
		MFADelete: types.MFADeleteStatusEnabled,
	}, nil
}

func (m *mockS3API) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if m.getBucketLoggingOutput == nil {
		return &s3.GetBucketLoggingOutput{}, m.getBucketLoggingErr
	}
	return m.getBucketLoggingOutput, m.getBucketLoggingErr
}

func (m *mockS3API) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if m.getBucketPolicyErr != nil {
		return nil, m.getBucketPolicyErr
	}
	if m.getBucketPolicyOutput != nil {
		return m.getBucketPolicyOutput, nil
	}
	// Default compliant policy with secure transport denial
	return &s3.GetBucketPolicyOutput{
		Policy: aws.String(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`),
	}, nil
}

func (m *mockS3API) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if m.getBucketAclErr != nil {
		return nil, m.getBucketAclErr
	}
	if m.getBucketAclOutput != nil {
		return m.getBucketAclOutput, nil
	}
	return &s3.GetBucketAclOutput{}, nil
}

type mockS3ControlAPI struct {
	getPublicAccessBlockOutput *s3control.GetPublicAccessBlockOutput
	getPublicAccessBlockErr    error
}

func (m *mockS3ControlAPI) GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	if m.getPublicAccessBlockErr != nil {
		return nil, m.getPublicAccessBlockErr
	}
	return m.getPublicAccessBlockOutput, nil
}

func TestS3Scanner_Scan(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		ctx            context.Context
		mockAPI        *mockS3API
		expectedErr    bool
		expectedLen    int
		verifyFindings func(t *testing.T, results []scanner.ScanResult)
	}{
		{
			name: "ListBuckets error",
			mockAPI: &mockS3API{
				listBucketsErr: errors.New("API error"),
			},
			expectedErr: true,
			expectedLen: 0,
		},
		{
			name: "Fully Compliant Bucket",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("healthy-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{
					ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
						Rules: []types.ServerSideEncryptionRule{
							{
								ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
									SSEAlgorithm:   types.ServerSideEncryptionAwsKms,
									KMSMasterKeyID: aws.String("arn:aws:kms:us-east-1:123456789012:key/cmk-key-id"),
								},
							},
						},
					},
				},
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusEnabled,
					MFADelete: types.MFADeleteStatusEnabled,
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: &types.LoggingEnabled{
						TargetBucket: aws.String("audit-logs"),
						TargetPrefix: aws.String("s3/"),
					},
				},
			},
			expectedErr: false,
			expectedLen: 4,
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				for _, r := range results {
					if r.Status != "PASS" {
						t.Errorf("expected only PASS findings for compliant bucket, got %s for rule %s", r.Status, r.RuleID)
					}
				}
				if len(results) != 4 {
					t.Errorf("expected 4 PASS findings, got %d: %+v", len(results), results)
				}
			},
		},
		{
			name: "Public Access Block Missing",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("public-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:   aws.Bool(false),
						BlockPublicPolicy: aws.Bool(false),
					},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{},
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusEnabled,
					MFADelete: types.MFADeleteStatusEnabled,
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: &types.LoggingEnabled{TargetBucket: aws.String("audit-logs")},
				},
			},
			expectedErr: false,
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_level_public_access_block" {
						found = true
						if r.Severity != "HIGH" {
							t.Errorf("expected HIGH severity, got %s", r.Severity)
						}
						if len(r.Edges) == 0 {
							t.Errorf("expected edge for public access block violation")
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_level_public_access_block")
				}
			},
		},
		{
			name: "Bucket missing encryption and versioning",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("medium-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketEncryptionErr: errors.New("NoSuchEncryptionConfiguration"),
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusSuspended,
					MFADelete: types.MFADeleteStatusEnabled,
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: &types.LoggingEnabled{TargetBucket: aws.String("audit-logs")},
				},
			},
			expectedErr: false,
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				foundEncryption := false
				foundVersioning := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_default_encryption" {
						foundEncryption = true
						if r.Severity != "MEDIUM" {
							t.Errorf("expected MEDIUM severity for encryption, got %s", r.Severity)
						}
					}
					if r.RuleID == "s3_bucket_object_versioning" {
						foundVersioning = true
						if r.Severity != "MEDIUM" {
							t.Errorf("expected MEDIUM severity for versioning, got %s", r.Severity)
						}
					}
				}
				if !foundEncryption {
					t.Errorf("expected finding s3_bucket_default_encryption")
				}
				if !foundVersioning {
					t.Errorf("expected finding s3_bucket_object_versioning")
				}
			},
		},
		{
			name: "Bucket with Public Policy and Missing Logging",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("policy-logging-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{},
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusEnabled,
					MFADelete: types.MFADeleteStatusEnabled,
				},
				getBucketPolicyOutput: &s3.GetBucketPolicyOutput{
					Policy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":"*"}]}`),
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: nil,
				},
			},
			expectedErr: false,
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				foundPolicy := false
				foundLogging := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_policy_public_write_access" {
						foundPolicy = true
						if r.Severity != "CRITICAL" {
							t.Errorf("expected CRITICAL severity for policy, got %s", r.Severity)
						}
					}
					if r.RuleID == "s3_bucket_server_access_logging_enabled" {
						foundLogging = true
						if r.Severity != "MEDIUM" {
							t.Errorf("expected MEDIUM severity for logging, got %s", r.Severity)
						}
					}
				}
				if !foundPolicy {
					t.Errorf("expected finding s3_bucket_policy_public_write_access")
				}
				if !foundLogging {
					t.Errorf("expected finding s3_bucket_server_access_logging_enabled")
				}
			},
		},
		{
			name: "Resource Limit Enforced",
			ctx:  context.WithValue(context.Background(), "ResourceLimit", 2),
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{
						{Name: aws.String("bucket-1")},
						{Name: aws.String("bucket-2")},
						{Name: aws.String("bucket-3")},
					},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{},
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusEnabled,
					MFADelete: types.MFADeleteStatusEnabled,
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: nil, // each bucket emits 1 logging finding
				},
			},
			expectedErr: false,
			expectedLen: 10,
		},
		{
			name: "Missing Secure Transport Policy",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("insecure-transport-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{},
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusEnabled,
					MFADelete: types.MFADeleteStatusEnabled,
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: &types.LoggingEnabled{TargetBucket: aws.String("audit-logs")},
				},
				getBucketPolicyOutput: &s3.GetBucketPolicyOutput{
					Policy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"}]}`),
				},
			},
			expectedErr: false,
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				foundSecureTransport := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_secure_transport_policy" {
						foundSecureTransport = true
						if r.Severity != "HIGH" {
							t.Errorf("expected HIGH severity, got %s", r.Severity)
						}
					}
				}
				if !foundSecureTransport {
					t.Errorf("expected finding s3_bucket_secure_transport_policy")
				}
			},
		},
		{
			name: "Missing MFA Delete",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("no-mfa-delete-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{},
				getBucketVersioningOutput: &s3.GetBucketVersioningOutput{
					Status:    types.BucketVersioningStatusEnabled,
					MFADelete: types.MFADeleteStatusDisabled,
				},
				getBucketLoggingOutput: &s3.GetBucketLoggingOutput{
					LoggingEnabled: &types.LoggingEnabled{TargetBucket: aws.String("audit-logs")},
				},
			},
			expectedErr: false,
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				foundMFADelete := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_no_mfa_delete" {
						foundMFADelete = true
						if r.Severity != "LOW" {
							t.Errorf("expected LOW severity, got %s", r.Severity)
						}
					}
				}
				if !foundMFADelete {
					t.Errorf("expected finding s3_bucket_no_mfa_delete")
				}
			},
		},
		{
			name: "s3_bucket_public_access - Missing Public Access Block (Non-Compliant)",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("pab-missing-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(false),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_access" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "CRITICAL" {
							t.Errorf("expected CRITICAL severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Enable all S3 Block Public Access settings and restrict bucket policy." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_access")
				}
			},
		},
		{
			name: "s3_bucket_public_access - Public Bucket Policy (Non-Compliant)",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("public-policy-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
				getBucketPolicyOutput: &s3.GetBucketPolicyOutput{
					Policy: aws.String(`{"Statement":[{"Effect":"Allow","Principal":"*"}]}`),
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_access" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "CRITICAL" {
							t.Errorf("expected CRITICAL severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Enable all S3 Block Public Access settings and restrict bucket policy." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_access")
				}
			},
		},
		{
			name: "s3_bucket_public_access - Compliant",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("pab-compliant-bucket")}},
				},
				getPublicAccessBlockOutput: &s3.GetPublicAccessBlockOutput{
					PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{
						BlockPublicAcls:       aws.Bool(true),
						BlockPublicPolicy:     aws.Bool(true),
						IgnorePublicAcls:      aws.Bool(true),
						RestrictPublicBuckets: aws.Bool(true),
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_access" {
						found = true
						if r.Status != "PASS" {
							t.Errorf("expected PASS, got %s", r.Status)
						}
						if r.Severity != "INFO" {
							t.Errorf("expected INFO severity, got %s", r.Severity)
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_access")
				}
			},
		},
		{
			name: "s3_bucket_public_list_acl - Non-Compliant AllUsers READ",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("acl-list-allusers-bucket")}},
				},
				getBucketAclOutput: &s3.GetBucketAclOutput{
					Grants: []types.Grant{
						{
							Grantee: &types.Grantee{
								URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
								Type: types.TypeGroup,
							},
							Permission: types.PermissionRead,
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_list_acl" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "CRITICAL" {
							t.Errorf("expected CRITICAL severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Remove public list permissions from S3 bucket ACL." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_list_acl")
				}
			},
		},
		{
			name: "s3_bucket_public_list_acl - Non-Compliant AuthenticatedUsers FULL_CONTROL",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("acl-list-auth-bucket")}},
				},
				getBucketAclOutput: &s3.GetBucketAclOutput{
					Grants: []types.Grant{
						{
							Grantee: &types.Grantee{
								URI:  aws.String("http://acs.amazonaws.com/groups/global/AuthenticatedUsers"),
								Type: types.TypeGroup,
							},
							Permission: types.PermissionFullControl,
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_list_acl" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "CRITICAL" {
							t.Errorf("expected CRITICAL severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Remove public list permissions from S3 bucket ACL." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_list_acl")
				}
			},
		},
		{
			name: "s3_bucket_public_list_acl - Compliant Private ACL",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("acl-compliant-bucket")}},
				},
				getBucketAclOutput: &s3.GetBucketAclOutput{
					Grants: []types.Grant{
						{
							Grantee: &types.Grantee{
								ID:   aws.String("canonical-user-id"),
								Type: types.TypeCanonicalUser,
							},
							Permission: types.PermissionFullControl,
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_list_acl" {
						found = true
						if r.Status != "PASS" {
							t.Errorf("expected PASS, got %s", r.Status)
						}
						if r.Severity != "INFO" {
							t.Errorf("expected INFO severity, got %s", r.Severity)
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_list_acl")
				}
			},
		},
		{
			name: "s3_bucket_public_write_acl - Non-Compliant AllUsers WRITE",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("acl-write-allusers-bucket")}},
				},
				getBucketAclOutput: &s3.GetBucketAclOutput{
					Grants: []types.Grant{
						{
							Grantee: &types.Grantee{
								URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
								Type: types.TypeGroup,
							},
							Permission: types.PermissionWrite,
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_write_acl" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "CRITICAL" {
							t.Errorf("expected CRITICAL severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Remove public write permissions from S3 bucket ACL." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_write_acl")
				}
			},
		},
		{
			name: "s3_bucket_public_write_acl - Compliant with only READ permission",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("acl-read-only-bucket")}},
				},
				getBucketAclOutput: &s3.GetBucketAclOutput{
					Grants: []types.Grant{
						{
							Grantee: &types.Grantee{
								URI:  aws.String("http://acs.amazonaws.com/groups/global/AllUsers"),
								Type: types.TypeGroup,
							},
							Permission: types.PermissionRead,
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_public_write_acl" {
						found = true
						if r.Status != "PASS" {
							t.Errorf("expected PASS, got %s", r.Status)
						}
						if r.Severity != "INFO" {
							t.Errorf("expected INFO severity, got %s", r.Severity)
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_public_write_acl")
				}
			},
		},
		{
			name: "s3_bucket_kms_encryption - Compliant Customer-Managed KMS",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("kms-cmk-bucket")}},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{
					ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
						Rules: []types.ServerSideEncryptionRule{
							{
								ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
									SSEAlgorithm:   types.ServerSideEncryptionAwsKms,
									KMSMasterKeyID: aws.String("arn:aws:kms:us-east-1:123456789012:key/cmk-key-id"),
								},
							},
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_kms_encryption" {
						found = true
						if r.Status != "PASS" {
							t.Errorf("expected PASS, got %s", r.Status)
						}
						if r.Severity != "INFO" {
							t.Errorf("expected INFO severity, got %s", r.Severity)
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_kms_encryption")
				}
			},
		},
		{
			name: "s3_bucket_kms_encryption - Non-Compliant AES256",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("aes256-bucket")}},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{
					ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
						Rules: []types.ServerSideEncryptionRule{
							{
								ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
									SSEAlgorithm: types.ServerSideEncryptionAes256,
								},
							},
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_kms_encryption" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "HIGH" {
							t.Errorf("expected HIGH severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Encrypt S3 bucket objects using customer-managed AWS KMS keys (SSE-KMS)." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_kms_encryption")
				}
			},
		},
		{
			name: "s3_bucket_kms_encryption - Non-Compliant Default aws/s3 Key",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("default-kms-key-bucket")}},
				},
				getBucketEncryptionOutput: &s3.GetBucketEncryptionOutput{
					ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
						Rules: []types.ServerSideEncryptionRule{
							{
								ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
									SSEAlgorithm:   types.ServerSideEncryptionAwsKms,
									KMSMasterKeyID: aws.String("alias/aws/s3"),
								},
							},
						},
					},
				},
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_kms_encryption" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "HIGH" {
							t.Errorf("expected HIGH severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Encrypt S3 bucket objects using customer-managed AWS KMS keys (SSE-KMS)." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_kms_encryption")
				}
			},
		},
		{
			name: "s3_bucket_kms_encryption - Non-Compliant Unencrypted",
			mockAPI: &mockS3API{
				listBucketsOutput: &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("unencrypted-bucket")}},
				},
				getBucketEncryptionErr: errors.New("ServerSideEncryptionConfigurationNotFoundError"),
			},
			verifyFindings: func(t *testing.T, results []scanner.ScanResult) {
				found := false
				for _, r := range results {
					if r.RuleID == "s3_bucket_kms_encryption" {
						found = true
						if r.Status != "FAIL" {
							t.Errorf("expected FAIL, got %s", r.Status)
						}
						if r.Severity != "HIGH" {
							t.Errorf("expected HIGH severity, got %s", r.Severity)
						}
						if r.Metrics.(map[string]interface{})["Recommendation"] != "Encrypt S3 bucket objects using customer-managed AWS KMS keys (SSE-KMS)." {
							t.Errorf("unexpected recommendation: %v", r.Metrics.(map[string]interface{})["Recommendation"])
						}
					}
				}
				if !found {
					t.Errorf("expected finding s3_bucket_kms_encryption")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := secaas.NewS3ScannerWithClient(tt.mockAPI)

			testCtx := tt.ctx
			if testCtx == nil {
				testCtx = ctx
			}
			results, err := s.Scan(testCtx)

			if (err != nil) != tt.expectedErr {
				t.Errorf("expected err: %v, got: %v", tt.expectedErr, err)
			}

			if tt.name == "Resource Limit Enforced" {
				if len(results) != tt.expectedLen {
					t.Errorf("expected %d results, got %d", tt.expectedLen, len(results))
				}
				return
			}

			if tt.verifyFindings != nil {
				tt.verifyFindings(t, results)
			}
		})
	}
}

func TestS3Scanner_AccountLevelPublicAccessBlocks(t *testing.T) {
	mockS3 := &mockS3API{
		listBucketsOutput: &s3.ListBucketsOutput{
			Buckets: []types.Bucket{},
		},
	}
	mockControl := &mockS3ControlAPI{
		getPublicAccessBlockOutput: &s3control.GetPublicAccessBlockOutput{
			PublicAccessBlockConfiguration: &s3controltypes.PublicAccessBlockConfiguration{
				BlockPublicAcls:       aws.Bool(false),
				IgnorePublicAcls:      aws.Bool(true),
				BlockPublicPolicy:     aws.Bool(true),
				RestrictPublicBuckets: aws.Bool(true),
			},
		},
	}

	sc := secaas.NewS3ScannerWithControlClient(mockS3, mockControl, "123456789012")
	results, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundAccountPab := false
	for _, r := range results {
		if r.RuleID == "s3_account_level_public_access_blocks" {
			foundAccountPab = true
			if r.Severity != "HIGH" {
				t.Errorf("expected HIGH severity, got %s", r.Severity)
			}
		}
	}
	if !foundAccountPab {
		t.Errorf("expected finding s3_account_level_public_access_blocks")
	}
}
