package secaas

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
)

type S3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketEncryption(ctx context.Context, params *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error)
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
}

type S3ControlAPI interface {
	GetPublicAccessBlock(ctx context.Context, params *s3control.GetPublicAccessBlockInput, optFns ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error)
}

type S3Scanner struct {
	client        S3API
	controlClient S3ControlAPI
	accountID     string
}

func NewS3Scanner(cfg aws.Config) *S3Scanner {
	return &S3Scanner{
		client:        s3.NewFromConfig(cfg),
		controlClient: s3control.NewFromConfig(cfg),
	}
}

// NewS3ScannerWithClient allows injecting a custom client (e.g. mock)
func NewS3ScannerWithClient(client S3API) *S3Scanner {
	return &S3Scanner{
		client: client,
	}
}

// NewS3ScannerWithControlClient allows injecting S3 and S3Control mock clients
func NewS3ScannerWithControlClient(client S3API, controlClient S3ControlAPI, accountID string) *S3Scanner {
	return &S3Scanner{
		client:        client,
		controlClient: controlClient,
		accountID:     accountID,
	}
}

func (s *S3Scanner) Name() string {
	return "S3-SecaaS-Scanner"
}

func (s *S3Scanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult
	output, err := s.client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	for _, bucket := range output.Buckets {
		if limit > 0 && processedCount >= limit {
			break
		}
		processedCount++

		bucketName := aws.ToString(bucket.Name)

		// 1. Check public access block (s3_bucket_level_public_access_block - HIGH)
		pubAccess, pubAccessErr := s.client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: aws.String(bucketName),
		})
		hasFullPAB := pubAccessErr == nil && pubAccess != nil && pubAccess.PublicAccessBlockConfiguration != nil &&
			aws.ToBool(pubAccess.PublicAccessBlockConfiguration.BlockPublicAcls) &&
			aws.ToBool(pubAccess.PublicAccessBlockConfiguration.IgnorePublicAcls) &&
			aws.ToBool(pubAccess.PublicAccessBlockConfiguration.BlockPublicPolicy) &&
			aws.ToBool(pubAccess.PublicAccessBlockConfiguration.RestrictPublicBuckets)

		if !hasFullPAB {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_level_public_access_block",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("Block Public Access is not configured for S3 bucket %s.", bucketName),
					"Recommendation": "Enable all 4 S3 Block Public Access settings at the bucket level.",
					"SecurityIssues": []string{"Public access block is missing or incomplete"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
				Edges: []graph.Edge{
					{
						From:     "Internet",
						To:       bucketName,
						Relation: "ROUTES_TO",
					},
				},
			})
		}

		// 2. Check server-side encryption (s3_bucket_default_encryption - MEDIUM) & KMS CMK (s3_bucket_kms_encryption - HIGH)
		encOutput, encErr := s.client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: aws.String(bucketName),
		})
		if encErr != nil {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_default_encryption",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not have default server-side encryption enabled.", bucketName),
					"Recommendation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) for the S3 bucket.",
					"SecurityIssues": []string{"Missing server-side encryption"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		hasKmsCMK := false
		if encErr == nil && encOutput != nil && encOutput.ServerSideEncryptionConfiguration != nil {
			for _, r := range encOutput.ServerSideEncryptionConfiguration.Rules {
				if r.ApplyServerSideEncryptionByDefault != nil {
					algo := string(r.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
					kmsKey := aws.ToString(r.ApplyServerSideEncryptionByDefault.KMSMasterKeyID)
					if (algo == "aws:kms" || algo == "aws:kms:dsse") && kmsKey != "" {
						if kmsKey != "aws/s3" && kmsKey != "alias/aws/s3" &&
							!strings.HasSuffix(kmsKey, "/aws/s3") &&
							!strings.HasSuffix(kmsKey, ":alias/aws/s3") {
							hasKmsCMK = true
							break
						}
					}
				}
			}
		}
		if hasKmsCMK {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "PASS",
				RuleID:       "s3_bucket_kms_encryption",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s is encrypted using customer-managed AWS KMS keys (SSE-KMS).", bucketName),
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_kms_encryption",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s is not encrypted using customer-managed AWS KMS keys (SSE-KMS).", bucketName),
					"Recommendation": "Encrypt S3 bucket objects using customer-managed AWS KMS keys (SSE-KMS).",
					"SecurityIssues": []string{"Bucket objects not encrypted with customer-managed KMS key"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		// 3. Check versioning (s3_bucket_object_versioning - MEDIUM) & MFA Delete (s3_bucket_no_mfa_delete - LOW)
		ver, err := s.client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil || string(ver.Status) != "Enabled" {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_object_versioning",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not have object versioning enabled.", bucketName),
					"Recommendation": "Enable object versioning for the S3 bucket to prevent accidental deletion or overwrite.",
					"SecurityIssues": []string{"Missing versioning"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}
		if ver != nil && string(ver.MFADelete) != "Enabled" {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_no_mfa_delete",
				Severity:     "LOW",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not have MFA Delete enabled.", bucketName),
					"Recommendation": "Enable MFA Delete on S3 versioned buckets to prevent irreversible object deletion without MFA token.",
					"SecurityIssues": []string{"MFA Delete disabled on versioned bucket"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		// 4. Check bucket policy public access & secure transport
		policyOutput, polErr := s.client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
			Bucket: aws.String(bucketName),
		})
		hasSecureTransportPolicy := false
		hasPublicPolicy := false
		if polErr == nil && policyOutput != nil && policyOutput.Policy != nil {
			var rawDoc map[string]interface{}
			if json.Unmarshal([]byte(*policyOutput.Policy), &rawDoc) == nil {
				var stmts []interface{}
				switch v := rawDoc["Statement"].(type) {
				case []interface{}:
					stmts = v
				case map[string]interface{}:
					stmts = []interface{}{v}
				}

				for _, stmtItem := range stmts {
					if stmt, ok := stmtItem.(map[string]interface{}); ok {
						effect, _ := stmt["Effect"].(string)
						if effect == "Allow" {
							isPublicPrincipal := false
							switch p := stmt["Principal"].(type) {
							case string:
								if p == "*" {
									isPublicPrincipal = true
								}
							case map[string]interface{}:
								if awsVal, ok := p["AWS"]; ok {
									switch av := awsVal.(type) {
									case string:
										if av == "*" {
											isPublicPrincipal = true
										}
									case []interface{}:
										for _, item := range av {
											if itemStr, ok := item.(string); ok && itemStr == "*" {
												isPublicPrincipal = true
												break
											}
										}
									}
								}
							}
							if isPublicPrincipal {
								cond, hasCond := stmt["Condition"].(map[string]interface{})
								if !hasCond || len(cond) == 0 {
									hasPublicPolicy = true
								}
							}
						}
						// Check secure transport denial: Effect == Deny && Condition.Bool.aws:SecureTransport == false
						if effect == "Deny" {
							if cond, ok := stmt["Condition"].(map[string]interface{}); ok {
								if boolCond, ok := cond["Bool"].(map[string]interface{}); ok {
									if secVal, ok := boolCond["aws:SecureTransport"]; ok {
										if secVal == "false" || secVal == false {
											hasSecureTransportPolicy = true
										}
									}
								}
							}
						}
					}
				}

				if hasPublicPolicy {
					results = append(results, scanner.ScanResult{
						ResourceID:   bucketName,
						ResourceType: "SecaaS-S3",
						Region:       "global",
						Status:       "FAIL",
						RuleID:       "s3_bucket_policy_public_write_access",
						Severity:     "CRITICAL",
						Metrics: map[string]interface{}{
							"BucketName":     bucketName,
							"StatusExtended": fmt.Sprintf("S3 bucket %s has a bucket policy granting public access to everyone (*).", bucketName),
							"Recommendation": "Remove public access policies from S3 bucket and restrict access to authorized principals only.",
							"SecurityIssues": []string{"Bucket policy grants public access to everyone (*)"},
						},
						Nodes: []graph.Node{
							{
								ID:       bucketName,
								NodeType: "SecaaS-S3",
							},
						},
					})
				}
			}
		}

		if !hasSecureTransportPolicy {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_secure_transport_policy",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not enforce HTTPS/TLS encrypted transmission in bucket policy.", bucketName),
					"Recommendation": "Add an explicit Deny statement for requests with aws:SecureTransport equal to false in the S3 bucket policy.",
					"SecurityIssues": []string{"Missing aws:SecureTransport denial in bucket policy"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		// Check public access (s3_bucket_public_access - CRITICAL)
		if hasPublicPolicy || !hasFullPAB {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_public_access",
				Severity:     "CRITICAL",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s allows public access via Block Public Access settings or bucket policy.", bucketName),
					"Recommendation": "Enable all S3 Block Public Access settings and restrict bucket policy.",
					"SecurityIssues": []string{"Public access block is missing or false, or bucket policy allows public access"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
				Edges: []graph.Edge{
					{
						From:     "Internet",
						To:       bucketName,
						Relation: "ROUTES_TO",
					},
				},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "PASS",
				RuleID:       "s3_bucket_public_access",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s has all Block Public Access settings enabled and restricts bucket policy public access.", bucketName),
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		// 5. Check server access logging (s3_bucket_server_access_logging_enabled - MEDIUM)
		logOutput, err := s.client.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{
			Bucket: aws.String(bucketName),
		})
		if err == nil && logOutput.LoggingEnabled == nil {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_server_access_logging_enabled",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not have server access logging enabled.", bucketName),
					"SecurityIssues": []string{"S3 Server Access Logging is disabled (access requests not tracked)"},
					"Recommendation": "Enable S3 Server Access Logging to an audit logging bucket.",
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		// 6. Check bucket ACL (s3_bucket_public_list_acl & s3_bucket_public_write_acl - CRITICAL)
		aclOutput, aclErr := s.client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(bucketName),
		})
		hasPublicListAcl := false
		hasPublicWriteAcl := false
		if aclErr == nil && aclOutput != nil {
			for _, grant := range aclOutput.Grants {
				if grant.Grantee != nil && grant.Grantee.URI != nil {
					uri := *grant.Grantee.URI
					isPublicGroup := uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
						uri == "https://acs.amazonaws.com/groups/global/AllUsers" ||
						uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" ||
						uri == "https://acs.amazonaws.com/groups/global/AuthenticatedUsers"
					if isPublicGroup {
						perm := string(grant.Permission)
						if perm == "READ" || perm == "FULL_CONTROL" {
							hasPublicListAcl = true
						}
						if perm == "WRITE" || perm == "FULL_CONTROL" {
							hasPublicWriteAcl = true
						}
					}
				}
			}
		}

		if hasPublicListAcl {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_public_list_acl",
				Severity:     "CRITICAL",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s grants public list permissions via bucket ACL.", bucketName),
					"Recommendation": "Remove public list permissions from S3 bucket ACL.",
					"SecurityIssues": []string{"Public list permissions granted in bucket ACL"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
				Edges: []graph.Edge{
					{
						From:     "Internet",
						To:       bucketName,
						Relation: "ROUTES_TO",
					},
				},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "PASS",
				RuleID:       "s3_bucket_public_list_acl",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not grant public list permissions via bucket ACL.", bucketName),
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}

		if hasPublicWriteAcl {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_bucket_public_write_acl",
				Severity:     "CRITICAL",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s grants public write permissions via bucket ACL.", bucketName),
					"Recommendation": "Remove public write permissions from S3 bucket ACL.",
					"SecurityIssues": []string{"Public write permissions granted in bucket ACL"},
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
				Edges: []graph.Edge{
					{
						From:     "Internet",
						To:       bucketName,
						Relation: "ROUTES_TO",
					},
				},
			})
		} else {
			results = append(results, scanner.ScanResult{
				ResourceID:   bucketName,
				ResourceType: "SecaaS-S3",
				Region:       "global",
				Status:       "PASS",
				RuleID:       "s3_bucket_public_write_acl",
				Severity:     "INFO",
				Metrics: map[string]interface{}{
					"BucketName":     bucketName,
					"StatusExtended": fmt.Sprintf("S3 bucket %s does not grant public write permissions via bucket ACL.", bucketName),
				},
				Nodes: []graph.Node{
					{
						ID:       bucketName,
						NodeType: "SecaaS-S3",
					},
				},
			})
		}
	}

	// 6. Check Account-level Block Public Access (s3_account_level_public_access_blocks - HIGH)
	if s.controlClient != nil && s.accountID != "" {
		acctPab, err := s.controlClient.GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
			AccountId: aws.String(s.accountID),
		})
		isAccountPabDisabled := false
		if err != nil || acctPab == nil || acctPab.PublicAccessBlockConfiguration == nil ||
			!aws.ToBool(acctPab.PublicAccessBlockConfiguration.BlockPublicAcls) ||
			!aws.ToBool(acctPab.PublicAccessBlockConfiguration.IgnorePublicAcls) ||
			!aws.ToBool(acctPab.PublicAccessBlockConfiguration.BlockPublicPolicy) ||
			!aws.ToBool(acctPab.PublicAccessBlockConfiguration.RestrictPublicBuckets) {
			isAccountPabDisabled = true
		}
		if isAccountPabDisabled {
			resID := fmt.Sprintf("s3-account-pab-%s", s.accountID)
			results = append(results, scanner.ScanResult{
				ResourceID:   resID,
				ResourceType: "SecaaS-S3-Account",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "s3_account_level_public_access_blocks",
				Severity:     "HIGH",
				Metrics: map[string]interface{}{
					"AccountId":      s.accountID,
					"StatusExtended": fmt.Sprintf("S3 account-level Block Public Access is disabled or incomplete for AWS account %s.", s.accountID),
					"Recommendation": "Enable all four S3 Block Public Access settings at the account level via S3Control.",
					"SecurityIssues": []string{"Incomplete or disabled account-level S3 Block Public Access"},
				},
				Nodes: []graph.Node{
					{
						ID:       resID,
						NodeType: "SecaaS-S3-Account",
					},
				},
			})
		}
	}

	return results, nil
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *S3Scanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "s3-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeGlobal,
		ExecutionCost: scanner.CostMedium,
		Service:       "s3",
		CheckIDs:      []string{"s3_account_level_public_access_blocks", "s3_bucket_default_encryption", "s3_bucket_kms_encryption", "s3_bucket_level_public_access_block", "s3_bucket_no_mfa_delete", "s3_bucket_object_versioning", "s3_bucket_policy_public_write_access", "s3_bucket_public_access", "s3_bucket_public_list_acl", "s3_bucket_public_write_acl", "s3_bucket_secure_transport_policy", "s3_bucket_server_access_logging_enabled"},
	}
}
