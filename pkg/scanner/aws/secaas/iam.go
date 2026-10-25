package secaas

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type IAMApi interface {
	GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListGroupsForUser(ctx context.Context, params *iam.ListGroupsForUserInput, optFns ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error)
	ListAttachedGroupPolicies(ctx context.Context, params *iam.ListAttachedGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListGroupPolicies(ctx context.Context, params *iam.ListGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
	GetGroupPolicy(ctx context.Context, params *iam.GetGroupPolicyInput, optFns ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	ListVirtualMFADevices(ctx context.Context, params *iam.ListVirtualMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListVirtualMFADevicesOutput, error)
	ListServerCertificates(ctx context.Context, params *iam.ListServerCertificatesInput, optFns ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error)
	ListSAMLProviders(ctx context.Context, params *iam.ListSAMLProvidersInput, optFns ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListGroups(ctx context.Context, params *iam.ListGroupsInput, optFns ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
	ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

type IAMScanner struct {
	client IAMApi
}

func NewIAMScanner(cfg aws.Config) *IAMScanner {
	return &IAMScanner{
		client: iam.NewFromConfig(cfg),
	}
}

func NewIAMScannerWithClient(client IAMApi) *IAMScanner {
	return &IAMScanner{
		client: client,
	}
}

func (s *IAMScanner) Name() string {
	return "IAM-SecaaS-Scanner"
}

func (s *IAMScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// 1. Check Root Account MFA and Root Access Keys
	summary, err := s.client.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, err
	}
	// iam_root_mfa_enabled (Severity: CRITICAL)
	if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val == 0 {
		results = append(results, scanner.ScanResult{
			ResourceID:   "RootAccount",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			IsOrphaned:   false,
			RuleID:       "iam_root_mfa_enabled",
			Severity:     "CRITICAL",
			Metrics: map[string]interface{}{
				"StatusExtended": "Root account does not have MFA enabled.",
				"SecurityIssues": []string{"Root account missing MFA"},
				"Recommendation": "Enable Multi-Factor Authentication (MFA) on the AWS root account immediately.",
			},
			Nodes: []graph.Node{{ID: "RootAccount", NodeType: "SecaaS-IAM"}},
		})
	}

	// iam_root_hardware_mfa_enabled (CIS 1.6)
	vMfaOut, err := s.client.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{})
	rootHasVirtualMFA := false
	if err == nil && vMfaOut != nil {
		for _, dev := range vMfaOut.VirtualMFADevices {
			sn := strings.ToLower(aws.ToString(dev.SerialNumber))
			if strings.Contains(sn, "root") || (dev.User != nil && strings.HasSuffix(aws.ToString(dev.User.Arn), ":root")) {
				rootHasVirtualMFA = true
				break
			}
		}
	}
	if val, ok := summary.SummaryMap["AccountMFAEnabled"]; ok && val > 0 && rootHasVirtualMFA {
		results = append(results, scanner.ScanResult{
			ResourceID:   "RootAccount",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "iam_root_hardware_mfa_enabled",
			Severity:     "CRITICAL",
			Metrics: map[string]interface{}{
				"StatusExtended": "Root account has virtual MFA enabled instead of hardware MFA.",
				"SecurityIssues": []string{"Root account using virtual MFA instead of hardware security key"},
				"Recommendation": "Configure a hardware MFA device (FIDO security key) for the root account.",
			},
			Nodes: []graph.Node{{ID: "RootAccount", NodeType: "SecaaS-IAM"}},
		})
	}

	// iam_avoid_root_usage (CIS 1.7)
	repOut, err := s.client.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err == nil && repOut != nil && len(repOut.Content) > 0 {
		lines := strings.Split(string(repOut.Content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "<root_account>") {
				fields := strings.Split(line, ",")
				rootUsedRecently := false
				var lastUsedTime time.Time
				checkTimestamps := []string{}
				if len(fields) > 4 && fields[4] != "N/A" && fields[4] != "not_supported" && fields[4] != "" {
					checkTimestamps = append(checkTimestamps, fields[4])
				}
				if len(fields) > 10 && fields[10] != "N/A" && fields[10] != "not_supported" && fields[10] != "" {
					checkTimestamps = append(checkTimestamps, fields[10])
				}
				if len(fields) > 13 && fields[13] != "N/A" && fields[13] != "not_supported" && fields[13] != "" {
					checkTimestamps = append(checkTimestamps, fields[13])
				}
				for _, tsStr := range checkTimestamps {
					if tParsed, parseErr := time.Parse(time.RFC3339, tsStr); parseErr == nil {
						if time.Since(tParsed) < 24*time.Hour {
							rootUsedRecently = true
							lastUsedTime = tParsed
							break
						}
					}
				}
				if rootUsedRecently {
					results = append(results, scanner.ScanResult{
						ResourceID:   "RootAccount",
						ResourceType: "SecaaS-IAM",
						Region:       "global",
						Status:       "FAIL",
						RuleID:       "iam_avoid_root_usage",
						Severity:     "HIGH",
						Metrics: map[string]interface{}{
							"LastUsed":       lastUsedTime.Format(time.RFC3339),
							"StatusExtended": fmt.Sprintf("Root user was used recently at %s (within the last 24 hours).", lastUsedTime.Format(time.RFC3339)),
							"SecurityIssues": []string{"Recent root user activity detected"},
							"Recommendation": "Avoid using the root user for administrative tasks; use IAM Identity Center SSO with temporary credentials.",
						},
						Nodes: []graph.Node{{ID: "RootAccount", NodeType: "SecaaS-IAM"}},
					})
				}
				break
			}
		}
	}

	// iam_no_root_access_key (Severity: CRITICAL)
	if val, ok := summary.SummaryMap["AccountAccessKeysPresent"]; ok && val > 0 {
		results = append(results, scanner.ScanResult{
			ResourceID:   "RootAccount",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			IsOrphaned:   false,
			RuleID:       "iam_no_root_access_key",
			Severity:     "CRITICAL",
			Metrics: map[string]interface{}{
				"StatusExtended": "Root account has active access keys.",
				"SecurityIssues": []string{"Root account has active access keys"},
				"Recommendation": "Delete all access keys for the root account.",
			},
			Nodes: []graph.Node{{ID: "RootAccount", NodeType: "SecaaS-IAM"}},
		})
	}

	// Password Policy Checks (CIS 1.8 & 1.9)
	pwPolicyOut, pwErr := s.client.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if pwErr != nil || pwPolicyOut == nil || pwPolicyOut.PasswordPolicy == nil {
		results = append(results, scanner.ScanResult{
			ResourceID:   "AccountPasswordPolicy",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "iam_password_policy_minimum_length_14",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": "No custom IAM password policy configured, failing minimum length requirement of 14.",
				"SecurityIssues": []string{"Password policy missing minimum length 14"},
				"Recommendation": "Set an IAM password policy with minimum length >= 14.",
			},
			Nodes: []graph.Node{{ID: "AccountPasswordPolicy", NodeType: "SecaaS-IAM"}},
		})
		results = append(results, scanner.ScanResult{
			ResourceID:   "AccountPasswordPolicy",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "iam_password_policy_reuse_24",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": "No custom IAM password policy configured, failing password reuse prevention of 24.",
				"SecurityIssues": []string{"Password policy missing reuse prevention of 24"},
				"Recommendation": "Set an IAM password policy preventing reuse of at least 24 passwords.",
			},
			Nodes: []graph.Node{{ID: "AccountPasswordPolicy", NodeType: "SecaaS-IAM"}},
		})
	} else {
		pol := pwPolicyOut.PasswordPolicy
		if pol.MinimumPasswordLength == nil || aws.ToInt32(pol.MinimumPasswordLength) < 14 {
			results = append(results, scanner.ScanResult{
				ResourceID:   "AccountPasswordPolicy",
				ResourceType: "SecaaS-IAM",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "iam_password_policy_minimum_length_14",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"MinimumPasswordLength": aws.ToInt32(pol.MinimumPasswordLength),
					"StatusExtended":        fmt.Sprintf("IAM password policy minimum length is %d (required: >= 14).", aws.ToInt32(pol.MinimumPasswordLength)),
					"SecurityIssues":        []string{"Password policy minimum length < 14"},
					"Recommendation":        "Set password policy minimum length to at least 14 characters.",
				},
				Nodes: []graph.Node{{ID: "AccountPasswordPolicy", NodeType: "SecaaS-IAM"}},
			})
		}
		if pol.PasswordReusePrevention == nil || aws.ToInt32(pol.PasswordReusePrevention) < 24 {
			results = append(results, scanner.ScanResult{
				ResourceID:   "AccountPasswordPolicy",
				ResourceType: "SecaaS-IAM",
				Region:       "global",
				Status:       "FAIL",
				RuleID:       "iam_password_policy_reuse_24",
				Severity:     "MEDIUM",
				Metrics: map[string]interface{}{
					"PasswordReusePrevention": aws.ToInt32(pol.PasswordReusePrevention),
					"StatusExtended":          fmt.Sprintf("IAM password policy reuse prevention is %d (required: >= 24).", aws.ToInt32(pol.PasswordReusePrevention)),
					"SecurityIssues":          []string{"Password policy reuse prevention < 24"},
					"Recommendation":          "Set password policy reuse prevention to at least 24 passwords.",
				},
				Nodes: []graph.Node{{ID: "AccountPasswordPolicy", NodeType: "SecaaS-IAM"}},
			})
		}
	}

	// Server Certificates (CIS 1.19)
	certsOut, certErr := s.client.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{})
	if certErr == nil && certsOut != nil {
		for _, cert := range certsOut.ServerCertificateMetadataList {
			certName := aws.ToString(cert.ServerCertificateName)
			if cert.Expiration != nil && cert.Expiration.Before(time.Now()) {
				results = append(results, scanner.ScanResult{
					ResourceID:   certName,
					ResourceType: "SecaaS-IAM-Certificate",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "iam_no_expired_server_certificates_stored",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"ServerCertificateName": certName,
						"Expiration":            cert.Expiration.Format(time.RFC3339),
						"StatusExtended":        fmt.Sprintf("Server certificate %s stored in IAM expired at %s.", certName, cert.Expiration.Format(time.RFC3339)),
						"SecurityIssues":        []string{"Expired server certificate in IAM store"},
						"Recommendation":        "Delete expired SSL/TLS server certificates stored in IAM.",
					},
					Nodes: []graph.Node{{ID: certName, NodeType: "SecaaS-IAM-Certificate"}},
				})
			}
		}
	}

	// SAML Identity Providers (CIS 1.21)
	samlOut, samlErr := s.client.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if samlErr == nil && samlOut != nil && len(samlOut.SAMLProviderList) == 0 {
		results = append(results, scanner.ScanResult{
			ResourceID:   "AccountSAMLProviders",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "iam_check_saml_providers_sts",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": "No active SAML 2.0 identity providers configured in IAM for federated SSO.",
				"SecurityIssues": []string{"Missing SAML 2.0 identity federation provider"},
				"Recommendation": "Configure a SAML 2.0 identity provider (IdP) in IAM to enable centralized SSO and temporary STS credentials.",
			},
			Nodes: []graph.Node{{ID: "AccountSAMLProviders", NodeType: "SecaaS-IAM"}},
		})
	}

	// 2. Check individual Users
	discoveredUserGroups := make(map[string]bool)
	paginator := iam.NewListUsersPaginator(s.client, &iam.ListUsersInput{})
	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, user := range page.Users {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			userName := aws.ToString(user.UserName)

			// Check Access Keys
			keysOutput, err := s.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: aws.String(userName),
			})
			if err != nil {
				return nil, err
			}

			hasStaleKeys := false
			var keyIssues []string
			activeKeysCount := 0

			for _, key := range keysOutput.AccessKeyMetadata {
				isActive := key.Status == types.StatusTypeActive
				if isActive {
					activeKeysCount++
				}

				if key.CreateDate != nil {
					daysSinceCreate := time.Since(*key.CreateDate).Hours() / 24
					if daysSinceCreate > 90 {
						hasStaleKeys = true
						keyIssues = append(keyIssues, fmt.Sprintf("Access Key %s is older than 90 days without rotation (%.0f days)", aws.ToString(key.AccessKeyId), daysSinceCreate))
					}

					// iam_user_no_setup_initial_access_key (CIS 1.11)
					if user.CreateDate != nil {
						diff := key.CreateDate.Sub(*user.CreateDate)
						if diff < 0 {
							diff = -diff
						}
						if diff <= 2*time.Minute {
							results = append(results, scanner.ScanResult{
								ResourceID:   userName,
								ResourceType: "SecaaS-IAM",
								Region:       "global",
								Status:       "FAIL",
								RuleID:       "iam_user_no_setup_initial_access_key",
								Severity:     "MEDIUM",
								Metrics: map[string]interface{}{
									"UserName":       userName,
									"AccessKeyId":    aws.ToString(key.AccessKeyId),
									"StatusExtended": fmt.Sprintf("IAM user %s was configured with initial access key %s at user creation time.", userName, aws.ToString(key.AccessKeyId)),
									"SecurityIssues": []string{"Initial access key created with user"},
									"Recommendation": "Do not generate access keys during IAM user creation; provision temporary credentials when needed.",
								},
								Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
							})
						}
					}
				}

				// iam_user_accesskey_unused (CIS 1.12 - 45 days)
				if isActive {
					keyUsed, keyErr := s.client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId})
					if keyErr == nil && keyUsed != nil && keyUsed.AccessKeyLastUsed != nil {
						if keyUsed.AccessKeyLastUsed.LastUsedDate != nil {
							if time.Since(*keyUsed.AccessKeyLastUsed.LastUsedDate).Hours()/24 > 45 {
								results = append(results, scanner.ScanResult{
									ResourceID:   userName,
									ResourceType: "SecaaS-IAM",
									Region:       "global",
									Status:       "FAIL",
									RuleID:       "iam_user_accesskey_unused",
									Severity:     "MEDIUM",
									Metrics: map[string]interface{}{
										"UserName":       userName,
										"AccessKeyId":    aws.ToString(key.AccessKeyId),
										"LastUsedDate":   keyUsed.AccessKeyLastUsed.LastUsedDate.Format(time.RFC3339),
										"StatusExtended": fmt.Sprintf("Access key %s for user %s has been unused for > 45 days.", aws.ToString(key.AccessKeyId), userName),
										"SecurityIssues": []string{"Active access key unused for > 45 days"},
										"Recommendation": "Deactivate or delete access keys unused for more than 45 days.",
									},
									Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
								})
							}
						} else if key.CreateDate != nil && time.Since(*key.CreateDate).Hours()/24 > 45 {
							results = append(results, scanner.ScanResult{
								ResourceID:   userName,
								ResourceType: "SecaaS-IAM",
								Region:       "global",
								Status:       "FAIL",
								RuleID:       "iam_user_accesskey_unused",
								Severity:     "MEDIUM",
								Metrics: map[string]interface{}{
									"UserName":       userName,
									"AccessKeyId":    aws.ToString(key.AccessKeyId),
									"StatusExtended": fmt.Sprintf("Access key %s for user %s was never used and is older than 45 days.", aws.ToString(key.AccessKeyId), userName),
									"SecurityIssues": []string{"Access key never used and older than 45 days"},
									"Recommendation": "Deactivate or delete unused access keys.",
								},
								Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
							})
						}
					}
				}
			}

			// iam_user_two_active_access_key (CIS 1.13)
			if activeKeysCount >= 2 {
				results = append(results, scanner.ScanResult{
					ResourceID:   userName,
					ResourceType: "SecaaS-IAM",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "iam_user_two_active_access_key",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"UserName":        userName,
						"ActiveKeysCount": activeKeysCount,
						"StatusExtended":  fmt.Sprintf("IAM user %s has %d active access keys (maximum allowed: 1).", userName, activeKeysCount),
						"SecurityIssues":  []string{"Multiple active access keys assigned to single user"},
						"Recommendation":  "Ensure no IAM user possesses more than one active access key.",
					},
					Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
				})
			}

			// iam_user_console_access_unused (CIS 1.12 - 45 days)
			if user.PasswordLastUsed != nil {
				daysSinceLogin := time.Since(*user.PasswordLastUsed).Hours() / 24
				if daysSinceLogin > 45 {
					results = append(results, scanner.ScanResult{
						ResourceID:   userName,
						ResourceType: "SecaaS-IAM",
						Region:       "global",
						Status:       "FAIL",
						RuleID:       "iam_user_console_access_unused",
						Severity:     "MEDIUM",
						Metrics: map[string]interface{}{
							"UserName":         userName,
							"PasswordLastUsed": user.PasswordLastUsed.Format(time.RFC3339),
							"StatusExtended":   fmt.Sprintf("Console access password for user %s has not been used for %.0f days (> 45 days).", userName, daysSinceLogin),
							"SecurityIssues":   []string{"Console password unused for > 45 days"},
							"Recommendation":   "Disable console login profile for users that have not logged in for 45+ days.",
						},
						Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
					})
				}
				if daysSinceLogin > 90 {
					hasStaleKeys = true
					keyIssues = append(keyIssues, fmt.Sprintf("Stale IAM user (no console login for %.0f days)", daysSinceLogin))
				}
			}

			if hasStaleKeys {
				results = append(results, scanner.ScanResult{
					ResourceID:   userName,
					ResourceType: "SecaaS-IAM",
					Region:       "global",
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "iam_rotate_access_key_90_days",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"UserName":       userName,
						"StatusExtended": fmt.Sprintf("IAM user %s has access keys older than 90 days without rotation or stale credentials.", userName),
						"SecurityIssues": keyIssues,
						"Recommendation": "Rotate IAM access keys every 90 days or less and disable unused credentials.",
					},
					Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
				})
			}

			// Check MFA for the user (iam_user_mfa_enabled_console_access - HIGH)
			mfaOutput, err := s.client.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: aws.String(userName),
			})
			if err != nil {
				return nil, err
			}
			if len(mfaOutput.MFADevices) == 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   userName,
					ResourceType: "SecaaS-IAM",
					Region:       "global",
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "iam_user_mfa_enabled_console_access",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"UserName":       userName,
						"StatusExtended": fmt.Sprintf("IAM user %s does not have MFA enabled for console access.", userName),
						"SecurityIssues": []string{"User missing MFA"},
						"Recommendation": "Enable Multi-Factor Authentication (MFA) for the IAM user.",
					},
					Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
				})
			}

			attachedPolicies, err := s.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(userName)})
			if err != nil {
				return nil, err
			}

			// iam_policy_attached_only_to_group_or_roles (CIS 1.15)
			if len(attachedPolicies.AttachedPolicies) > 0 {
				results = append(results, scanner.ScanResult{
					ResourceID:   userName,
					ResourceType: "SecaaS-IAM",
					Region:       "global",
					Status:       "FAIL",
					RuleID:       "iam_policy_attached_only_to_group_or_roles",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"UserName":       userName,
						"PolicyCount":    len(attachedPolicies.AttachedPolicies),
						"StatusExtended": fmt.Sprintf("IAM user %s has %d policies directly attached instead of inherited via groups.", userName, len(attachedPolicies.AttachedPolicies)),
						"SecurityIssues": []string{"Direct policy attachment to user"},
						"Recommendation": "Attach managed policies exclusively to IAM groups or roles, not directly to individual users.",
					},
					Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
				})
			}

			userHasAdminAccess := false
			for _, p := range attachedPolicies.AttachedPolicies {
				pName := aws.ToString(p.PolicyName)
				pArn := aws.ToString(p.PolicyArn)
				if pName == "AdministratorAccess" || strings.HasSuffix(pArn, "/AdministratorAccess") {
					userHasAdminAccess = true
				}

				if strings.Contains(pArn, "AdministratorAccess") || pName == "AdministratorAccess" {
					// iam_aws_attached_policy_no_administrative_privileges (CIS 1.16)
					results = append(results, scanner.ScanResult{
						ResourceID:   userName,
						ResourceType: "SecaaS-IAM",
						Region:       "global",
						Status:       "FAIL",
						RuleID:       "iam_aws_attached_policy_no_administrative_privileges",
						Severity:     "CRITICAL",
						Metrics: map[string]interface{}{
							"UserName":       userName,
							"PolicyArn":      pArn,
							"StatusExtended": fmt.Sprintf("IAM user %s has AWS managed AdministratorAccess policy attached.", userName),
							"SecurityIssues": []string{"AWS AdministratorAccess directly attached to user"},
							"Recommendation": "Detach AdministratorAccess and use scoped least-privilege IAM roles instead.",
						},
						Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
					})
				}
			}

			// iam_user_administrator_access_policy (CRITICAL)
			if userHasAdminAccess {
				results = append(results, scanner.ScanResult{
					ResourceID:   userName,
					ResourceType: "SecaaS-IAM-User",
					Region:       "global",
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "iam_user_administrator_access_policy",
					Severity:     "CRITICAL",
					Metrics: map[string]interface{}{
						"UserName":       userName,
						"StatusExtended": fmt.Sprintf("IAM user %s has AdministratorAccess managed policy attached.", userName),
						"SecurityIssues": []string{"AdministratorAccess managed policy attached to user"},
						"Recommendation": "Detach AdministratorAccess managed policy from IAM users; use temporary federated roles.",
					},
					Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM-User"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   userName,
					ResourceType: "SecaaS-IAM-User",
					Region:       "global",
					Status:       "PASS",
					IsOrphaned:   false,
					RuleID:       "iam_user_administrator_access_policy",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"UserName":       userName,
						"StatusExtended": fmt.Sprintf("IAM user %s does not have AdministratorAccess managed policy attached.", userName),
						"Recommendation": "Detach AdministratorAccess managed policy from IAM users; use temporary federated roles.",
					},
					Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM-User"}},
				})
			}

			userPolicies, err := s.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(userName)})
			if err != nil {
				return nil, err
			}
			for _, pName := range userPolicies.PolicyNames {
				policyOutput, err := s.client.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
					UserName:   aws.String(userName),
					PolicyName: aws.String(pName),
				})
				if err != nil {
					return nil, err
				}
				if policyOutput.PolicyDocument != nil {
					docStr := aws.ToString(policyOutput.PolicyDocument)
					if isWildcardDoc(docStr) {
						// iam_customer_attached_policy_no_administrative_privileges (CIS 1.16)
						results = append(results, scanner.ScanResult{
							ResourceID:   userName,
							ResourceType: "SecaaS-IAM",
							Region:       "global",
							Status:       "FAIL",
							RuleID:       "iam_customer_attached_policy_no_administrative_privileges",
							Severity:     "HIGH",
							Metrics: map[string]interface{}{
								"UserName":       userName,
								"PolicyName":     pName,
								"StatusExtended": fmt.Sprintf("Inline policy %s for user %s grants full administrative privileges (*:*).", pName, userName),
								"SecurityIssues": []string{"Customer inline policy grants *:*"},
								"Recommendation": "Scope customer policy actions away from wildcard *:*.",
							},
							Nodes: []graph.Node{{ID: userName, NodeType: "SecaaS-IAM"}},
						})
					}

					// iam_inline_policy_no_administrative_privileges (CRITICAL)
					resID := userName + "-inline-" + pName
					if isAdministrativeWildcard(docStr) {
						results = append(results, scanner.ScanResult{
							ResourceID:   resID,
							ResourceType: "SecaaS-IAM-Policy",
							Region:       "global",
							Status:       "FAIL",
							IsOrphaned:   false,
							RuleID:       "iam_inline_policy_no_administrative_privileges",
							Severity:     "CRITICAL",
							Metrics: map[string]interface{}{
								"UserName":       userName,
								"PolicyName":     pName,
								"StatusExtended": fmt.Sprintf("Inline policy %s for user %s grants full administrative privileges (*:*).", pName, userName),
								"SecurityIssues": []string{"Inline policy grants *:* administrative privileges"},
								"Recommendation": "Remove *:* administrative permissions from inline policies; scope to specific actions and resources.",
							},
							Nodes: []graph.Node{{ID: resID, NodeType: "SecaaS-IAM-Policy"}},
						})
					} else {
						results = append(results, scanner.ScanResult{
							ResourceID:   resID,
							ResourceType: "SecaaS-IAM-Policy",
							Region:       "global",
							Status:       "PASS",
							IsOrphaned:   false,
							RuleID:       "iam_inline_policy_no_administrative_privileges",
							Severity:     "INFO",
							Metrics: map[string]interface{}{
								"UserName":       userName,
								"PolicyName":     pName,
								"StatusExtended": fmt.Sprintf("Inline policy %s for user %s does not grant unrestricted administrative privileges.", pName, userName),
								"Recommendation": "Remove *:* administrative permissions from inline policies; scope to specific actions and resources.",
							},
							Nodes: []graph.Node{{ID: resID, NodeType: "SecaaS-IAM-Policy"}},
						})
					}
				}
			}

			userGroups, err := s.client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: aws.String(userName)})
			if err != nil {
				return nil, err
			}
			for _, g := range userGroups.Groups {
				gName := aws.ToString(g.GroupName)
				if gName != "" {
					discoveredUserGroups[gName] = true
				}
			}
		}
	}

	// 3 & 4. Check Roles
	hasSupportRole := false
	rolesPaginator := iam.NewListRolesPaginator(s.client, &iam.ListRolesInput{})
	for rolesPaginator.HasMorePages() {
		page, err := rolesPaginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, role := range page.Roles {
			roleName := aws.ToString(role.RoleName)
			roleArn := aws.ToString(role.Arn)

			// Check role inline policies (iam_inline_policy_no_administrative_privileges)
			rolePolicies, rPolErr := s.client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: role.RoleName})
			if rPolErr == nil && rolePolicies != nil {
				for _, pName := range rolePolicies.PolicyNames {
					policyOutput, getPolErr := s.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
						RoleName:   role.RoleName,
						PolicyName: aws.String(pName),
					})
					if getPolErr == nil && policyOutput != nil && policyOutput.PolicyDocument != nil {
						docStr := aws.ToString(policyOutput.PolicyDocument)
						resID := roleName + "-inline-" + pName
						if isAdministrativeWildcard(docStr) {
							results = append(results, scanner.ScanResult{
								ResourceID:   resID,
								ResourceType: "SecaaS-IAM-Policy",
								Region:       "global",
								Status:       "FAIL",
								IsOrphaned:   false,
								RuleID:       "iam_inline_policy_no_administrative_privileges",
								Severity:     "CRITICAL",
								Metrics: map[string]interface{}{
									"RoleName":       roleName,
									"PolicyName":     pName,
									"StatusExtended": fmt.Sprintf("Inline policy %s for role %s grants full administrative privileges (*:*).", pName, roleName),
									"SecurityIssues": []string{"Role inline policy grants *:* administrative privileges"},
									"Recommendation": "Remove *:* administrative permissions from inline policies; scope to specific actions and resources.",
								},
								Nodes: []graph.Node{{ID: resID, NodeType: "SecaaS-IAM-Policy"}},
							})
						} else {
							results = append(results, scanner.ScanResult{
								ResourceID:   resID,
								ResourceType: "SecaaS-IAM-Policy",
								Region:       "global",
								Status:       "PASS",
								IsOrphaned:   false,
								RuleID:       "iam_inline_policy_no_administrative_privileges",
								Severity:     "INFO",
								Metrics: map[string]interface{}{
									"RoleName":       roleName,
									"PolicyName":     pName,
									"StatusExtended": fmt.Sprintf("Inline policy %s for role %s does not grant unrestricted administrative privileges.", pName, roleName),
									"Recommendation": "Remove *:* administrative permissions from inline policies; scope to specific actions and resources.",
								},
								Nodes: []graph.Node{{ID: resID, NodeType: "SecaaS-IAM-Policy"}},
							})
						}
					}
				}
			}

			// Check for AWSSupportAccess policy attached
			attachedRolePols, polErr := s.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName})
			if polErr == nil && attachedRolePols != nil {
				for _, p := range attachedRolePols.AttachedPolicies {
					pArn := aws.ToString(p.PolicyArn)
					if strings.Contains(pArn, "AWSSupportAccess") {
						hasSupportRole = true
					}
				}
			}

			// iam_role_unused (Severity: LOW)
			isStale := false
			if role.RoleLastUsed != nil {
				if role.RoleLastUsed.LastUsedDate != nil {
					daysSinceUsed := time.Since(*role.RoleLastUsed.LastUsedDate).Hours() / 24
					if daysSinceUsed > 90 {
						isStale = true
					}
				} else {
					isStale = true // Never used
				}
			} else {
				isStale = true // Never used
			}

			if isStale {
				results = append(results, scanner.ScanResult{
					ResourceID:   roleName,
					ResourceType: "SecaaS-IAM-Role",
					Region:       "global",
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "iam_role_unused",
					Severity:     "LOW",
					Metrics: map[string]interface{}{
						"RoleName":       roleName,
						"StatusExtended": fmt.Sprintf("IAM Role %s has been inactive/unused for 90+ days or has never been assumed.", roleName),
						"SecurityIssues": []string{"IAM Role has been inactive/unused for 90+ days or has never been assumed"},
						"Recommendation": "IAM Role unused for 90+ days. Consider removing inactive roles to reduce attack surface.",
					},
					Nodes: []graph.Node{{ID: roleName, NodeType: "SecaaS-IAM-Role"}},
				})
			}

			// iam_role_cross_account_readonlyaccess_policy (Severity: HIGH)
			parts := strings.Split(roleArn, ":")
			if len(parts) >= 5 {
				currentAccountID := parts[4]
				if role.AssumeRolePolicyDocument != nil {
					doc, err := url.QueryUnescape(aws.ToString(role.AssumeRolePolicyDocument))
					if err == nil {
						var docMap map[string]interface{}
						if err := json.Unmarshal([]byte(doc), &docMap); err == nil {
							var statements []interface{}
							switch v := docMap["Statement"].(type) {
							case []interface{}:
								statements = v
							case map[string]interface{}:
								statements = []interface{}{v}
							}

							hasCrossAccount := false
							for _, stmtItem := range statements {
								if stmt, ok := stmtItem.(map[string]interface{}); ok {
									if effect, ok := stmt["Effect"].(string); ok && effect == "Allow" {
										if principal, ok := stmt["Principal"].(map[string]interface{}); ok {
											awsPrincipal := principal["AWS"]
											checkCrossAccount := func(p string) bool {
												if p == "*" {
													return true
												}
												if strings.Contains(p, "arn:aws:iam::") {
													pParts := strings.Split(p, ":")
													if len(pParts) >= 5 && pParts[4] != currentAccountID && pParts[4] != "" {
														return true
													}
												}
												return false
											}

											if pStr, ok := awsPrincipal.(string); ok {
												hasCrossAccount = checkCrossAccount(pStr)
											} else if pList, ok := awsPrincipal.([]interface{}); ok {
												for _, pItem := range pList {
													if pStr, ok := pItem.(string); ok && checkCrossAccount(pStr) {
														hasCrossAccount = true
													}
												}
											}
										}
									}
								}
							}

							if hasCrossAccount {
								results = append(results, scanner.ScanResult{
									ResourceID:   roleName,
									ResourceType: "SecaaS-IAM-Role",
									Region:       "global",
									Status:       "FAIL",
									IsOrphaned:   false,
									RuleID:       "iam_role_cross_account_readonlyaccess_policy",
									Severity:     "HIGH",
									Metrics: map[string]interface{}{
										"RoleName":       roleName,
										"StatusExtended": fmt.Sprintf("IAM Role %s trust policy grants access to external account or wildcard principal (*).", roleName),
										"SecurityIssues": []string{"IAM Role trust policy grants access to external account or wildcard principal (*)"},
										"Recommendation": "IAM Role trusts an external account or wildcard principal. Verify trust relationship in AssumeRolePolicyDocument.",
									},
									Nodes: []graph.Node{{ID: roleName, NodeType: "SecaaS-IAM-Role"}},
								})
							}
						}
					}
				}
			}
		}
	}

	// iam_support_role_created (CIS 1.17)
	if !hasSupportRole {
		results = append(results, scanner.ScanResult{
			ResourceID:   "AccountSupportRole",
			ResourceType: "SecaaS-IAM",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "iam_support_role_created",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": "No IAM role found with AWSSupportAccess policy attached.",
				"SecurityIssues": []string{"Missing dedicated AWSSupportAccess role for incident support"},
				"Recommendation": "Create an IAM role with the AWSSupportAccess managed policy attached for AWS Support operations.",
			},
			Nodes: []graph.Node{{ID: "AccountSupportRole", NodeType: "SecaaS-IAM"}},
		})
	}

	// 5. Check Group Inline Policies (iam_inline_policy_no_administrative_privileges)
	inspectedGroups := make(map[string]bool)
	var allGroups []string

	groupsOut, groupsErr := s.client.ListGroups(ctx, &iam.ListGroupsInput{})
	if groupsErr == nil && groupsOut != nil {
		for _, g := range groupsOut.Groups {
			gName := aws.ToString(g.GroupName)
			if gName != "" && !inspectedGroups[gName] {
				inspectedGroups[gName] = true
				allGroups = append(allGroups, gName)
			}
		}
	}
	for gName := range discoveredUserGroups {
		if !inspectedGroups[gName] {
			inspectedGroups[gName] = true
			allGroups = append(allGroups, gName)
		}
	}

	for _, gName := range allGroups {
		gPolicies, err := s.client.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{GroupName: aws.String(gName)})
		if err == nil && gPolicies != nil {
			for _, pName := range gPolicies.PolicyNames {
				policyOutput, err := s.client.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
					GroupName:  aws.String(gName),
					PolicyName: aws.String(pName),
				})
				if err == nil && policyOutput != nil && policyOutput.PolicyDocument != nil {
					docStr := aws.ToString(policyOutput.PolicyDocument)
					resID := gName + "-inline-" + pName
					if isAdministrativeWildcard(docStr) {
						results = append(results, scanner.ScanResult{
							ResourceID:   resID,
							ResourceType: "SecaaS-IAM-Policy",
							Region:       "global",
							Status:       "FAIL",
							IsOrphaned:   false,
							RuleID:       "iam_inline_policy_no_administrative_privileges",
							Severity:     "CRITICAL",
							Metrics: map[string]interface{}{
								"GroupName":      gName,
								"PolicyName":     pName,
								"StatusExtended": fmt.Sprintf("Inline policy %s for group %s grants full administrative privileges (*:*).", pName, gName),
								"SecurityIssues": []string{"Group inline policy grants *:* administrative privileges"},
								"Recommendation": "Remove *:* administrative permissions from inline policies; scope to specific actions and resources.",
							},
							Nodes: []graph.Node{{ID: resID, NodeType: "SecaaS-IAM-Policy"}},
						})
					} else {
						results = append(results, scanner.ScanResult{
							ResourceID:   resID,
							ResourceType: "SecaaS-IAM-Policy",
							Region:       "global",
							Status:       "PASS",
							IsOrphaned:   false,
							RuleID:       "iam_inline_policy_no_administrative_privileges",
							Severity:     "INFO",
							Metrics: map[string]interface{}{
								"GroupName":      gName,
								"PolicyName":     pName,
								"StatusExtended": fmt.Sprintf("Inline policy %s for group %s does not grant unrestricted administrative privileges.", pName, gName),
								"Recommendation": "Remove *:* administrative permissions from inline policies; scope to specific actions and resources.",
							},
							Nodes: []graph.Node{{ID: resID, NodeType: "SecaaS-IAM-Policy"}},
						})
					}
				}
			}
		}
	}

	// 6. Check Customer Managed Policies for Privilege Escalation (iam_policy_allows_privilege_escalation)
	policiesPaginator := iam.NewListPoliciesPaginator(s.client, &iam.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	})
	for policiesPaginator.HasMorePages() {
		page, err := policiesPaginator.NextPage(ctx)
		if err != nil {
			break
		}
		for _, policy := range page.Policies {
			policyArn := aws.ToString(policy.Arn)
			policyName := aws.ToString(policy.PolicyName)
			if policyArn == "" {
				policyArn = policyName
			}
			versionID := policy.DefaultVersionId
			if versionID == nil {
				defaultV := "v1"
				versionID = &defaultV
			}

			verOutput, err := s.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: versionID,
			})
			if err != nil || verOutput == nil || verOutput.PolicyVersion == nil || verOutput.PolicyVersion.Document == nil {
				continue
			}

			docStr := aws.ToString(verOutput.PolicyVersion.Document)
			if hasPrivilegeEscalation(docStr) {
				results = append(results, scanner.ScanResult{
					ResourceID:   policyArn,
					ResourceType: "SecaaS-IAM-Policy",
					Region:       "global",
					Status:       "FAIL",
					IsOrphaned:   false,
					RuleID:       "iam_policy_allows_privilege_escalation",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"PolicyArn":      policyArn,
						"PolicyName":     policyName,
						"StatusExtended": fmt.Sprintf("Customer managed policy %s grants dangerous privilege escalation permissions on Resource: '*'.", policyName),
						"SecurityIssues": []string{"Customer managed policy allows privilege escalation actions on wildcard resource"},
						"Recommendation": "Restrict privilege escalation actions (e.g. iam:AttachUserPolicy, iam:PassRole) in customer managed policies.",
					},
					Nodes: []graph.Node{{ID: policyArn, NodeType: "SecaaS-IAM-Policy"}},
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   policyArn,
					ResourceType: "SecaaS-IAM-Policy",
					Region:       "global",
					Status:       "PASS",
					IsOrphaned:   false,
					RuleID:       "iam_policy_allows_privilege_escalation",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"PolicyArn":      policyArn,
						"PolicyName":     policyName,
						"StatusExtended": fmt.Sprintf("Customer managed policy %s does not allow privilege escalation.", policyName),
						"Recommendation": "Restrict privilege escalation actions (e.g. iam:AttachUserPolicy, iam:PassRole) in customer managed policies.",
					},
					Nodes: []graph.Node{{ID: policyArn, NodeType: "SecaaS-IAM-Policy"}},
				})
			}
		}
	}

	return results, nil
}

func isWildcardDoc(docStr string) bool {
	doc, err := url.QueryUnescape(docStr)
	if err != nil {
		return false
	}
	var docMap map[string]interface{}
	if err := json.Unmarshal([]byte(doc), &docMap); err != nil {
		return false
	}
	var statements []interface{}
	switch v := docMap["Statement"].(type) {
	case []interface{}:
		statements = v
	case map[string]interface{}:
		statements = []interface{}{v}
	}

	for _, stmtItem := range statements {
		if stmt, ok := stmtItem.(map[string]interface{}); ok {
			if action, ok := stmt["Action"]; ok {
				if actStr, ok := action.(string); ok && actStr == "*" {
					return true
				} else if actList, ok := action.([]interface{}); ok {
					for _, actItem := range actList {
						if actStr, ok := actItem.(string); ok && actStr == "*" {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isAdministrativeWildcard(docStr string) bool {
	doc, err := url.QueryUnescape(docStr)
	if err != nil {
		doc = docStr
	}
	var docMap map[string]interface{}
	if err := json.Unmarshal([]byte(doc), &docMap); err != nil {
		return false
	}
	var statements []interface{}
	switch v := docMap["Statement"].(type) {
	case []interface{}:
		statements = v
	case map[string]interface{}:
		statements = []interface{}{v}
	}

	containsWildcard := func(val interface{}) bool {
		switch v := val.(type) {
		case string:
			return v == "*"
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok && s == "*" {
					return true
				}
			}
		}
		return false
	}

	for _, stmtItem := range statements {
		stmt, ok := stmtItem.(map[string]interface{})
		if !ok {
			continue
		}
		effect, _ := stmt["Effect"].(string)
		if strings.EqualFold(effect, "Allow") {
			if containsWildcard(stmt["Action"]) && containsWildcard(stmt["Resource"]) {
				return true
			}
		}
	}
	return false
}

var dangerousPrivEscActions = []string{
	"iam:createaccesskey",
	"iam:createloginprofile",
	"iam:updateloginprofile",
	"iam:attachuserpolicy",
	"iam:attachrolepolicy",
	"iam:putuserpolicy",
	"iam:putrolepolicy",
	"iam:setdefaultpolicyversion",
	"iam:passrole",
}

func actionMatchesDangerous(pattern string, dangerousAction string) bool {
	p := strings.ToLower(pattern)
	d := strings.ToLower(dangerousAction)
	if p == "*" || p == d {
		return true
	}
	if p == "iam:*" && strings.HasPrefix(d, "iam:") {
		return true
	}
	if strings.HasSuffix(p, "*") {
		prefix := strings.TrimSuffix(p, "*")
		if strings.HasPrefix(d, prefix) {
			return true
		}
	}
	return false
}

func hasPrivilegeEscalation(docStr string) bool {
	doc, err := url.QueryUnescape(docStr)
	if err != nil {
		doc = docStr
	}
	var docMap map[string]interface{}
	if err := json.Unmarshal([]byte(doc), &docMap); err != nil {
		return false
	}
	var statements []interface{}
	switch v := docMap["Statement"].(type) {
	case []interface{}:
		statements = v
	case map[string]interface{}:
		statements = []interface{}{v}
	}

	containsWildcardResource := func(val interface{}) bool {
		switch v := val.(type) {
		case string:
			return v == "*"
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok && s == "*" {
					return true
				}
			}
		}
		return false
	}

	getActions := func(val interface{}) []string {
		var acts []string
		switch v := val.(type) {
		case string:
			acts = append(acts, v)
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					acts = append(acts, s)
				}
			}
		}
		return acts
	}

	for _, stmtItem := range statements {
		stmt, ok := stmtItem.(map[string]interface{})
		if !ok {
			continue
		}
		effect, _ := stmt["Effect"].(string)
		if strings.EqualFold(effect, "Allow") && containsWildcardResource(stmt["Resource"]) {
			actions := getActions(stmt["Action"])
			for _, act := range actions {
				for _, dangerous := range dangerousPrivEscActions {
					if actionMatchesDangerous(act, dangerous) {
						return true
					}
				}
			}
		}
	}
	return false
}
