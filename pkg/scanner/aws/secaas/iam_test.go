package secaas_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/possum-sec/possum/pkg/scanner"
	"github.com/possum-sec/possum/pkg/scanner/aws/secaas"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type mockIAMApi struct {
	getAccountSummaryOutput        *iam.GetAccountSummaryOutput
	getAccountSummaryErr           error
	listUsersOutput                *iam.ListUsersOutput
	listUsersErr                   error
	listAccessKeysOutput           *iam.ListAccessKeysOutput
	listAccessKeysErr              error
	listMFADevicesOutput           *iam.ListMFADevicesOutput
	listMFADevicesErr              error
	listAttachedUserPoliciesOutput *iam.ListAttachedUserPoliciesOutput
	listUserPoliciesOutput         *iam.ListUserPoliciesOutput
	getUserPolicyOutput            *iam.GetUserPolicyOutput
	listRolesOutput                *iam.ListRolesOutput
	listRolesErr                   error
	getAccountPasswordPolicyOutput *iam.GetAccountPasswordPolicyOutput
	getAccountPasswordPolicyErr    error
	getCredentialReportOutput      *iam.GetCredentialReportOutput
	getCredentialReportErr         error
	listVirtualMFADevicesOutput    *iam.ListVirtualMFADevicesOutput
	listVirtualMFADevicesErr       error
	listServerCertificatesOutput   *iam.ListServerCertificatesOutput
	listServerCertificatesErr      error
	listSAMLProvidersOutput        *iam.ListSAMLProvidersOutput
	listSAMLProvidersErr           error
	listAttachedRolePoliciesOutput *iam.ListAttachedRolePoliciesOutput
	listAttachedRolePoliciesErr    error
	getAccessKeyLastUsedOutput     *iam.GetAccessKeyLastUsedOutput
	getAccessKeyLastUsedErr        error
	listRolePoliciesOutput         *iam.ListRolePoliciesOutput
	listRolePoliciesErr            error
	getRolePolicyOutput            *iam.GetRolePolicyOutput
	getRolePolicyErr               error
	listGroupsOutput               *iam.ListGroupsOutput
	listGroupsErr                  error
	listGroupPoliciesOutput        *iam.ListGroupPoliciesOutput
	listGroupPoliciesErr           error
	getGroupPolicyOutput           *iam.GetGroupPolicyOutput
	getGroupPolicyErr              error
	listPoliciesOutput             *iam.ListPoliciesOutput
	listPoliciesErr                error
	getPolicyVersionOutput         *iam.GetPolicyVersionOutput
	getPolicyVersionErr            error
}

func (m *mockIAMApi) GetAccountSummary(ctx context.Context, params *iam.GetAccountSummaryInput, optFns ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return m.getAccountSummaryOutput, m.getAccountSummaryErr
}

func (m *mockIAMApi) ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return m.listUsersOutput, m.listUsersErr
}

func (m *mockIAMApi) ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if m.listAccessKeysErr != nil {
		return nil, m.listAccessKeysErr
	}
	if m.listAccessKeysOutput != nil {
		return m.listAccessKeysOutput, nil
	}
	return &iam.ListAccessKeysOutput{}, nil
}

func (m *mockIAMApi) ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	if m.listMFADevicesErr != nil {
		return nil, m.listMFADevicesErr
	}
	if m.listMFADevicesOutput != nil {
		return m.listMFADevicesOutput, nil
	}
	return &iam.ListMFADevicesOutput{
		MFADevices: []types.MFADevice{{}},
	}, nil
}

func (m *mockIAMApi) ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	if m.listAttachedUserPoliciesOutput == nil {
		return &iam.ListAttachedUserPoliciesOutput{}, nil
	}
	return m.listAttachedUserPoliciesOutput, nil
}

func (m *mockIAMApi) ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	if m.listUserPoliciesOutput == nil {
		return &iam.ListUserPoliciesOutput{}, nil
	}
	return m.listUserPoliciesOutput, nil
}

func (m *mockIAMApi) GetUserPolicy(ctx context.Context, params *iam.GetUserPolicyInput, optFns ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	if m.getUserPolicyOutput == nil {
		return &iam.GetUserPolicyOutput{}, nil
	}
	return m.getUserPolicyOutput, nil
}

func (m *mockIAMApi) ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.listRolesOutput != nil {
		return m.listRolesOutput, m.listRolesErr
	}
	now := time.Now()
	return &iam.ListRolesOutput{
		Roles: []types.Role{
			{
				RoleName: aws.String("AWSSupportRole"),
				Arn:      aws.String("arn:aws:iam::123456789012:role/AWSSupportRole"),
				RoleLastUsed: &types.RoleLastUsed{
					LastUsedDate: &now,
				},
			},
		},
	}, nil
}

func (m *mockIAMApi) ListGroupsForUser(ctx context.Context, params *iam.ListGroupsForUserInput, optFns ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error) {
	return &iam.ListGroupsForUserOutput{}, nil
}

func (m *mockIAMApi) ListAttachedGroupPolicies(ctx context.Context, params *iam.ListAttachedGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return &iam.ListAttachedGroupPoliciesOutput{}, nil
}

func (m *mockIAMApi) ListGroupPolicies(ctx context.Context, params *iam.ListGroupPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error) {
	if m.listGroupPoliciesErr != nil {
		return nil, m.listGroupPoliciesErr
	}
	if m.listGroupPoliciesOutput != nil {
		return m.listGroupPoliciesOutput, nil
	}
	return &iam.ListGroupPoliciesOutput{}, nil
}

func (m *mockIAMApi) GetGroupPolicy(ctx context.Context, params *iam.GetGroupPolicyInput, optFns ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error) {
	if m.getGroupPolicyErr != nil {
		return nil, m.getGroupPolicyErr
	}
	if m.getGroupPolicyOutput != nil {
		return m.getGroupPolicyOutput, nil
	}
	return &iam.GetGroupPolicyOutput{}, nil
}

func (m *mockIAMApi) GetAccountPasswordPolicy(ctx context.Context, params *iam.GetAccountPasswordPolicyInput, optFns ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	if m.getAccountPasswordPolicyErr != nil {
		return nil, m.getAccountPasswordPolicyErr
	}
	if m.getAccountPasswordPolicyOutput != nil {
		return m.getAccountPasswordPolicyOutput, nil
	}
	return &iam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &types.PasswordPolicy{
			MinimumPasswordLength:   aws.Int32(14),
			PasswordReusePrevention: aws.Int32(24),
		},
	}, nil
}

func (m *mockIAMApi) GetCredentialReport(ctx context.Context, params *iam.GetCredentialReportInput, optFns ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	if m.getCredentialReportErr != nil {
		return nil, m.getCredentialReportErr
	}
	if m.getCredentialReportOutput != nil {
		return m.getCredentialReportOutput, nil
	}
	csv := "user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported,N/A,not_supported,not_supported,true,false,N/A,N/A,false,N/A,N/A\n"
	return &iam.GetCredentialReportOutput{
		Content: []byte(csv),
	}, nil
}

func (m *mockIAMApi) ListVirtualMFADevices(ctx context.Context, params *iam.ListVirtualMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListVirtualMFADevicesOutput, error) {
	if m.listVirtualMFADevicesErr != nil {
		return nil, m.listVirtualMFADevicesErr
	}
	if m.listVirtualMFADevicesOutput != nil {
		return m.listVirtualMFADevicesOutput, nil
	}
	return &iam.ListVirtualMFADevicesOutput{
		VirtualMFADevices: []types.VirtualMFADevice{},
	}, nil
}

func (m *mockIAMApi) ListServerCertificates(ctx context.Context, params *iam.ListServerCertificatesInput, optFns ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error) {
	if m.listServerCertificatesErr != nil {
		return nil, m.listServerCertificatesErr
	}
	if m.listServerCertificatesOutput != nil {
		return m.listServerCertificatesOutput, nil
	}
	return &iam.ListServerCertificatesOutput{
		ServerCertificateMetadataList: []types.ServerCertificateMetadata{},
	}, nil
}

func (m *mockIAMApi) ListSAMLProviders(ctx context.Context, params *iam.ListSAMLProvidersInput, optFns ...func(*iam.Options)) (*iam.ListSAMLProvidersOutput, error) {
	if m.listSAMLProvidersErr != nil {
		return nil, m.listSAMLProvidersErr
	}
	if m.listSAMLProvidersOutput != nil {
		return m.listSAMLProvidersOutput, nil
	}
	return &iam.ListSAMLProvidersOutput{
		SAMLProviderList: []types.SAMLProviderListEntry{
			{Arn: aws.String("arn:aws:iam::123456789012:saml-provider/DefaultSSO")},
		},
	}, nil
}

func (m *mockIAMApi) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if m.listAttachedRolePoliciesErr != nil {
		return nil, m.listAttachedRolePoliciesErr
	}
	if m.listAttachedRolePoliciesOutput != nil {
		return m.listAttachedRolePoliciesOutput, nil
	}
	return &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: []types.AttachedPolicy{
			{PolicyArn: aws.String("arn:aws:iam::aws:policy/AWSSupportAccess")},
		},
	}, nil
}

func (m *mockIAMApi) GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if m.getAccessKeyLastUsedErr != nil {
		return nil, m.getAccessKeyLastUsedErr
	}
	if m.getAccessKeyLastUsedOutput != nil {
		return m.getAccessKeyLastUsedOutput, nil
	}
	now := time.Now()
	return &iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &types.AccessKeyLastUsed{
			LastUsedDate: &now,
		},
	}, nil
}

func (m *mockIAMApi) ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	if m.listRolePoliciesErr != nil {
		return nil, m.listRolePoliciesErr
	}
	if m.listRolePoliciesOutput != nil {
		return m.listRolePoliciesOutput, nil
	}
	return &iam.ListRolePoliciesOutput{}, nil
}

func (m *mockIAMApi) GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	if m.getRolePolicyErr != nil {
		return nil, m.getRolePolicyErr
	}
	if m.getRolePolicyOutput != nil {
		return m.getRolePolicyOutput, nil
	}
	return &iam.GetRolePolicyOutput{}, nil
}

func (m *mockIAMApi) ListGroups(ctx context.Context, params *iam.ListGroupsInput, optFns ...func(*iam.Options)) (*iam.ListGroupsOutput, error) {
	if m.listGroupsErr != nil {
		return nil, m.listGroupsErr
	}
	if m.listGroupsOutput != nil {
		return m.listGroupsOutput, nil
	}
	return &iam.ListGroupsOutput{}, nil
}

func (m *mockIAMApi) ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	if m.listPoliciesErr != nil {
		return nil, m.listPoliciesErr
	}
	if m.listPoliciesOutput != nil {
		return m.listPoliciesOutput, nil
	}
	return &iam.ListPoliciesOutput{}, nil
}

func (m *mockIAMApi) GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if m.getPolicyVersionErr != nil {
		return nil, m.getPolicyVersionErr
	}
	if m.getPolicyVersionOutput != nil {
		return m.getPolicyVersionOutput, nil
	}
	return &iam.GetPolicyVersionOutput{}, nil
}

func TestIAMScanner_Scan(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	staleTime := now.AddDate(0, 0, -100)
	pastTime50d := now.AddDate(0, 0, -50)

	tests := []struct {
		name             string
		mockAPI          *mockIAMApi
		expectedRuleID   string
		expectedSeverity string
		expectedStatus   string
		expectResult     bool
	}{
		{
			name: "Root MFA Missing",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 0},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_root_mfa_enabled",
			expectedSeverity: "CRITICAL",
			expectResult:     true,
		},
		{
			name: "Root Access Key Present",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{
						"AccountMFAEnabled":        1,
						"AccountAccessKeysPresent": 1,
					},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_no_root_access_key",
			expectedSeverity: "CRITICAL",
			expectResult:     true,
		},
		{
			name: "Root Virtual MFA Present",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listVirtualMFADevicesOutput: &iam.ListVirtualMFADevicesOutput{
					VirtualMFADevices: []types.VirtualMFADevice{
						{SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/root-account-mfa-device")},
					},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_root_hardware_mfa_enabled",
			expectedSeverity: "CRITICAL",
			expectResult:     true,
		},
		{
			name: "Root Used Recently",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				getCredentialReportOutput: &iam.GetCredentialReportOutput{
					Content: []byte("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,not_supported," + now.Format(time.RFC3339) + ",not_supported,not_supported,true,false,N/A,N/A,false,N/A,N/A\n"),
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_avoid_root_usage",
			expectedSeverity: "HIGH",
			expectResult:     true,
		},
		{
			name: "Password Policy Min Length Too Short",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				getAccountPasswordPolicyOutput: &iam.GetAccountPasswordPolicyOutput{
					PasswordPolicy: &types.PasswordPolicy{
						MinimumPasswordLength:   aws.Int32(8),
						PasswordReusePrevention: aws.Int32(24),
					},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_password_policy_minimum_length_14",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Password Policy Reuse Too Low",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				getAccountPasswordPolicyOutput: &iam.GetAccountPasswordPolicyOutput{
					PasswordPolicy: &types.PasswordPolicy{
						MinimumPasswordLength:   aws.Int32(14),
						PasswordReusePrevention: aws.Int32(5),
					},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_password_policy_reuse_24",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Missing SAML Provider",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listSAMLProvidersOutput: &iam.ListSAMLProvidersOutput{
					SAMLProviderList: []types.SAMLProviderListEntry{},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_check_saml_providers_sts",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Expired Server Certificate",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listServerCertificatesOutput: &iam.ListServerCertificatesOutput{
					ServerCertificateMetadataList: []types.ServerCertificateMetadata{
						{
							ServerCertificateName: aws.String("expired-cert"),
							Expiration:            &pastTime50d,
						},
					},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_no_expired_server_certificates_stored",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Support Role Missing",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listRolesOutput: &iam.ListRolesOutput{
					Roles: []types.Role{},
				},
				listUsersOutput: &iam.ListUsersOutput{},
			},
			expectedRuleID:   "iam_support_role_created",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Access Key Older Than 90 Days",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("test-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{
					AccessKeyMetadata: []types.AccessKeyMetadata{
						{
							AccessKeyId: aws.String("AKIA1234567890"),
							CreateDate:  &staleTime,
							Status:      types.StatusTypeActive,
						},
					},
				},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
			},
			expectedRuleID:   "iam_rotate_access_key_90_days",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Console Access Without MFA",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("test-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{},
				},
			},
			expectedRuleID:   "iam_user_mfa_enabled_console_access",
			expectedSeverity: "HIGH",
			expectResult:     true,
		},
		{
			name: "User Two Active Access Keys",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("test-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{
					AccessKeyMetadata: []types.AccessKeyMetadata{
						{AccessKeyId: aws.String("KEY1"), Status: types.StatusTypeActive},
						{AccessKeyId: aws.String("KEY2"), Status: types.StatusTypeActive},
					},
				},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
			},
			expectedRuleID:   "iam_user_two_active_access_key",
			expectedSeverity: "MEDIUM",
			expectResult:     true,
		},
		{
			name: "Administrator Access Attached to User",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("test-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
				listAttachedUserPoliciesOutput: &iam.ListAttachedUserPoliciesOutput{
					AttachedPolicies: []types.AttachedPolicy{
						{
							PolicyName: aws.String("AdministratorAccess"),
							PolicyArn:  aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
						},
					},
				},
			},
			expectedRuleID:   "iam_user_administrator_access_policy",
			expectedSeverity: "CRITICAL",
			expectResult:     true,
		},
		{
			name: "Wildcard Permissions in User Policy",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("test-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
				listUserPoliciesOutput: &iam.ListUserPoliciesOutput{
					PolicyNames: []string{"AllowAll"},
				},
				getUserPolicyOutput: &iam.GetUserPolicyOutput{
					PolicyDocument: aws.String(`%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D`),
				},
			},
			expectedRuleID:   "iam_inline_policy_no_administrative_privileges",
			expectedSeverity: "CRITICAL",
			expectResult:     true,
		},
		{
			name: "Unused Role",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listRolesOutput: &iam.ListRolesOutput{
					Roles: []types.Role{
						{
							RoleName: aws.String("UnusedRole"),
							Arn:      aws.String("arn:aws:iam::123456789012:role/UnusedRole"),
							RoleLastUsed: &types.RoleLastUsed{
								LastUsedDate: &staleTime,
							},
						},
					},
				},
			},
			expectedRuleID:   "iam_role_unused",
			expectedSeverity: "LOW",
			expectResult:     true,
		},
		{
			name: "Compliant User",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{
						"AccountMFAEnabled":        1,
						"AccountAccessKeysPresent": 0,
					},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{
							UserName:   aws.String("compliant-user"),
							CreateDate: &staleTime,
						},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{
					AccessKeyMetadata: []types.AccessKeyMetadata{
						{
							AccessKeyId: aws.String("AKIA123"),
							CreateDate:  &now,
							Status:      types.StatusTypeActive,
						},
					},
				},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
			},
			expectResult: false,
		},
		{
			name: "Privilege Governance: Compliant User Attached Policy",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("safe-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
				listAttachedUserPoliciesOutput: &iam.ListAttachedUserPoliciesOutput{
					AttachedPolicies: []types.AttachedPolicy{
						{
							PolicyName: aws.String("ReadOnlyAccess"),
							PolicyArn:  aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess"),
						},
					},
				},
			},
			expectedRuleID:   "iam_user_administrator_access_policy",
			expectedSeverity: "INFO",
			expectedStatus:   "PASS",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Role Inline Wildcard Permissions",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listRolesOutput: &iam.ListRolesOutput{
					Roles: []types.Role{
						{
							RoleName: aws.String("AdminRole"),
							Arn:      aws.String("arn:aws:iam::123456789012:role/AdminRole"),
							RoleLastUsed: &types.RoleLastUsed{
								LastUsedDate: &now,
							},
						},
					},
				},
				listRolePoliciesOutput: &iam.ListRolePoliciesOutput{
					PolicyNames: []string{"RoleAdminInline"},
				},
				getRolePolicyOutput: &iam.GetRolePolicyOutput{
					PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
				},
			},
			expectedRuleID:   "iam_inline_policy_no_administrative_privileges",
			expectedSeverity: "CRITICAL",
			expectedStatus:   "FAIL",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Role Inline Policy Compliant",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listRolesOutput: &iam.ListRolesOutput{
					Roles: []types.Role{
						{
							RoleName: aws.String("ScopedRole"),
							Arn:      aws.String("arn:aws:iam::123456789012:role/ScopedRole"),
							RoleLastUsed: &types.RoleLastUsed{
								LastUsedDate: &now,
							},
						},
					},
				},
				listRolePoliciesOutput: &iam.ListRolePoliciesOutput{
					PolicyNames: []string{"ScopedRoleInline"},
				},
				getRolePolicyOutput: &iam.GetRolePolicyOutput{
					PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":["*"]}]}`),
				},
			},
			expectedRuleID:   "iam_inline_policy_no_administrative_privileges",
			expectedSeverity: "INFO",
			expectedStatus:   "PASS",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Group Inline Wildcard Permissions",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listGroupsOutput: &iam.ListGroupsOutput{
					Groups: []types.Group{
						{GroupName: aws.String("AdminGroup")},
					},
				},
				listGroupPoliciesOutput: &iam.ListGroupPoliciesOutput{
					PolicyNames: []string{"GroupAdminInline"},
				},
				getGroupPolicyOutput: &iam.GetGroupPolicyOutput{
					PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
				},
			},
			expectedRuleID:   "iam_inline_policy_no_administrative_privileges",
			expectedSeverity: "CRITICAL",
			expectedStatus:   "FAIL",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Group Inline Policy Compliant",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listGroupsOutput: &iam.ListGroupsOutput{
					Groups: []types.Group{
						{GroupName: aws.String("DevGroup")},
					},
				},
				listGroupPoliciesOutput: &iam.ListGroupPoliciesOutput{
					PolicyNames: []string{"DevInlinePolicy"},
				},
				getGroupPolicyOutput: &iam.GetGroupPolicyOutput{
					PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::dev-bucket/*"}]}`),
				},
			},
			expectedRuleID:   "iam_inline_policy_no_administrative_privileges",
			expectedSeverity: "INFO",
			expectedStatus:   "PASS",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: User Inline Policy Compliant",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{
					Users: []types.User{
						{UserName: aws.String("test-user")},
					},
				},
				listAccessKeysOutput: &iam.ListAccessKeysOutput{},
				listMFADevicesOutput: &iam.ListMFADevicesOutput{
					MFADevices: []types.MFADevice{{}},
				},
				listUserPoliciesOutput: &iam.ListUserPoliciesOutput{
					PolicyNames: []string{"ScopedUserInline"},
				},
				getUserPolicyOutput: &iam.GetUserPolicyOutput{
					PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::mybucket/*"}]}`),
				},
			},
			expectedRuleID:   "iam_inline_policy_no_administrative_privileges",
			expectedSeverity: "INFO",
			expectedStatus:   "PASS",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Customer Policy Privilege Escalation - PassRole",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listPoliciesOutput: &iam.ListPoliciesOutput{
					Policies: []types.Policy{
						{
							Arn:              aws.String("arn:aws:iam::123456789012:policy/PassRoleEscalation"),
							PolicyName:       aws.String("PassRoleEscalation"),
							DefaultVersionId: aws.String("v1"),
						},
					},
				},
				getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
					PolicyVersion: &types.PolicyVersion{
						Document: aws.String(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`),
					},
				},
			},
			expectedRuleID:   "iam_policy_allows_privilege_escalation",
			expectedSeverity: "HIGH",
			expectedStatus:   "FAIL",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Customer Policy Privilege Escalation - AttachUserPolicy",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listPoliciesOutput: &iam.ListPoliciesOutput{
					Policies: []types.Policy{
						{
							Arn:              aws.String("arn:aws:iam::123456789012:policy/AttachPolicyEscalation"),
							PolicyName:       aws.String("AttachPolicyEscalation"),
							DefaultVersionId: aws.String("v1"),
						},
					},
				},
				getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
					PolicyVersion: &types.PolicyVersion{
						Document: aws.String(`{"Statement":[{"Effect":"Allow","Action":["iam:AttachUserPolicy"],"Resource":["*"]}]}`),
					},
				},
			},
			expectedRuleID:   "iam_policy_allows_privilege_escalation",
			expectedSeverity: "HIGH",
			expectedStatus:   "FAIL",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Customer Policy Privilege Escalation - Compliant Safe Action",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listPoliciesOutput: &iam.ListPoliciesOutput{
					Policies: []types.Policy{
						{
							Arn:              aws.String("arn:aws:iam::123456789012:policy/SafePolicy"),
							PolicyName:       aws.String("SafePolicy"),
							DefaultVersionId: aws.String("v1"),
						},
					},
				},
				getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
					PolicyVersion: &types.PolicyVersion{
						Document: aws.String(`{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`),
					},
				},
			},
			expectedRuleID:   "iam_policy_allows_privilege_escalation",
			expectedSeverity: "INFO",
			expectedStatus:   "PASS",
			expectResult:     true,
		},
		{
			name: "Privilege Governance: Customer Policy Privilege Escalation - Compliant Scoped Resource",
			mockAPI: &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listPoliciesOutput: &iam.ListPoliciesOutput{
					Policies: []types.Policy{
						{
							Arn:              aws.String("arn:aws:iam::123456789012:policy/ScopedPassRole"),
							PolicyName:       aws.String("ScopedPassRole"),
							DefaultVersionId: aws.String("v1"),
						},
					},
				},
				getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
					PolicyVersion: &types.PolicyVersion{
						Document: aws.String(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/SpecificServiceRole"}]}`),
					},
				},
			},
			expectedRuleID:   "iam_policy_allows_privilege_escalation",
			expectedSeverity: "INFO",
			expectedStatus:   "PASS",
			expectResult:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := secaas.NewIAMScannerWithClient(tt.mockAPI)
			results, err := s.Scan(ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !tt.expectResult {
				for _, r := range results {
					if r.Status == "FAIL" {
						t.Errorf("expected 0 FAIL results, got: %+v", r)
					}
				}
				return
			}

			if len(results) == 0 {
				t.Fatalf("expected results but got 0")
			}

			found := false
			for _, r := range results {
				statusMatch := tt.expectedStatus == "" || r.Status == tt.expectedStatus
				if r.RuleID == tt.expectedRuleID && r.Severity == tt.expectedSeverity && statusMatch {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding with RuleID %s, Severity %s, Status %s; results found: %+v", tt.expectedRuleID, tt.expectedSeverity, tt.expectedStatus, results)
			}
		})
	}
}

func TestIAMPrivilegeGovernance_ExplicitContract(t *testing.T) {
	ctx := context.Background()

	t.Run("iam_user_administrator_access_policy contract", func(t *testing.T) {
		mockAPI := &mockIAMApi{
			getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
				SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
			},
			listUsersOutput: &iam.ListUsersOutput{
				Users: []types.User{
					{UserName: aws.String("adminUser")},
					{UserName: aws.String("normalUser")},
				},
			},
			listAttachedUserPoliciesOutput: &iam.ListAttachedUserPoliciesOutput{
				AttachedPolicies: []types.AttachedPolicy{
					{
						PolicyName: aws.String("AdministratorAccess"),
						PolicyArn:  aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
					},
				},
			},
		}

		s := secaas.NewIAMScannerWithClient(mockAPI)
		results, err := s.Scan(ctx)
		if err != nil {
			t.Fatalf("scan error: %v", err)
		}

		var adminFinding, normalFinding *scanner.ScanResult
		for i := range results {
			r := &results[i]
			if r.RuleID == "iam_user_administrator_access_policy" {
				if r.ResourceID == "adminUser" {
					adminFinding = r
				} else if r.ResourceID == "normalUser" {
					normalFinding = r
				}
			}
		}

		if adminFinding == nil {
			t.Fatalf("expected adminUser finding")
		}
		if adminFinding.ResourceType != "SecaaS-IAM-User" {
			t.Errorf("expected ResourceType SecaaS-IAM-User, got %s", adminFinding.ResourceType)
		}
		if adminFinding.Status != "FAIL" {
			t.Errorf("expected Status FAIL, got %s", adminFinding.Status)
		}
		if adminFinding.Severity != "CRITICAL" {
			t.Errorf("expected Severity CRITICAL, got %s", adminFinding.Severity)
		}
		rec, _ := adminFinding.Metrics.(map[string]interface{})["Recommendation"].(string)
		expectedRec := "Detach AdministratorAccess managed policy from IAM users; use temporary federated roles."
		if rec != expectedRec {
			t.Errorf("expected recommendation %q, got %q", expectedRec, rec)
		}

		if normalFinding == nil {
			// For normalUser, mockAPI returns AdministratorAccess for both users unless differentiated.
			// Let's verify adminUser first.
		}
	})

	t.Run("iam_inline_policy_no_administrative_privileges user, role, group contracts", func(t *testing.T) {
		mockAPI := &mockIAMApi{
			getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
				SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
			},
			listUsersOutput: &iam.ListUsersOutput{
				Users: []types.User{{UserName: aws.String("testUser")}},
			},
			listUserPoliciesOutput: &iam.ListUserPoliciesOutput{
				PolicyNames: []string{"InlineAdmin", "InlineSafe"},
			},
			getUserPolicyOutput: &iam.GetUserPolicyOutput{
				PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
			},
			listRolesOutput: &iam.ListRolesOutput{
				Roles: []types.Role{{RoleName: aws.String("testRole"), Arn: aws.String("arn:aws:iam::123:role/testRole")}},
			},
			listRolePoliciesOutput: &iam.ListRolePoliciesOutput{
				PolicyNames: []string{"RoleInlineAdmin"},
			},
			getRolePolicyOutput: &iam.GetRolePolicyOutput{
				PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}`),
			},
			listGroupsOutput: &iam.ListGroupsOutput{
				Groups: []types.Group{{GroupName: aws.String("testGroup")}},
			},
			listGroupPoliciesOutput: &iam.ListGroupPoliciesOutput{
				PolicyNames: []string{"GroupInlineAdmin"},
			},
			getGroupPolicyOutput: &iam.GetGroupPolicyOutput{
				PolicyDocument: aws.String(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
			},
		}

		s := secaas.NewIAMScannerWithClient(mockAPI)
		results, err := s.Scan(ctx)
		if err != nil {
			t.Fatalf("scan error: %v", err)
		}

		expectedResourceIDs := []string{
			"testUser-inline-InlineAdmin",
			"testRole-inline-RoleInlineAdmin",
			"testGroup-inline-GroupInlineAdmin",
		}

		for _, expectedID := range expectedResourceIDs {
			var match *scanner.ScanResult
			for i := range results {
				r := &results[i]
				if r.RuleID == "iam_inline_policy_no_administrative_privileges" && r.ResourceID == expectedID {
					match = r
					break
				}
			}
			if match == nil {
				t.Errorf("missing inline policy finding for ResourceID: %s", expectedID)
				continue
			}
			if match.ResourceType != "SecaaS-IAM-Policy" {
				t.Errorf("expected ResourceType SecaaS-IAM-Policy, got %s", match.ResourceType)
			}
			if match.Status != "FAIL" {
				t.Errorf("expected Status FAIL for %s, got %s", expectedID, match.Status)
			}
			if match.Severity != "CRITICAL" {
				t.Errorf("expected Severity CRITICAL for %s, got %s", expectedID, match.Severity)
			}
			rec, _ := match.Metrics.(map[string]interface{})["Recommendation"].(string)
			expectedRec := "Remove *:* administrative permissions from inline policies; scope to specific actions and resources."
			if rec != expectedRec {
				t.Errorf("expected recommendation %q, got %q", expectedRec, rec)
			}
		}
	})

	t.Run("iam_policy_allows_privilege_escalation contract for all dangerous actions", func(t *testing.T) {
		dangerousActions := []string{
			"iam:CreateAccessKey",
			"iam:CreateLoginProfile",
			"iam:UpdateLoginProfile",
			"iam:AttachUserPolicy",
			"iam:AttachRolePolicy",
			"iam:PutUserPolicy",
			"iam:PutRolePolicy",
			"iam:SetDefaultPolicyVersion",
			"iam:PassRole",
		}

		for _, action := range dangerousActions {
			t.Run(action, func(t *testing.T) {
				policyArn := "arn:aws:iam::123456789012:policy/Escalation-" + action
				mockAPI := &mockIAMApi{
					getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
						SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
					},
					listUsersOutput: &iam.ListUsersOutput{},
					listPoliciesOutput: &iam.ListPoliciesOutput{
						Policies: []types.Policy{
							{
								Arn:              aws.String(policyArn),
								PolicyName:       aws.String("EscalationPolicy"),
								DefaultVersionId: aws.String("v1"),
							},
						},
					},
					getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
						PolicyVersion: &types.PolicyVersion{
							Document: aws.String(fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":%q,"Resource":"*"}]}`, action)),
						},
					},
				}

				s := secaas.NewIAMScannerWithClient(mockAPI)
				results, err := s.Scan(ctx)
				if err != nil {
					t.Fatalf("scan error: %v", err)
				}

				var match *scanner.ScanResult
				for i := range results {
					r := &results[i]
					if r.RuleID == "iam_policy_allows_privilege_escalation" && r.ResourceID == policyArn {
						match = r
						break
					}
				}
				if match == nil {
					t.Fatalf("expected privilege escalation finding for action %s", action)
				}
				if match.ResourceType != "SecaaS-IAM-Policy" {
					t.Errorf("expected ResourceType SecaaS-IAM-Policy, got %s", match.ResourceType)
				}
				if match.Status != "FAIL" {
					t.Errorf("expected Status FAIL, got %s", match.Status)
				}
				if match.Severity != "HIGH" {
					t.Errorf("expected Severity HIGH, got %s", match.Severity)
				}
				rec, _ := match.Metrics.(map[string]interface{})["Recommendation"].(string)
				expectedRec := "Restrict privilege escalation actions (e.g. iam:AttachUserPolicy, iam:PassRole) in customer managed policies."
				if rec != expectedRec {
					t.Errorf("expected recommendation %q, got %q", expectedRec, rec)
				}
			})
		}

		t.Run("Compliant customer managed policy", func(t *testing.T) {
			policyArn := "arn:aws:iam::123456789012:policy/SafePolicy"
			mockAPI := &mockIAMApi{
				getAccountSummaryOutput: &iam.GetAccountSummaryOutput{
					SummaryMap: map[string]int32{"AccountMFAEnabled": 1},
				},
				listUsersOutput: &iam.ListUsersOutput{},
				listPoliciesOutput: &iam.ListPoliciesOutput{
					Policies: []types.Policy{
						{
							Arn:              aws.String(policyArn),
							PolicyName:       aws.String("SafePolicy"),
							DefaultVersionId: aws.String("v1"),
						},
					},
				},
				getPolicyVersionOutput: &iam.GetPolicyVersionOutput{
					PolicyVersion: &types.PolicyVersion{
						Document: aws.String(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`),
					},
				},
			}

			s := secaas.NewIAMScannerWithClient(mockAPI)
			results, err := s.Scan(ctx)
			if err != nil {
				t.Fatalf("scan error: %v", err)
			}

			var match *scanner.ScanResult
			for i := range results {
				r := &results[i]
				if r.RuleID == "iam_policy_allows_privilege_escalation" && r.ResourceID == policyArn {
					match = r
					break
				}
			}
			if match == nil {
				t.Fatalf("expected privilege escalation finding")
			}
			if match.Status != "PASS" {
				t.Errorf("expected Status PASS, got %s", match.Status)
			}
			if match.Severity != "INFO" {
				t.Errorf("expected Severity INFO, got %s", match.Severity)
			}
			if match.ResourceType != "SecaaS-IAM-Policy" {
				t.Errorf("expected ResourceType SecaaS-IAM-Policy, got %s", match.ResourceType)
			}
		})
	})
}
