package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AccountInfo represents metadata for an AWS account within an Organization.
type AccountInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Status string `json:"status"`
	ARN    string `json:"arn"`
}

// OrganizationsListAccountsAPI defines the interface for querying AWS Organizations accounts.
type OrganizationsListAccountsAPI interface {
	ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
}

// DiscoverOrganizationAccounts queries AWS Organizations to list all ACTIVE member accounts.
func DiscoverOrganizationAccounts(ctx context.Context, cfg aws.Config) ([]AccountInfo, error) {
	client := organizations.NewFromConfig(cfg)
	return DiscoverOrganizationAccountsWithClient(ctx, client)
}

// DiscoverOrganizationAccountsWithClient allows injecting a mock Organizations API client.
func DiscoverOrganizationAccountsWithClient(ctx context.Context, client OrganizationsListAccountsAPI) ([]AccountInfo, error) {
	var accounts []AccountInfo
	var nextToken *string

	for {
		output, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("organizations:ListAccounts failed: %w", err)
		}

		for _, acct := range output.Accounts {
			// Only include ACTIVE accounts
			if acct.Status != orgtypes.AccountStatusActive {
				continue
			}

			accounts = append(accounts, AccountInfo{
				ID:     aws.ToString(acct.Id),
				Name:   aws.ToString(acct.Name),
				Email:  aws.ToString(acct.Email),
				Status: string(acct.Status),
				ARN:    aws.ToString(acct.Arn),
			})
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].ID < accounts[j].ID
	})

	return accounts, nil
}

// CreateCrossAccountConfig returns a new aws.Config configured to assume the target role in accountID.
func CreateCrossAccountConfig(ctx context.Context, baseCfg aws.Config, accountID, roleName, externalID string) (aws.Config, error) {
	if accountID == "" {
		return baseCfg, fmt.Errorf("accountID cannot be empty")
	}
	if roleName == "" {
		roleName = "OrganizationAccountAccessRole"
	}

	roleARN := roleName
	if !strings.HasPrefix(roleName, "arn:aws:iam::") {
		roleARN = fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	}

	stsClient := sts.NewFromConfig(baseCfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
		o.RoleSessionName = fmt.Sprintf("PossumScan-%s", accountID)
	})

	cfgCopy := baseCfg.Copy()
	cfgCopy.Credentials = aws.NewCredentialsCache(provider)
	return cfgCopy, nil
}
