package aws

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

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

// ResolveCrossAccountRoleARN builds an IAM Role ARN targeting accountID.
// If roleNameOrARN is already an IAM Role ARN (e.g. from --role-arn), the role name/path
// and partition are extracted so that each target member account gets its own role ARN.
func ResolveCrossAccountRoleARN(accountID, roleNameOrARN string) string {
	roleNameOrARN = strings.TrimSpace(roleNameOrARN)
	if roleNameOrARN == "" {
		roleNameOrARN = "OrganizationAccountAccessRole"
	}

	partition := "aws"
	extractedRoleName := roleNameOrARN

	if strings.HasPrefix(roleNameOrARN, "arn:") {
		parts := strings.SplitN(roleNameOrARN, ":", 6)
		if len(parts) >= 2 && parts[1] != "" {
			partition = parts[1]
		}
		if idx := strings.Index(roleNameOrARN, ":role/"); idx != -1 {
			extractedRoleName = strings.TrimPrefix(roleNameOrARN[idx+len(":role/"):], "/")
		} else if len(parts) == 6 {
			extractedRoleName = strings.TrimPrefix(parts[5], "role/")
			extractedRoleName = strings.TrimPrefix(extractedRoleName, "/")
		}
	} else if idx := strings.Index(roleNameOrARN, ":role/"); idx != -1 {
		extractedRoleName = strings.TrimPrefix(roleNameOrARN[idx+len(":role/"):], "/")
	} else {
		extractedRoleName = strings.TrimPrefix(roleNameOrARN, "/")
	}

	if extractedRoleName == "" {
		extractedRoleName = "OrganizationAccountAccessRole"
	}

	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, extractedRoleName)
}

func unwrapRootTransport(client aws.HTTPClient) http.RoundTripper {
	httpClient, ok := client.(*http.Client)
	if !ok || httpClient == nil || httpClient.Transport == nil {
		return http.DefaultTransport
	}
	rt := httpClient.Transport
	for {
		switch t := rt.(type) {
		case *ThrottledTransport:
			rt = t.Base()
		case *AWSCacheTransport:
			rt = t.Base()
		default:
			if rt == nil {
				return http.DefaultTransport
			}
			return rt
		}
	}
}

// CreateCrossAccountConfig returns a new aws.Config configured to assume the target role in accountID.
func CreateCrossAccountConfig(ctx context.Context, baseCfg aws.Config, accountID, roleNameOrARN, externalID string) (aws.Config, error) {
	if accountID == "" {
		return baseCfg, fmt.Errorf("accountID cannot be empty")
	}

	roleARN := ResolveCrossAccountRoleARN(accountID, roleNameOrARN)

	stsClient := sts.NewFromConfig(baseCfg)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(o *stscreds.AssumeRoleOptions) {
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
		o.RoleSessionName = fmt.Sprintf("PossumScan-%s", accountID)
	})

	cfgCopy := baseCfg.Copy()
	cfgCopy.Credentials = aws.NewCredentialsCache(provider)

	rootTransport := unwrapRootTransport(baseCfg.HTTPClient)
	baseTransport := rootTransport
	if os.Getenv("AWS_DISABLE_CACHE") != "true" {
		baseTransport = GetSharedAWSCache().ForAccount(accountID, rootTransport)
	}
	throttledTransport := NewThrottledTransport(baseTransport, accountID, GetSharedAPITelemetry())
	cfgCopy.HTTPClient = &http.Client{
		Transport: throttledTransport,
		Timeout:   45 * time.Second,
	}

	return cfgCopy, nil
}
