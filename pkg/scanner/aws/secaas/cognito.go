package secaas

import (
	"context"
	"fmt"

	"github.com/possum-sec/possum/pkg/scanner"
	graph "github.com/possum-sec/possum/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type CognitoScanner struct {
	client *cognitoidentityprovider.Client
}

func NewCognitoScanner(cfg aws.Config) *CognitoScanner {
	return &CognitoScanner{
		client: cognitoidentityprovider.NewFromConfig(cfg),
	}
}

func (s *CognitoScanner) Name() string {
	return "Cognito-SecaaS-Scanner"
}

func (s *CognitoScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := 0
	if val, ok := ctx.Value("ResourceLimit").(int); ok {
		limit = val
	}
	processedCount := 0
	var results []scanner.ScanResult

	// List User Pools
	paginator := cognitoidentityprovider.NewListUserPoolsPaginator(s.client, &cognitoidentityprovider.ListUserPoolsInput{
		MaxResults: aws.Int32(60),
	})

	for paginator.HasMorePages() {
		if limit > 0 && processedCount >= limit {
			break
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, pool := range page.UserPools {
			if limit > 0 && processedCount >= limit {
				break
			}
			processedCount++

			poolID := aws.ToString(pool.Id)
			poolName := aws.ToString(pool.Name)

			// Describe user pool to get MfaConfiguration
			descOutput, err := s.client.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{
				UserPoolId: aws.String(poolID),
			})
			if err != nil {
				return nil, err
			}

			if descOutput.UserPool != nil {
				mfaConfig := descOutput.UserPool.MfaConfiguration

				// Flag User Pools lacking MFA enforcement
				if mfaConfig == types.UserPoolMfaTypeOff || string(mfaConfig) == "OFF" || string(mfaConfig) == "" {
					results = append(results, scanner.ScanResult{
						ResourceID:   poolID,
						ResourceType: "SecaaS-Cognito",
						Region:       "global",
						Status:       "FAIL",
						IsOrphaned:   false,
						RuleID:       "cognito_user_pool_mfa_enabled",
						Severity:     "HIGH",
						Metrics: map[string]interface{}{
							"UserPoolName":     poolName,
							"MfaConfiguration": string(mfaConfig),
							"StatusExtended":   fmt.Sprintf("Cognito User Pool %s (%s) has MFA enforcement disabled.", poolName, poolID),
							"SecurityIssues":   []string{"Cognito User Pool has MFA enforcement turned off"},
							"Recommendation":   "Enable Multi-Factor Authentication (MFA) enforcement for the Cognito User Pool.",
						},
						Nodes: []graph.Node{{ID: poolID, NodeType: "SecaaS-Cognito"}},
					})
				}
			}
		}
	}

	return results, nil
}
