//go:build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/possum-security/possum-core/pkg/scanner/aws/secaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalStack_IAMScanner_AdminRole(t *testing.T) {
	ctx := context.Background()
	cfg := setupLocalStack(t, ctx)

	iamClient := iam.NewFromConfig(cfg)

	roleName := fmt.Sprintf("possum-test-role-%d", time.Now().UnixNano()%100000000)
	assumeRoleDoc := `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "ec2.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`

	// Create test IAM role
	_, err := iamClient.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(roleName),
		AssumeRolePolicyDocument: aws.String(assumeRoleDoc),
	})
	require.NoError(t, err, "failed to create test IAM role")

	t.Cleanup(func() {
		_, _ = iamClient.DetachRolePolicy(context.Background(), &iam.DetachRolePolicyInput{
			RoleName:  aws.String(roleName),
			PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
		})
		_, _ = iamClient.DeleteRole(context.Background(), &iam.DeleteRoleInput{
			RoleName: aws.String(roleName),
		})
	})

	// Attach AWS managed AdministratorAccess policy
	_, err = iamClient.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(roleName),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})
	require.NoError(t, err, "failed to attach AdministratorAccess policy to role")

	// Run IAM SecaaS scanner
	iamScanner := secaas.NewIAMScanner(cfg)
	results, err := iamScanner.Scan(ctx)
	require.NoError(t, err, "IAM scanner failed to execute")

	var foundAdminAccessRule bool
	for _, res := range results {
		if res.ResourceID == roleName && res.RuleID == "iam_role_admin_access" && res.Status == "FAIL" {
			foundAdminAccessRule = true
			break
		}
	}

	assert.True(t, foundAdminAccessRule, "expected iam_role_admin_access FAIL finding for role %s", roleName)
}
