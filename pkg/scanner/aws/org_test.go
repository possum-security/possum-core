package aws_test

import (
	"context"
	"errors"
	"testing"

	scanneraws "github.com/amirmahdy/possum-core/pkg/scanner/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

type mockOrganizationsAPI struct {
	output *organizations.ListAccountsOutput
	err    error
}

func (m *mockOrganizationsAPI) ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestDiscoverOrganizationAccountsWithClient(t *testing.T) {
	t.Run("successfully lists active accounts and excludes suspended", func(t *testing.T) {
		mock := &mockOrganizationsAPI{
			output: &organizations.ListAccountsOutput{
				Accounts: []orgtypes.Account{
					{
						Id:     aws.String("111122223333"),
						Name:   aws.String("Production"),
						Email:  aws.String("prod@example.com"),
						Status: orgtypes.AccountStatusActive,
						Arn:    aws.String("arn:aws:organizations::123:account/o-abc/111122223333"),
					},
					{
						Id:     aws.String("444455556666"),
						Name:   aws.String("Suspended-Dev"),
						Email:  aws.String("dev@example.com"),
						Status: orgtypes.AccountStatusSuspended,
					},
					{
						Id:     aws.String("222233334444"),
						Name:   aws.String("Staging"),
						Email:  aws.String("staging@example.com"),
						Status: orgtypes.AccountStatusActive,
					},
				},
			},
		}

		accounts, err := scanneraws.DiscoverOrganizationAccountsWithClient(context.Background(), mock)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(accounts) != 2 {
			t.Fatalf("expected 2 active accounts, got %d", len(accounts))
		}
		if accounts[0].ID != "111122223333" || accounts[1].ID != "222233334444" {
			t.Errorf("expected sorted accounts, got %v", accounts)
		}
	})

	t.Run("api failure propagates error", func(t *testing.T) {
		mock := &mockOrganizationsAPI{
			err: errors.New("AccessDeniedException"),
		}

		_, err := scanneraws.DiscoverOrganizationAccountsWithClient(context.Background(), mock)
		if err == nil {
			t.Error("expected error on AccessDeniedException, got nil")
		}
	})
}

func TestCreateCrossAccountConfig(t *testing.T) {
	baseCfg := aws.Config{Region: "us-east-1"}
	cfg, err := scanneraws.CreateCrossAccountConfig(context.Background(), baseCfg, "123456789012", "MyRole", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "us-east-1" {
		t.Errorf("expected region us-east-1, got %s", cfg.Region)
	}

	_, errEmpty := scanneraws.CreateCrossAccountConfig(context.Background(), baseCfg, "", "MyRole", "")
	if errEmpty == nil {
		t.Error("expected error for empty account ID")
	}
}
