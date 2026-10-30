package aws_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	scanneraws "github.com/possum-security/possum-core/pkg/scanner/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
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

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCreateCrossAccountConfig_FullRoleARNTargetsEachMemberAccount(t *testing.T) {
	var assumedRoleARNs []string
	var backendCalls atomic.Int32

	rootRT := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			bodyBytes, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			vals, err := url.ParseQuery(string(bodyBytes))
			if err == nil && vals.Get("Action") == "AssumeRole" {
				assumedRoleARNs = append(assumedRoleARNs, vals.Get("RoleArn"))
				xmlResp := `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATESTKEY123456789</AccessKeyId>
      <SecretAccessKey>TESTSECRETKEY12345678901234567890</SecretAccessKey>
      <SessionToken>TESTTOKEN</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"text/xml"}},
					Body:       io.NopCloser(strings.NewReader(xmlResp)),
				}, nil
			}
		}

		backendCalls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
		}, nil
	})

	baseCfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIABASE", "BASE_SECRET", ""),
		HTTPClient:  &http.Client{Transport: rootRT},
	}

	inputRoleARN := "arn:aws:iam::111122223333:role/security/ScannerRole"
	cfgAcctA, err := scanneraws.CreateCrossAccountConfig(context.Background(), baseCfg, "222233334444", inputRoleARN, "ext-1")
	if err != nil {
		t.Fatalf("unexpected error for account A: %v", err)
	}
	cfgAcctB, err := scanneraws.CreateCrossAccountConfig(context.Background(), baseCfg, "333344445555", inputRoleARN, "ext-1")
	if err != nil {
		t.Fatalf("unexpected error for account B: %v", err)
	}

	// Trigger STS AssumeRole for both accounts and verify each targets its own member account ID
	if _, err := cfgAcctA.Credentials.Retrieve(context.Background()); err != nil {
		t.Fatalf("failed retrieving credentials for account A: %v", err)
	}
	if _, err := cfgAcctB.Credentials.Retrieve(context.Background()); err != nil {
		t.Fatalf("failed retrieving credentials for account B: %v", err)
	}

	if len(assumedRoleARNs) != 2 {
		t.Fatalf("expected 2 AssumeRole calls, got %d", len(assumedRoleARNs))
	}
	if assumedRoleARNs[0] != "arn:aws:iam::222233334444:role/security/ScannerRole" {
		t.Errorf("expected account A role ARN arn:aws:iam::222233334444:role/security/ScannerRole, got %s", assumedRoleARNs[0])
	}
	if assumedRoleARNs[1] != "arn:aws:iam::333344445555:role/security/ScannerRole" {
		t.Errorf("expected account B role ARN arn:aws:iam::333344445555:role/security/ScannerRole, got %s", assumedRoleARNs[1])
	}

	// Verify each account config has its own isolated HTTP transport and cache keys
	scanneraws.GetSharedAWSCache().Clear()
	clientA, ok := cfgAcctA.HTTPClient.(*http.Client)
	if !ok || clientA == nil {
		t.Fatal("expected *http.Client on cfgAcctA")
	}
	clientB, ok := cfgAcctB.HTTPClient.(*http.Client)
	if !ok || clientB == nil {
		t.Fatal("expected *http.Client on cfgAcctB")
	}

	throttledA, ok := clientA.Transport.(*scanneraws.ThrottledTransport)
	if !ok || throttledA.AccountID() != "222233334444" {
		t.Fatalf("expected ThrottledTransport for 222233334444, got %#v", clientA.Transport)
	}
	throttledB, ok := clientB.Transport.(*scanneraws.ThrottledTransport)
	if !ok || throttledB.AccountID() != "333344445555" {
		t.Fatalf("expected ThrottledTransport for 333344445555, got %#v", clientB.Transport)
	}

	cacheA, ok := throttledA.Base().(*scanneraws.AWSCacheTransport)
	if !ok || cacheA.AccountID() != "222233334444" {
		t.Fatalf("expected AWSCacheTransport for 222233334444, got %#v", throttledA.Base())
	}
	cacheB, ok := throttledB.Base().(*scanneraws.AWSCacheTransport)
	if !ok || cacheB.AccountID() != "333344445555" {
		t.Fatalf("expected AWSCacheTransport for 333344445555, got %#v", throttledB.Base())
	}

	// Identical API request through clientA and clientB must not share cached responses
	reqA, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", nil)
	respA, err := clientA.Do(reqA)
	if err != nil {
		t.Fatalf("clientA request failed: %v", err)
	}
	respA.Body.Close()

	reqB, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://ec2.us-east-1.amazonaws.com/?Action=DescribeInstances", nil)
	respB, err := clientB.Do(reqB)
	if err != nil {
		t.Fatalf("clientB request failed: %v", err)
	}
	respB.Body.Close()

	if count := backendCalls.Load(); count != 2 {
		t.Errorf("expected 2 isolated backend calls across accounts A and B, got %d", count)
	}
}
