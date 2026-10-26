package secaas

import (
	"context"
	"fmt"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	graph "github.com/amirmahdy/possum-core/pkg/model"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
)

// AccountClient defines the interface for AWS Account API calls.
type AccountClient interface {
	GetContactInformation(ctx context.Context, params *account.GetContactInformationInput, optFns ...func(*account.Options)) (*account.GetContactInformationOutput, error)
	GetAlternateContact(ctx context.Context, params *account.GetAlternateContactInput, optFns ...func(*account.Options)) (*account.GetAlternateContactOutput, error)
}

// AccountScanner evaluates AWS Account governance and contact configurations.
type AccountScanner struct {
	client AccountClient
}

// NewAccountScanner creates a new AccountScanner with AWS config.
func NewAccountScanner(cfg aws.Config) *AccountScanner {
	return &AccountScanner{
		client: account.NewFromConfig(cfg),
	}
}

// NewAccountScannerWithClient creates a new AccountScanner with custom/mock client.
func NewAccountScannerWithClient(client AccountClient) *AccountScanner {
	return &AccountScanner{
		client: client,
	}
}

func (s *AccountScanner) Name() string {
	return "Account-SecaaS-Scanner"
}

func (s *AccountScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	var results []scanner.ScanResult
	accountResourceID := "aws-account-governance"

	// 1. Check primary contact details (account_maintain_current_contact_details - CIS 1.1)
	contactInfo, err := s.client.GetContactInformation(ctx, &account.GetContactInformationInput{})
	if err != nil || contactInfo.ContactInformation == nil ||
		aws.ToString(contactInfo.ContactInformation.FullName) == "" ||
		aws.ToString(contactInfo.ContactInformation.PhoneNumber) == "" ||
		aws.ToString(contactInfo.ContactInformation.AddressLine1) == "" {
		results = append(results, scanner.ScanResult{
			ResourceID:   accountResourceID,
			ResourceType: "SecaaS-Account",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "account_maintain_current_contact_details",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": "AWS Account primary contact information is incomplete or missing.",
				"SecurityIssues": []string{"Primary account contact information is not properly maintained"},
				"Recommendation": "Ensure account contact information includes full name, address, and phone number.",
			},
			Nodes: []graph.Node{{ID: accountResourceID, NodeType: "SecaaS-Account"}},
		})
	} else {
		results = append(results, scanner.ScanResult{
			ResourceID:   accountResourceID,
			ResourceType: "SecaaS-Account",
			Region:       "global",
			Status:       "PASS",
			RuleID:       "account_maintain_current_contact_details",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("AWS Account primary contact information is complete for %s.", aws.ToString(contactInfo.ContactInformation.FullName)),
			},
			Nodes: []graph.Node{{ID: accountResourceID, NodeType: "SecaaS-Account"}},
		})
	}

	// 2. Check Security alternate contact (account_security_contact_information_is_registered - CIS 1.2)
	secContact, err := s.client.GetAlternateContact(ctx, &account.GetAlternateContactInput{
		AlternateContactType: accounttypes.AlternateContactTypeSecurity,
	})
	if err != nil || secContact.AlternateContact == nil ||
		aws.ToString(secContact.AlternateContact.EmailAddress) == "" ||
		aws.ToString(secContact.AlternateContact.PhoneNumber) == "" {
		results = append(results, scanner.ScanResult{
			ResourceID:   accountResourceID,
			ResourceType: "SecaaS-Account",
			Region:       "global",
			Status:       "FAIL",
			RuleID:       "account_security_contact_information_is_registered",
			Severity:     "MEDIUM",
			Metrics: map[string]interface{}{
				"StatusExtended": "AWS Account security alternate contact is not registered or missing required email/phone.",
				"SecurityIssues": []string{"Missing dedicated security alternate contact"},
				"Recommendation": "Register a dedicated security alternate contact (email, phone, name) under AWS Account settings.",
			},
			Nodes: []graph.Node{{ID: accountResourceID, NodeType: "SecaaS-Account"}},
		})
	} else {
		results = append(results, scanner.ScanResult{
			ResourceID:   accountResourceID,
			ResourceType: "SecaaS-Account",
			Region:       "global",
			Status:       "PASS",
			RuleID:       "account_security_contact_information_is_registered",
			Severity:     "INFO",
			Metrics: map[string]interface{}{
				"StatusExtended": fmt.Sprintf("AWS Account security alternate contact is registered: %s.", aws.ToString(secContact.AlternateContact.EmailAddress)),
			},
			Nodes: []graph.Node{{ID: accountResourceID, NodeType: "SecaaS-Account"}},
		})
	}

	// 3. Security questions (account_security_questions_are_registered_in_the_aws_account - CIS 1.3 - DEPRECATED by AWS)
	// AWS deprecated security challenge questions as of January 2025 in favor of MFA.
	results = append(results, scanner.ScanResult{
		ResourceID:   accountResourceID,
		ResourceType: "SecaaS-Account",
		Region:       "global",
		Status:       "PASS",
		RuleID:       "account_security_questions_are_registered_in_the_aws_account",
		Severity:     "INFO",
		Metrics: map[string]interface{}{
			"StatusExtended": "AWS security challenge questions have been deprecated by AWS in favor of hardware/virtual MFA.",
		},
		Nodes: []graph.Node{{ID: accountResourceID, NodeType: "SecaaS-Account"}},
	})

	return results, nil
}
