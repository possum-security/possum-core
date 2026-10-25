package secaas

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/stretchr/testify/assert"
)

type mockAccountClient struct {
	getContactInfoOutput    *account.GetContactInformationOutput
	getContactInfoErr       error
	getAlternateContactFunc func(params *account.GetAlternateContactInput) (*account.GetAlternateContactOutput, error)
}

func (m *mockAccountClient) GetContactInformation(ctx context.Context, params *account.GetContactInformationInput, optFns ...func(*account.Options)) (*account.GetContactInformationOutput, error) {
	if m.getContactInfoErr != nil {
		return nil, m.getContactInfoErr
	}
	return m.getContactInfoOutput, nil
}

func (m *mockAccountClient) GetAlternateContact(ctx context.Context, params *account.GetAlternateContactInput, optFns ...func(*account.Options)) (*account.GetAlternateContactOutput, error) {
	if m.getAlternateContactFunc != nil {
		return m.getAlternateContactFunc(params)
	}
	return &account.GetAlternateContactOutput{}, nil
}

func TestAccountScanner_Compliant(t *testing.T) {
	mock := &mockAccountClient{
		getContactInfoOutput: &account.GetContactInformationOutput{
			ContactInformation: &accounttypes.ContactInformation{
				FullName:     aws.String("Security Admin"),
				PhoneNumber:  aws.String("+1-555-1234"),
				AddressLine1: aws.String("123 Cloud Way"),
			},
		},
		getAlternateContactFunc: func(params *account.GetAlternateContactInput) (*account.GetAlternateContactOutput, error) {
			if params.AlternateContactType == accounttypes.AlternateContactTypeSecurity {
				return &account.GetAlternateContactOutput{
					AlternateContact: &accounttypes.AlternateContact{
						EmailAddress: aws.String("secops@example.com"),
						PhoneNumber:  aws.String("+1-555-9999"),
						Name:         aws.String("Security Response"),
					},
				}, nil
			}
			return nil, fmt.Errorf("not found")
		},
	}

	scanner := NewAccountScannerWithClient(mock)
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	for _, r := range results {
		assert.Equal(t, "PASS", r.Status)
	}
}

func TestAccountScanner_NonCompliant(t *testing.T) {
	mock := &mockAccountClient{
		getContactInfoOutput: &account.GetContactInformationOutput{
			ContactInformation: nil,
		},
		getAlternateContactFunc: func(params *account.GetAlternateContactInput) (*account.GetAlternateContactOutput, error) {
			return nil, fmt.Errorf("ResourceNotFoundException: alternate contact not found")
		},
	}

	scanner := NewAccountScannerWithClient(mock)
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)

	statusMap := make(map[string]string)
	for _, r := range results {
		statusMap[r.RuleID] = r.Status
	}

	assert.Equal(t, "FAIL", statusMap["account_maintain_current_contact_details"])
	assert.Equal(t, "FAIL", statusMap["account_security_contact_information_is_registered"])
	assert.Equal(t, "PASS", statusMap["account_security_questions_are_registered_in_the_aws_account"]) // deprecated
}
