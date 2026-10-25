package secaas

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/stretchr/testify/assert"
)

type mockMacieClient struct {
	output *macie2.GetMacieSessionOutput
	err    error
}

func (m *mockMacieClient) GetMacieSession(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.output, nil
}

func TestMacieScanner_Enabled(t *testing.T) {
	mock := &mockMacieClient{
		output: &macie2.GetMacieSessionOutput{
			Status: macietypes.MacieStatusEnabled,
		},
	}

	scanner := NewMacieScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "PASS", results[0].Status)
	assert.Equal(t, "macie_is_enabled", results[0].RuleID)
}

func TestMacieScanner_PausedOrDisabled(t *testing.T) {
	mock := &mockMacieClient{
		output: &macie2.GetMacieSessionOutput{
			Status: macietypes.MacieStatusPaused,
		},
	}

	scanner := NewMacieScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "macie_is_enabled", results[0].RuleID)
}

func TestMacieScanner_Error(t *testing.T) {
	mock := &mockMacieClient{
		err: fmt.Errorf("AccessDeniedException: user is not subscribed to Macie"),
	}

	scanner := NewMacieScannerWithClient(mock, "us-east-1")
	results, err := scanner.Scan(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "FAIL", results[0].Status)
	assert.Equal(t, "macie_is_enabled", results[0].RuleID)
}
