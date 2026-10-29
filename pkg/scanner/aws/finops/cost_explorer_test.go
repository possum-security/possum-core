package finops_test

import (
	"testing"

	"github.com/amirmahdy/possum-core/pkg/scanner"
	"github.com/amirmahdy/possum-core/pkg/scanner/aws/finops"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestNewCostExplorerScanner_Defaults(t *testing.T) {
	cfg := aws.Config{}

	// Test default when days <= 0
	scannerDefault := finops.NewCostExplorerScanner(cfg, 0)
	if scannerDefault == nil {
		t.Fatal("expected scanner instance, got nil")
	}
	if scannerDefault.Name() != "CostExplorer-Scanner" {
		t.Errorf("expected CostExplorer-Scanner, got %s", scannerDefault.Name())
	}

	// Verify it satisfies the Scanner interface
	var _ scanner.Scanner = scannerDefault

	// Test explicit 30 days
	scanner30 := finops.NewCostExplorerScanner(cfg, 30)
	if scanner30 == nil {
		t.Fatal("expected scanner instance, got nil")
	}
}
