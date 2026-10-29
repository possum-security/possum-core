package scanner

import (
	"context"

	"github.com/possum-security/possum-core/pkg/model"
)

// Type aliases pointing to pkg/model for convenience
type (
	ScanResult = model.ScanResult
	Node       = model.Node
	Edge       = model.Edge
	Severity   = model.Severity
	Status     = model.Status
	Category   = model.Category
	Scope      = model.Scope
	ScanMode   = model.ScanMode
)

// ExecutionCost indicates resource intensity of a scanner.
type ExecutionCost string

const (
	CostLight  ExecutionCost = "LIGHT"  // Fast API calls
	CostMedium ExecutionCost = "MEDIUM" // Moderate API queries / CloudWatch metrics
	CostHeavy  ExecutionCost = "HEAVY"  // Large listings, deep policy analyses
)

// ScannerMeta provides rich metadata for filtering and execution planning.
type ScannerMeta struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Category      Category      `json:"category"`
	Scope         Scope         `json:"scope"`
	ExecutionCost ExecutionCost `json:"execution_cost"`
	Description   string        `json:"description"`
	Service       string        `json:"service"`
	CheckIDs      []string      `json:"check_ids"`
}

// Scanner is the core interface implemented by all resource scanners.
type Scanner interface {
	Name() string
	Scan(ctx context.Context) ([]ScanResult, error)
}

// MetaScanner extends Scanner with rich metadata.
type MetaScanner interface {
	Scanner
	Meta() ScannerMeta
}

// ShouldStop checks if scanning should stop early due to resource limit or cancellation.
func ShouldStop(ctx context.Context, currentCount int, maxAllowed int) bool {
	if maxAllowed > 0 && currentCount >= maxAllowed {
		return true
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// GetResourceLimit extracts the resource limit from the context if configured.
func GetResourceLimit(ctx context.Context) int {
	if val, ok := ctx.Value("ResourceLimit").(int); ok && val > 0 {
		return val
	}
	return 0
}
