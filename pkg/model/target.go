package model

// Scope defines whether a scanner operates per-region or globally across the cloud account.
type Scope = string

const (
	ScopeRegional = "REGIONAL"
	ScopeGlobal   = "GLOBAL"
)

// ScanMode controls the depth and execution profile of a scan.
type ScanMode = string

const (
	ScanModeQuick    = "QUICK"    // Critical & High severity checks only
	ScanModeStandard = "STANDARD" // Full FinOps & SecaaS checks
	ScanModeDeep     = "DEEP"     // Full checks + IAM privilege analysis + DSPM heuristics
)

// ScanTarget defines criteria for targeted rule and service execution.
type ScanTarget struct {
	Mode       ScanMode   `json:"mode,omitempty"`
	Services   []string   `json:"services,omitempty"`
	Checks     []string   `json:"checks,omitempty"`
	Categories []Category `json:"categories,omitempty"`
	Severities []Severity `json:"severities,omitempty"`
}

// FilterOptions defines runtime filters applied during scan execution or result processing.
type FilterOptions struct {
	Services   []string
	Severities []Severity
	FailOn     Severity
	Categories []Category
	Checks     []string
}
