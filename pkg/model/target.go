package model

import "strings"

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

// ParseScanMode normalizes a mode string to a valid ScanMode constant.
func ParseScanMode(mode string) ScanMode {
	switch strings.ToUpper(strings.TrimSpace(mode)) {
	case ScanModeQuick:
		return ScanModeQuick
	case ScanModeDeep:
		return ScanModeDeep
	default:
		return ScanModeStandard
	}
}

// ScanTarget defines criteria for targeted rule and service execution.
type ScanTarget struct {
	Mode       ScanMode   `json:"mode,omitempty"`
	Services   []string   `json:"services,omitempty"`
	Checks     []string   `json:"checks,omitempty"`
	Categories []Category `json:"categories,omitempty"`
	Severities []Severity `json:"severities,omitempty"`
}

// MatchesMode checks whether a given severity should be included under the target ScanMode.
func (t ScanTarget) MatchesMode(sev Severity) bool {
	if strings.EqualFold(t.Mode, ScanModeQuick) {
		return MeetsThreshold(sev, SeverityHigh)
	}
	return true
}

// FilterOptions defines runtime filters applied during scan execution or result processing.
type FilterOptions struct {
	Mode       ScanMode
	Services   []string
	Severities []Severity
	FailOn     Severity
	Categories []Category
	Checks     []string
	Compliance string
}
