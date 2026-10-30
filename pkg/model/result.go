package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrThresholdExceeded is returned when scan findings meet or exceed the configured --fail-on severity threshold.
var ErrThresholdExceeded = errors.New("scan findings meet or exceed failure threshold")

// ErrScannerExecution is returned when one or more scanners fail during execution.
var ErrScannerExecution = errors.New("one or more scanners encountered execution errors")

// Severity defines finding severity levels.
type Severity = string

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// ParseSeverity validates and normalizes a severity string (case-insensitive).
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case SeverityCritical:
		return SeverityCritical, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityInfo:
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity %q (must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO)", s)
	}
}

// SeverityLevel returns numeric weight for severity comparison.
// Returns -1 for unknown severities so invalid inputs never match valid findings.
func SeverityLevel(s Severity) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return -1
	}
}

// MeetsThreshold checks if severity meets or exceeds the given threshold.
func MeetsThreshold(s, threshold Severity) bool {
	sl := SeverityLevel(s)
	tl := SeverityLevel(threshold)
	if sl <= 0 || tl <= 0 {
		return false
	}
	return sl >= tl
}

// Status represents the evaluation outcome of a rule.
type Status = string

const (
	StatusPass       = "PASS"
	StatusFail       = "FAIL"
	StatusSuppressed = "SUPPRESSED"
)

// Category classifies scanners and findings.
type Category = string

const (
	CategorySecurity = "SECURITY"
	CategorySecOps   = "SECAAS"
	CategorySecaaS   = "SECAAS"
	CategoryFinOps   = "FINOPS"
	CategoryIAM      = "IAM"
	CategoryDSPM     = "DSPM"
)

// SecurityFinding represents a security issue reference (e.g. for ECR CVE correlation).
type SecurityFinding struct {
	ResourceID string `json:"resource_id"`
	Severity   string `json:"severity"`
	RuleID     string `json:"rule_id,omitempty"`
}

// ScanResult is the unified output emitted by any scanner check.
type ScanResult struct {
	ResourceID       string                 `json:"resource_id"`
	ResourceType     string                 `json:"resource_type"`
	Region           string                 `json:"region"`
	AccountID        string                 `json:"account_id,omitempty"`
	RuleID           string                 `json:"rule_id"`
	Title            string                 `json:"title,omitempty"`
	Severity         Severity               `json:"severity"`
	Status           Status                 `json:"status"`
	Category         Category               `json:"category,omitempty"`
	IsOrphaned       bool                   `json:"is_orphaned,omitempty"`
	CostWasteMo      float64                `json:"cost_waste_monthly,omitempty"`
	Description      string                 `json:"description,omitempty"`
	Remediation      string                 `json:"remediation,omitempty"`
	Compliance       []string               `json:"compliance,omitempty"`
	SuppressedReason string                 `json:"suppressed_reason,omitempty"`
	EvaluatedAt      time.Time              `json:"evaluated_at"`
	Metrics          interface{}            `json:"metrics,omitempty"`
	Nodes            []Node                 `json:"nodes,omitempty"`
	Edges            []Edge                 `json:"edges,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// MeetsThreshold checks if this finding meets or exceeds the given severity threshold.
func (r ScanResult) MeetsThreshold(threshold Severity) bool {
	return MeetsThreshold(r.Severity, threshold)
}
