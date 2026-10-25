package model

import (
	"strings"
	"time"
)

// Severity defines finding severity levels.
type Severity = string

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// SeverityLevel returns numeric weight for severity comparison.
func SeverityLevel(s Severity) int {
	switch strings.ToUpper(s) {
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
		return 0
	}
}

// MeetsThreshold checks if severity meets or exceeds the given threshold.
func MeetsThreshold(s, threshold Severity) bool {
	return SeverityLevel(s) >= SeverityLevel(threshold)
}

// Status represents the evaluation outcome of a rule.
type Status = string

const (
	StatusPass = "PASS"
	StatusFail = "FAIL"
)

// Category classifies scanners and findings.
type Category = string

const (
	CategorySecurity = "SECURITY"
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
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"`
	Region       string                 `json:"region"`
	RuleID       string                 `json:"rule_id"`
	Title        string                 `json:"title,omitempty"`
	Severity     Severity               `json:"severity"`
	Status       Status                 `json:"status"`
	Category     Category               `json:"category,omitempty"`
	IsOrphaned   bool                   `json:"is_orphaned,omitempty"`
	CostWasteMo  float64                `json:"cost_waste_monthly,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Remediation  string                 `json:"remediation,omitempty"`
	EvaluatedAt  time.Time              `json:"evaluated_at"`
	Metrics      interface{}            `json:"metrics,omitempty"`
	Nodes        []Node                 `json:"nodes,omitempty"`
	Edges        []Edge                 `json:"edges,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// MeetsThreshold checks if this finding meets or exceeds the given severity threshold.
func (r ScanResult) MeetsThreshold(threshold Severity) bool {
	return MeetsThreshold(r.Severity, threshold)
}
