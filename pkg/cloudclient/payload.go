package cloudclient

import (
	"time"

	"github.com/possum-security/possum-core/pkg/model"
)

// ClientInfo details the CLI runner environment.
type ClientInfo struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// GitContext captures version control provenance when executed in CI/CD.
type GitContext struct {
	Repository string `json:"repository,omitempty"`
	CommitSHA  string `json:"commit_sha,omitempty"`
	Branch     string `json:"branch,omitempty"`
	Author     string `json:"author,omitempty"`
}

// SummaryPayload matches SecaaS ingestion contract.
type SummaryPayload struct {
	TotalEvaluated      int     `json:"total_evaluated"`
	CriticalCount       int     `json:"critical_count"`
	HighCount           int     `json:"high_count"`
	MediumCount         int     `json:"medium_count"`
	LowCount            int     `json:"low_count"`
	PassCount           int     `json:"pass_count"`
	MonthlyWasteDollars float64 `json:"monthly_waste_dollars"`
}

// GraphFragments encapsulates 1-hop topology nodes and edges emitted by local checks.
type GraphFragments struct {
	Nodes []model.Node `json:"nodes"`
	Edges []model.Edge `json:"edges"`
}

// ScanBundle is the comprehensive payload sent to the Possum SecaaS Platform.
type ScanBundle struct {
	Version        string             `json:"version"`
	AccountID      string             `json:"account_id"`
	ScanID         string             `json:"scan_id"`
	TriggeredAt    time.Time          `json:"triggered_at"`
	ClientInfo     ClientInfo         `json:"client_info"`
	GitContext     GitContext         `json:"git_context,omitempty"`
	Summary        SummaryPayload     `json:"summary"`
	Results        []model.ScanResult `json:"results"`
	GraphFragments GraphFragments     `json:"graph_fragments"`
}
