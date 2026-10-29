package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/model"
	"github.com/amirmahdy/possum-core/pkg/version"
)

// SARIFReport represents OASIS SARIF v2.1.0 schema root.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single tool execution run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the scanner tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the driver details and rules.
type SARIFDriver struct {
	Name           string           `json:"name"`
	Version        string           `json:"version"`
	InformationURI string           `json:"informationUri"`
	Rules          []SARIFRuleEntry `json:"rules"`
}

// SARIFRuleEntry defines metadata for an individual rule.
type SARIFRuleEntry struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription SARIFDescription `json:"shortDescription"`
	FullDescription  SARIFDescription `json:"fullDescription,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
	Properties       map[string]any   `json:"properties,omitempty"`
}

// SARIFDescription contains text content for descriptions.
type SARIFDescription struct {
	Text string `json:"text"`
}

// SARIFResult represents an individual finding reported by SARIF.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage represents the result message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes the location where the finding occurred.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation defines the artifact URI.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation contains the URI identifier.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFFormatter formats results as OASIS SARIF v2.1.0.
type SARIFFormatter struct{}

// NewSARIFFormatter creates a new SARIFFormatter.
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

// Format renders the results in SARIF v2.1.0 JSON format.
func (f *SARIFFormatter) Format(w io.Writer, results []model.ScanResult) error {
	ruleMap := make(map[string]int)
	var rules []SARIFRuleEntry
	var sarifResults []SARIFResult

	for _, r := range results {
		// SARIF only records failures / security findings
		if r.Status == model.StatusPass {
			continue
		}

		ruleIdx, exists := ruleMap[r.RuleID]
		if !exists {
			ruleIdx = len(rules)
			ruleMap[r.RuleID] = ruleIdx

			title := r.Title
			if title == "" {
				title = r.RuleID
			}

			desc := r.Description
			if desc == "" {
				desc = title
			}

			props := map[string]any{
				"severity": string(r.Severity),
				"category": string(r.Category),
			}
			if r.Remediation != "" {
				props["remediation"] = r.Remediation
			}
			if r.CostWasteMo > 0 {
				props["cost_waste_monthly"] = r.CostWasteMo
			}

			rules = append(rules, SARIFRuleEntry{
				ID:   r.RuleID,
				Name: strings.ReplaceAll(r.RuleID, "_", " "),
				ShortDescription: SARIFDescription{
					Text: title,
				},
				FullDescription: SARIFDescription{
					Text: desc,
				},
				HelpURI:    fmt.Sprintf("https://possum.io/rules/%s", r.RuleID),
				Properties: props,
			})
		}

		level := "note"
		switch r.Severity {
		case model.SeverityCritical, model.SeverityHigh:
			level = "error"
		case model.SeverityMedium:
			level = "warning"
		case model.SeverityLow, model.SeverityInfo:
			level = "note"
		}

		msg := r.Description
		if msg == "" {
			msg = fmt.Sprintf("[%s] %s on %s (%s)", r.Severity, r.RuleID, r.ResourceID, r.ResourceType)
		}
		if r.Remediation != "" {
			msg += fmt.Sprintf("\nRemediation: %s", r.Remediation)
		}

		locationURI := r.ResourceID
		if locationURI == "" {
			locationURI = r.ResourceType
		}

		sarifResults = append(sarifResults, SARIFResult{
			RuleID:    r.RuleID,
			RuleIndex: ruleIdx,
			Level:     level,
			Message: SARIFMessage{
				Text: msg,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: locationURI,
						},
					},
				},
			},
		})
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "possum",
						Version:        version.Version,
						InformationURI: "https://possum.io",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
