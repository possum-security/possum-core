package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/version"
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

// SARIFRuleProperties defines GitHub Code Scanning and SARIF rule metadata properties.
type SARIFRuleProperties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Category         string   `json:"category,omitempty"`
	Remediation      string   `json:"remediation,omitempty"`
	CostWasteMo      float64  `json:"cost_waste_monthly,omitempty"`
}

type sarifRuleProperties = SARIFRuleProperties

// SARIFRuleEntry defines metadata for an individual rule.
type SARIFRuleEntry struct {
	ID               string               `json:"id"`
	Name             string               `json:"name,omitempty"`
	ShortDescription SARIFDescription     `json:"shortDescription"`
	FullDescription  SARIFDescription     `json:"fullDescription,omitempty"`
	HelpURI          string               `json:"helpUri,omitempty"`
	Properties       *SARIFRuleProperties `json:"properties,omitempty"`
}

type sarifRule = SARIFRuleEntry

// SARIFDescription contains text content for descriptions.
type SARIFDescription struct {
	Text string `json:"text"`
}

// SARIFResult represents an individual finding reported by SARIF.
type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifResult = SARIFResult

// SARIFMessage represents the result message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation describes the location where the finding occurred.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation defines the artifact URI and optional source region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation contains the URI identifier.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion represents a line/column region in a source file.
type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type sarifRegion = SARIFRegion

// SARIFLogicalLocation represents a logical cloud resource location (e.g. ARN).
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFFormatter formats results as OASIS SARIF v2.1.0.
type SARIFFormatter struct{}

// NewSARIFFormatter creates a new SARIFFormatter.
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

func securitySeverityScore(sev model.Severity) string {
	switch strings.ToUpper(sev) {
	case model.SeverityCritical:
		return "9.0"
	case model.SeverityHigh:
		return "7.0"
	case model.SeverityMedium:
		return "4.0"
	case model.SeverityLow:
		return "2.0"
	case model.SeverityInfo:
		return "1.0"
	default:
		return "1.0"
	}
}

func extractFileAndLine(r model.ScanResult) (string, int) {
	checkMap := func(m map[string]interface{}) (string, int) {
		var file string
		var line int
		if f, ok := m["File"].(string); ok && f != "" {
			file = f
		} else if f, ok := m["file"].(string); ok && f != "" {
			file = f
		}
		switch l := m["Line"].(type) {
		case int:
			line = l
		case float64:
			line = int(l)
		case int64:
			line = int(l)
		}
		if line == 0 {
			switch l := m["line"].(type) {
			case int:
				line = l
			case float64:
				line = int(l)
			case int64:
				line = int(l)
			}
		}
		return file, line
	}

	if m, ok := r.Metrics.(map[string]interface{}); ok {
		if f, l := checkMap(m); f != "" {
			return f, l
		}
	}
	if r.Metadata != nil {
		if f, l := checkMap(r.Metadata); f != "" {
			return f, l
		}
	}
	return "", 0
}

// Format renders the results in SARIF v2.1.0 JSON format.
func (f *SARIFFormatter) Format(w io.Writer, results []model.ScanResult) error {
	SortResults(results)

	ruleMap := make(map[string]int)
	rules := make([]sarifRule, 0)
	sarifResults := make([]sarifResult, 0)

	for _, r := range results {
		// SARIF only records active failures (skip PASS and SUPPRESSED)
		if r.Status == model.StatusPass || r.Status == model.StatusSuppressed {
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

			tags := []string{"security"}
			if r.Category != "" {
				tags = append(tags, strings.ToLower(r.Category))
			}
			if len(r.Compliance) > 0 {
				tags = append(tags, r.Compliance...)
			}

			props := &sarifRuleProperties{
				SecuritySeverity: securitySeverityScore(r.Severity),
				Tags:             tags,
				Severity:         r.Severity,
				Category:         r.Category,
				Remediation:      r.Remediation,
				CostWasteMo:      r.CostWasteMo,
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

		filePath, startLine := extractFileAndLine(r)
		var loc SARIFLocation
		if filePath != "" {
			phys := SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{
					URI: filePath,
				},
			}
			if startLine > 0 {
				phys.Region = &sarifRegion{StartLine: startLine}
			}
			loc = SARIFLocation{
				PhysicalLocation: phys,
			}
		} else {
			rawID := r.ResourceID
			if rawID == "" {
				rawID = r.ResourceType
			}
			relURI := strings.TrimLeft(strings.ReplaceAll(rawID, ":", "/"), "/")
			if relURI == "" {
				relURI = "aws-resource/unknown"
			}
			loc = SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: relURI,
					},
				},
				LogicalLocations: []SARIFLogicalLocation{
					{
						Name:               rawID,
						FullyQualifiedName: rawID,
						Kind:               r.ResourceType,
					},
				},
			}
		}

		fpSum := sha256.Sum256([]byte(r.RuleID + "|" + r.ResourceID + "|" + r.Region))
		fpHex := hex.EncodeToString(fpSum[:])

		sarifResults = append(sarifResults, SARIFResult{
			RuleID:    r.RuleID,
			RuleIndex: ruleIdx,
			Level:     level,
			Message: SARIFMessage{
				Text: msg,
			},
			Locations: []SARIFLocation{loc},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": fpHex,
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
