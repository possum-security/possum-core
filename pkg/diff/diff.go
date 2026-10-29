package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/possum-security/possum-core/pkg/model"
)

// Report contains comparison results between a baseline scan and a head scan.
type Report struct {
	NewFindings       []model.ScanResult `json:"new_findings"`
	ResolvedFindings  []model.ScanResult `json:"resolved_findings"`
	UnchangedFindings []model.ScanResult `json:"unchanged_findings"`

	BaselineCount int `json:"baseline_count"`
	HeadCount     int `json:"head_count"`

	BaselineWaste float64 `json:"baseline_waste_monthly"`
	HeadWaste     float64 `json:"head_waste_monthly"`
	NetWasteDelta float64 `json:"net_waste_delta_monthly"`
}

// FindingKey generates a deterministic deduplication key for a finding.
func FindingKey(r model.ScanResult) string {
	return fmt.Sprintf("%s|%s|%s", r.RuleID, r.ResourceID, r.Region)
}

// Compare computes differences between baseline findings and head findings.
func Compare(baseline, head []model.ScanResult) *Report {
	report := &Report{
		BaselineCount: len(baseline),
		HeadCount:     len(head),
	}

	baselineMap := make(map[string]model.ScanResult, len(baseline))
	for _, r := range baseline {
		if r.Status == model.StatusFail {
			report.BaselineWaste += r.CostWasteMo
			baselineMap[FindingKey(r)] = r
		}
	}

	headMap := make(map[string]model.ScanResult, len(head))
	for _, r := range head {
		if r.Status == model.StatusFail {
			report.HeadWaste += r.CostWasteMo
			headMap[FindingKey(r)] = r
		}
	}

	report.NetWasteDelta = report.HeadWaste - report.BaselineWaste

	// Identify new findings and unchanged
	for key, r := range headMap {
		if _, exists := baselineMap[key]; exists {
			report.UnchangedFindings = append(report.UnchangedFindings, r)
		} else {
			report.NewFindings = append(report.NewFindings, r)
		}
	}

	// Identify resolved findings
	for key, r := range baselineMap {
		if _, exists := headMap[key]; !exists {
			report.ResolvedFindings = append(report.ResolvedFindings, r)
		}
	}

	// Sort findings deterministically by severity then RuleID
	sortFindings(report.NewFindings)
	sortFindings(report.ResolvedFindings)
	sortFindings(report.UnchangedFindings)

	return report
}

func sortFindings(findings []model.ScanResult) {
	sort.Slice(findings, func(i, j int) bool {
		si := model.SeverityLevel(findings[i].Severity)
		sj := model.SeverityLevel(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].ResourceID < findings[j].ResourceID
	})
}

// LoadResultsFromFile reads ScanResult slice from a JSON scan file.
func LoadResultsFromFile(path string) ([]model.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer f.Close()

	var results []model.ScanResult
	if err := json.NewDecoder(f).Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %s: %w", path, err)
	}
	return results, nil
}

// FormatMarkdownPR renders a GitHub PR comment markdown summary.
func (rep *Report) FormatMarkdownPR(w io.Writer) error {
	var sb strings.Builder

	sb.WriteString("## 🐾 Possum Cloud Security & FinOps PR Delta\n\n")

	// Summary banner
	statusEmoji := "✅"
	if len(rep.NewFindings) > 0 {
		statusEmoji = "⚠️"
	}
	costTrend := "neutral"
	if rep.NetWasteDelta > 0.01 {
		costTrend = fmt.Sprintf("📈 +$%.2f/mo waste", rep.NetWasteDelta)
	} else if rep.NetWasteDelta < -0.01 {
		costTrend = fmt.Sprintf("📉 -$%.2f/mo savings", -rep.NetWasteDelta)
	} else {
		costTrend = "$0.00/mo delta"
	}

	sb.WriteString(fmt.Sprintf("%s **Diff Summary:** %d new findings, %d resolved findings | Cost Impact: **%s**\n\n",
		statusEmoji, len(rep.NewFindings), len(rep.ResolvedFindings), costTrend))

	// Breakdown table
	sb.WriteString("| Metric | Baseline | Current PR | Delta |\n")
	sb.WriteString("| :--- | :---: | :---: | :---: |\n")
	sb.WriteString(fmt.Sprintf("| Total Active Findings | %d | %d | %+d |\n",
		rep.BaselineCount, rep.HeadCount, len(rep.NewFindings)-len(rep.ResolvedFindings)))
	sb.WriteString(fmt.Sprintf("| Estimated Monthly Waste | $%.2f | $%.2f | %s |\n\n",
		rep.BaselineWaste, rep.HeadWaste, costTrend))

	// New Findings Section
	if len(rep.NewFindings) > 0 {
		sb.WriteString("### 🚨 New Issues Introduced in this PR\n\n")
		sb.WriteString("| Severity | Rule | Resource | Cost Waste | Details |\n")
		sb.WriteString("| :---: | :--- | :--- | :---: | :--- |\n")
		for _, r := range rep.NewFindings {
			title := r.Title
			if title == "" {
				title = r.RuleID
			}
			wasteStr := "-"
			if r.CostWasteMo > 0 {
				wasteStr = fmt.Sprintf("$%.2f/mo", r.CostWasteMo)
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s | %s |\n",
				r.Severity, r.RuleID, r.ResourceID, wasteStr, title))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("### 🎉 No new security misconfigurations or waste introduced!\n\n")
	}

	// Resolved Findings Section
	if len(rep.ResolvedFindings) > 0 {
		sb.WriteString("### ✅ Issues Resolved by this PR\n\n")
		sb.WriteString("| Severity | Rule | Resource | Cost Waste Saved |\n")
		sb.WriteString("| :---: | :--- | :--- | :---: |\n")
		for _, r := range rep.ResolvedFindings {
			wasteStr := "-"
			if r.CostWasteMo > 0 {
				wasteStr = fmt.Sprintf("-$%.2f/mo", r.CostWasteMo)
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` | %s |\n",
				r.Severity, r.RuleID, r.ResourceID, wasteStr))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("> *Generated automatically by [Possum Core](https://github.com/possum-security/possum-core)*\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
