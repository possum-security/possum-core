package tui

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/model"
)

// Model represents the state of the interactive Terminal UI.
type Model struct {
	Findings       []model.ScanResult
	Filtered       []model.ScanResult
	SelectedIndex  int
	FilterSeverity string
	ViewingDetail  bool
}

// NewModel initializes the TUI state with scan findings.
func NewModel(findings []model.ScanResult) *Model {
	m := &Model{
		Findings: findings,
	}
	m.ApplyFilter("")
	return m
}

// ApplyFilter filters findings by severity level.
func (m *Model) ApplyFilter(sev string) {
	m.FilterSeverity = strings.ToUpper(strings.TrimSpace(sev))
	if m.FilterSeverity == "" || m.FilterSeverity == "ALL" {
		m.Filtered = m.Findings
	} else {
		m.Filtered = nil
		for _, f := range m.Findings {
			if strings.EqualFold(f.Severity, m.FilterSeverity) {
				m.Filtered = append(m.Filtered, f)
			}
		}
	}
	if m.SelectedIndex >= len(m.Filtered) {
		m.SelectedIndex = 0
	}
}

// MoveDown increments selected index safely.
func (m *Model) MoveDown() {
	if len(m.Filtered) > 0 && m.SelectedIndex < len(m.Filtered)-1 {
		m.SelectedIndex++
	}
}

// MoveUp decrements selected index safely.
func (m *Model) MoveUp() {
	if m.SelectedIndex > 0 {
		m.SelectedIndex--
	}
}

// ToggleDetail switches between list and detail inspection view.
func (m *Model) ToggleDetail() {
	if len(m.Filtered) > 0 {
		m.ViewingDetail = !m.ViewingDetail
	}
}

// SelectedItem returns the currently highlighted finding.
func (m *Model) SelectedItem() *model.ScanResult {
	if len(m.Filtered) == 0 || m.SelectedIndex < 0 || m.SelectedIndex >= len(m.Filtered) {
		return nil
	}
	return &m.Filtered[m.SelectedIndex]
}

// Render writes the current UI frame to w.
func (m *Model) Render(w io.Writer) {
	fmt.Fprintln(w, "┌────────────────────────────────────────────────────────────────────────┐")
	fmt.Fprintln(w, "│ 🐾 Possum Interactive Terminal Inspector                              │")
	fmt.Fprintf(w, "│ Filter: %-10s Total: %-4d Highlighted: %-4d                           │\n",
		defaultStr(m.FilterSeverity, "ALL"), len(m.Filtered), m.SelectedIndex+1)
	fmt.Fprintln(w, "├────────────────────────────────────────────────────────────────────────┤")

	if m.ViewingDetail {
		item := m.SelectedItem()
		if item != nil {
			fmt.Fprintf(w, "│ [DETAIL VIEW] Rule: %-51s│\n", item.RuleID)
			fmt.Fprintf(w, "│ Severity:   %-59s│\n", item.Severity)
			fmt.Fprintf(w, "│ Resource:   %-59s│\n", item.ResourceID)
			fmt.Fprintf(w, "│ Status:     %-59s│\n", item.Status)
			if item.CostWasteMo > 0 {
				fmt.Fprintf(w, "│ Cost Waste: $%-58.2f│\n", item.CostWasteMo)
			}
			fmt.Fprintln(w, "├────────────────────────────────────────────────────────────────────────┤")
			fmt.Fprintf(w, "│ Title:       %-58s│\n", truncate(item.Title, 58))
			fmt.Fprintf(w, "│ Remediation: %-58s│\n", truncate(item.Remediation, 58))
		}
		fmt.Fprintln(w, "├────────────────────────────────────────────────────────────────────────┤")
		fmt.Fprintln(w, "│ [ESC/Enter: Back to List | q: Quit]                                    │")
	} else {
		// List view: display up to 10 findings centered on selection
		start := 0
		if m.SelectedIndex > 5 {
			start = m.SelectedIndex - 5
		}
		end := start + 10
		if end > len(m.Filtered) {
			end = len(m.Filtered)
		}

		if len(m.Filtered) == 0 {
			fmt.Fprintln(w, "│  (No findings matching current filter)                                 │")
		} else {
			for i := start; i < end; i++ {
				f := m.Filtered[i]
				cursor := " "
				if i == m.SelectedIndex {
					cursor = ">"
				}
				wasteStr := "   -   "
				if f.CostWasteMo > 0 {
					wasteStr = fmt.Sprintf("$%5.1f/m", f.CostWasteMo)
				}
				line := fmt.Sprintf("%s [%-8s] %-8s %-24s %s",
					cursor, f.Severity, wasteStr, truncate(f.ResourceID, 24), truncate(f.RuleID, 20))
				fmt.Fprintf(w, "│ %-70s │\n", line)
			}
		}
		fmt.Fprintln(w, "├────────────────────────────────────────────────────────────────────────┤")
		fmt.Fprintln(w, "│ [j/Down: Next | k/Up: Prev | Enter: View Details | f: Filter | q: Quit]│")
	}
	fmt.Fprintln(w, "└────────────────────────────────────────────────────────────────────────┘")
}

// RunInteractive reads user keyboard inputs from r and renders to w.
func (m *Model) RunInteractive(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	m.Render(w)

	for scanner.Scan() {
		cmd := strings.TrimSpace(scanner.Text())
		switch strings.ToLower(cmd) {
		case "q", "quit", "exit":
			return nil
		case "j", "down", "n":
			m.MoveDown()
		case "k", "up", "p":
			m.MoveUp()
		case "enter", "v", "d", "":
			m.ToggleDetail()
		case "f", "filter":
			// Cycle filters: ALL -> CRITICAL -> HIGH -> MEDIUM -> LOW -> ALL
			switch m.FilterSeverity {
			case "ALL", "":
				m.ApplyFilter("CRITICAL")
			case "CRITICAL":
				m.ApplyFilter("HIGH")
			case "HIGH":
				m.ApplyFilter("MEDIUM")
			case "MEDIUM":
				m.ApplyFilter("LOW")
			default:
				m.ApplyFilter("ALL")
			}
		}
		m.Render(w)
	}
	return scanner.Err()
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
