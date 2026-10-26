package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/amirmahdy/possum-core/pkg/model"
)

// ANSI color escape codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[1;31m"
	colorGreen   = "\033[1;32m"
	colorYellow  = "\033[1;33m"
	colorBlue    = "\033[1;34m"
	colorMagenta = "\033[1;35m"
	colorCyan    = "\033[1;36m"
	colorWhite   = "\033[1;37m"
	colorBold    = "\033[1m"
)

// TableFormatter renders scan results in an ANSI terminal table format.
type TableFormatter struct {
	DisableColor bool
	Region       string
}

// NewTableFormatter creates a new terminal table renderer.
func NewTableFormatter(region string, disableColor bool) *TableFormatter {
	return &TableFormatter{
		Region:       region,
		DisableColor: disableColor,
	}
}

func (f *TableFormatter) colorize(code, text string) string {
	if f.DisableColor {
		return text
	}
	return code + text + colorReset
}

func (f *TableFormatter) severityColor(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical:
		return colorRed
	case model.SeverityHigh:
		return colorMagenta
	case model.SeverityMedium:
		return colorYellow
	case model.SeverityLow:
		return colorCyan
	default:
		return colorWhite
	}
}

// Format renders the results to the writer.
func (f *TableFormatter) Format(w io.Writer, results []model.ScanResult) error {
	summary := CalculateSummary(results)

	// Print findings table
	fmt.Fprintln(w, f.colorize(colorBold, "── Possum FinSecOps Cloud Scan ──────────────────────────────────────────────────"))
	fmt.Fprintf(w, "%-10s %-6s %-10s %-24s %-32s %-12s\n",
		"SEVERITY", "STATUS", "CATEGORY", "RESOURCE", "RULE ID", "WASTE ($/mo)")
	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")

	for _, r := range results {
		var statusStr string
		if r.Status == model.StatusPass {
			statusStr = f.colorize(colorGreen, string(r.Status))
		} else {
			statusStr = f.colorize(colorRed, string(r.Status))
		}

		sevColor := f.severityColor(r.Severity)
		sevStr := f.colorize(sevColor, fmt.Sprintf("%-10s", r.Severity))

		resource := r.ResourceID
		if len(resource) > 23 {
			resource = resource[:20] + "..."
		}

		rule := r.RuleID
		if len(rule) > 31 {
			rule = rule[:28] + "..."
		}

		wasteStr := "-"
		if r.CostWasteMo > 0 {
			wasteStr = fmt.Sprintf("$%.2f", r.CostWasteMo)
		}

		fmt.Fprintf(w, "%s %-6s %-10s %-24s %-32s %-12s\n",
			sevStr, statusStr, r.Category, resource, rule, wasteStr)
	}

	fmt.Fprintln(w, "─────────────────────────────────────────────────────────────────────────────────")

	// Print Summary Banner
	regionText := ""
	if f.Region != "" {
		regionText = fmt.Sprintf(" across %s", f.Region)
	}
	fmt.Fprintf(w, "Scan Summary: %d checks evaluated%s.\n", summary.TotalEvaluated, regionText)
	fmt.Fprintf(w, "Findings:     %s | %s | %s | %s\n",
		f.colorize(colorRed, fmt.Sprintf("%d CRITICAL", summary.CriticalCount)),
		f.colorize(colorMagenta, fmt.Sprintf("%d HIGH", summary.HighCount)),
		f.colorize(colorYellow, fmt.Sprintf("%d MEDIUM", summary.MediumCount)),
		f.colorize(colorGreen, fmt.Sprintf("%d PASS", summary.PassCount)),
	)
	if summary.TotalMonthlyWasteMo > 0 {
		fmt.Fprintf(w, "FinOps Waste: %s in orphaned resources detected.\n",
			f.colorize(colorYellow, fmt.Sprintf("$%.2f/month", summary.TotalMonthlyWasteMo)))
	}

	// PLG Teaser (Section 8)
	if summary.FailCount > 0 || summary.TotalMonthlyWasteMo > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, f.colorize(colorCyan, "💡 FINSECOPS INSIGHT:"))
		if summary.CriticalCount > 0 || summary.HighCount > 0 {
			fmt.Fprintln(w, "   Attack surface topology contains exposure paths with potential financial impact.")
		}
		if summary.TotalMonthlyWasteMo > 0 {
			fmt.Fprintf(w, "   Resolving orphaned assets can immediately recover up to $%.2f/month.\n", summary.TotalMonthlyWasteMo)
		}
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, f.colorize(colorBold, "👉 Visualize your Attack Graph & auto-generate Terraform fix PRs:"))
		fmt.Fprintln(w, "   Run: possum scan aws --cloud --api-key <YOUR_KEY>")
		fmt.Fprintln(w, "   Or sign up for free at https://app.possum.io/signup")
	}
	fmt.Fprintln(w, "=================================================================================")

	return nil
}

// StripANSI removes ANSI escape codes from string.
func StripANSI(str string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(str); i++ {
		if str[i] == '\033' {
			inEsc = true
			continue
		}
		if inEsc {
			if str[i] == 'm' {
				inEsc = false
			}
			continue
		}
		b.WriteByte(str[i])
	}
	return b.String()
}
