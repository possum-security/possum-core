package output

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
)

// HTMLFormatter renders a standalone, zero-dependency offline HTML report and attack graph.
type HTMLFormatter struct {
	Title string
}

// NewHTMLFormatter creates a new HTML graph formatter.
func NewHTMLFormatter() *HTMLFormatter {
	return &HTMLFormatter{
		Title: "Possum Cloud Attack Graph & Audit Report",
	}
}

// Format generates an offline interactive HTML dashboard.
func (f *HTMLFormatter) Format(writer io.Writer, results []model.ScanResult) error {
	summary := CalculateSummary(results)

	// Prepare JSON payload for interactive client script
	jsonData, err := json.Marshal(results)
	if err != nil {
		jsonData = []byte("[]")
	}

	var sb strings.Builder

	sb.WriteString("<!DOCTYPE html>\n")
	sb.WriteString("<html lang=\"en\">\n<head>\n")
	sb.WriteString("  <meta charset=\"UTF-8\">\n")
	sb.WriteString("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	sb.WriteString(fmt.Sprintf("  <title>%s</title>\n", html.EscapeString(f.Title)))
	sb.WriteString(`  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --pass: #22c55e;
      --suppressed: #a855f7;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; padding: 24px; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
    .header h1 { font-size: 24px; display: flex; align-items: center; gap: 8px; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
    .stat-value { font-size: 28px; font-weight: bold; }
    .stat-label { font-size: 13px; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; }
    .grid-2 { display: grid; grid-template-columns: 1fr; gap: 24px; }
    @media (min-width: 1024px) { .grid-2 { grid-template-columns: 1.2fr 1fr; } }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 20px; overflow: hidden; }
    .card h2 { font-size: 18px; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    .table-container { max-height: 500px; overflow-y: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: #131d31; position: sticky; top: 0; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-LOW { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }
    .badge-PASS { background: rgba(34, 197, 94, 0.2); color: var(--pass); border: 1px solid var(--pass); }
    .badge-SUPPRESSED { background: rgba(168, 85, 247, 0.2); color: var(--suppressed); border: 1px solid var(--suppressed); }
    .graph-canvas { width: 100%; height: 480px; background: #090d16; border: 1px solid var(--border); border-radius: 6px; }
  </style>
</head>
<body>
`)

	sb.WriteString("  <div class=\"header\">\n")
	sb.WriteString("    <h1>🐾 Possum Core — Cloud Topology & Audit Report</h1>\n")
	sb.WriteString(fmt.Sprintf("    <div style=\"color: var(--text-muted); font-size: 13px;\">Generated: %s</div>\n", time.Now().UTC().Format(time.RFC3339)))
	sb.WriteString("  </div>\n\n")

	// Summary Cards
	sb.WriteString("  <div class=\"stats-grid\">\n")
	sb.WriteString(fmt.Sprintf("    <div class=\"stat-card\"><div class=\"stat-value\" style=\"color: var(--critical);\">%d</div><div class=\"stat-label\">Critical Issues</div></div>\n", summary.CriticalCount))
	sb.WriteString(fmt.Sprintf("    <div class=\"stat-card\"><div class=\"stat-value\" style=\"color: var(--high);\">%d</div><div class=\"stat-label\">High Issues</div></div>\n", summary.HighCount))
	sb.WriteString(fmt.Sprintf("    <div class=\"stat-card\"><div class=\"stat-value\" style=\"color: var(--medium);\">%d</div><div class=\"stat-label\">Medium / Low</div></div>\n", summary.MediumCount+summary.LowCount))
	sb.WriteString(fmt.Sprintf("    <div class=\"stat-card\"><div class=\"stat-value\" style=\"color: var(--accent);\">$%.2f/mo</div><div class=\"stat-label\">Monthly Waste</div></div>\n", summary.TotalMonthlyWasteMo))
	sb.WriteString(fmt.Sprintf("    <div class=\"stat-card\"><div class=\"stat-value\" style=\"color: var(--pass);\">%d</div><div class=\"stat-label\">Passed Checks</div></div>\n", summary.PassCount))
	sb.WriteString("  </div>\n\n")

	sb.WriteString("  <div class=\"grid-2\">\n")

	// Left: Finding Details Table
	sb.WriteString("    <div class=\"card\">\n")
	sb.WriteString("      <h2>Security & FinOps Findings</h2>\n")
	sb.WriteString("      <div class=\"table-container\">\n")
	sb.WriteString("        <table>\n")
	sb.WriteString("          <thead><tr><th>Status</th><th>Severity</th><th>Rule</th><th>Resource</th><th>Waste</th></tr></thead>\n")
	sb.WriteString("          <tbody>\n")
	for _, r := range results {
		statusBadge := fmt.Sprintf("<span class=\"badge badge-%s\">%s</span>", html.EscapeString(r.Status), html.EscapeString(r.Status))
		sevBadge := fmt.Sprintf("<span class=\"badge badge-%s\">%s</span>", html.EscapeString(r.Severity), html.EscapeString(r.Severity))
		wasteStr := "-"
		if r.CostWasteMo > 0 {
			wasteStr = fmt.Sprintf("$%.2f/mo", r.CostWasteMo)
		}
		sb.WriteString(fmt.Sprintf("            <tr><td>%s</td><td>%s</td><td><strong>%s</strong></td><td style=\"word-break: break-all;\">%s</td><td>%s</td></tr>\n",
			statusBadge, sevBadge, html.EscapeString(r.RuleID), html.EscapeString(r.ResourceID), wasteStr))
	}
	sb.WriteString("          </tbody>\n")
	sb.WriteString("        </table>\n")
	sb.WriteString("      </div>\n")
	sb.WriteString("    </div>\n\n")

	// Right: Offline SVG Topology Graph
	sb.WriteString("    <div class=\"card\">\n")
	sb.WriteString("      <h2>Attack Surface Topology Graph (Offline)</h2>\n")
	sb.WriteString("      <svg class=\"graph-canvas\" id=\"topo-svg\" viewBox=\"0 0 600 480\">\n")
	sb.WriteString("        <defs>\n")
	sb.WriteString("          <marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"8\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\">\n")
	sb.WriteString("            <path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#64748b\" />\n")
	sb.WriteString("          </marker>\n")
	sb.WriteString("        </defs>\n")

	// Render SVG nodes and lines
	renderSVGTopology(&sb, results)

	sb.WriteString("      </svg>\n")
	sb.WriteString("    </div>\n")
	sb.WriteString("  </div>\n\n")

	// Embedded Data Script
	sb.WriteString("  <script>\n")
	sb.WriteString("    const scanData = ")
	sb.Write(jsonData)
	sb.WriteString(";\n")
	sb.WriteString("  </script>\n")
	sb.WriteString("</body>\n</html>\n")

	_, err = io.WriteString(writer, sb.String())
	return err
}

func renderSVGTopology(sb *strings.Builder, results []model.ScanResult) {
	// Root/Internet Node
	sb.WriteString("        <!-- Threat Actor / Internet Node -->\n")
	sb.WriteString("        <circle cx=\"300\" cy=\"60\" r=\"28\" fill=\"#ef4444\" opacity=\"0.9\" />\n")
	sb.WriteString("        <text x=\"300\" y=\"65\" fill=\"#fff\" font-size=\"12\" font-weight=\"bold\" text-anchor=\"middle\">INTERNET</text>\n")

	// Render distinct resource nodes around canvas
	nodeCount := 0
	maxNodes := 8
	radius := 160.0
	centerX := 300.0
	centerY := 260.0

	seenResources := make(map[string]bool)

	for _, r := range results {
		if r.Status != model.StatusFail {
			continue
		}
		if seenResources[r.ResourceID] {
			continue
		}
		seenResources[r.ResourceID] = true
		nodeCount++
		if nodeCount > maxNodes {
			break
		}

		angle := float64(nodeCount-1) * (3.14159 / float64(maxNodes-1))
		x := centerX + radius*mathCos(angle)
		y := centerY + radius*mathSin(angle)*0.8

		// Connector line
		sb.WriteString(fmt.Sprintf("        <line x1=\"300\" y1=\"88\" x2=\"%.1f\" y2=\"%.1f\" stroke=\"#475569\" stroke-width=\"2\" stroke-dasharray=\"4\" marker-end=\"url(#arrow)\" />\n", x, y))

		// Node circle
		fillColor := "#3b82f6"
		if r.Severity == model.SeverityCritical {
			fillColor = "#ef4444"
		} else if r.Severity == model.SeverityHigh {
			fillColor = "#f97316"
		}

		sb.WriteString(fmt.Sprintf("        <circle cx=\"%.1f\" cy=\"%.1f\" r=\"22\" fill=\"%s\" stroke=\"#ffffff\" stroke-width=\"1.5\" />\n", x, y, fillColor))

		// Truncated resource label
		label := r.ResourceID
		if len(label) > 12 {
			label = label[:10] + ".."
		}
		sb.WriteString(fmt.Sprintf("        <text x=\"%.1f\" y=\"%.1f\" fill=\"#f8fafc\" font-size=\"10\" text-anchor=\"middle\">%s</text>\n", x, y+34, html.EscapeString(label)))
	}
}

func mathCos(rad float64) float64 {
	// Approximate cos for zero-dependency layout
	x := rad - 1.5708
	return -x + (x*x*x)/6.0
}

func mathSin(rad float64) float64 {
	x := rad
	return x - (x*x*x)/6.0 + (x*x*x*x*x)/120.0
}
