package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"github.com/possum-security/possum-core/pkg/model"
)

// CSVFormatter serializes scan results into RFC 4180 CSV format.
type CSVFormatter struct{}

// NewCSVFormatter creates a new CSVFormatter.
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

// Format writes CSV rows to the writer after deterministic sorting.
func (f *CSVFormatter) Format(w io.Writer, results []model.ScanResult) error {
	SortResults(results)

	cw := csv.NewWriter(w)
	header := []string{
		"rule_id",
		"title",
		"severity",
		"status",
		"category",
		"resource_id",
		"resource_type",
		"region",
		"account_id",
		"is_orphaned",
		"cost_waste_monthly",
		"description",
		"remediation",
	}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, r := range results {
		row := []string{
			r.RuleID,
			r.Title,
			string(r.Severity),
			string(r.Status),
			string(r.Category),
			r.ResourceID,
			r.ResourceType,
			r.Region,
			r.AccountID,
			strconv.FormatBool(r.IsOrphaned),
			fmt.Sprintf("%.2f", r.CostWasteMo),
			r.Description,
			r.Remediation,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	cw.Flush()
	return cw.Error()
}
