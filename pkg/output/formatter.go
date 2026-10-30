package output

import (
	"io"
	"sort"

	"github.com/possum-security/possum-core/pkg/model"
)

// Formatter defines the contract for rendering scan results.
type Formatter interface {
	Format(writer io.Writer, results []model.ScanResult) error
}

// SortResults deterministically sorts scan results in-place by:
// SeverityLevel desc, RuleID asc, ResourceID asc, Region asc, Status asc.
func SortResults(results []model.ScanResult) {
	sort.Slice(results, func(i, j int) bool {
		si := model.SeverityLevel(results[i].Severity)
		sj := model.SeverityLevel(results[j].Severity)
		if si != sj {
			return si > sj
		}
		if results[i].RuleID != results[j].RuleID {
			return results[i].RuleID < results[j].RuleID
		}
		if results[i].ResourceID != results[j].ResourceID {
			return results[i].ResourceID < results[j].ResourceID
		}
		if results[i].Region != results[j].Region {
			return results[i].Region < results[j].Region
		}
		return results[i].Status < results[j].Status
	})
}

// Summary calculates statistics across a set of scan results.
type Summary struct {
	TotalEvaluated      int
	PassCount           int
	FailCount           int
	SuppressedCount     int
	CriticalCount       int
	HighCount           int
	MediumCount         int
	LowCount            int
	InfoCount           int
	TotalMonthlyWasteMo float64
	OrphanedCount       int
}

// CalculateSummary aggregates metrics from scan results.
func CalculateSummary(results []model.ScanResult) Summary {
	s := Summary{
		TotalEvaluated: len(results),
	}

	for _, r := range results {
		if r.Status == model.StatusPass {
			s.PassCount++
			continue
		}
		if r.Status == model.StatusSuppressed {
			s.SuppressedCount++
			continue
		}

		s.FailCount++
		switch r.Severity {
		case model.SeverityCritical:
			s.CriticalCount++
		case model.SeverityHigh:
			s.HighCount++
		case model.SeverityMedium:
			s.MediumCount++
		case model.SeverityLow:
			s.LowCount++
		case model.SeverityInfo:
			s.InfoCount++
		}

		if r.IsOrphaned {
			s.OrphanedCount++
		}
		s.TotalMonthlyWasteMo += r.CostWasteMo
	}

	return s
}
