package output

import (
	"io"

	"github.com/possum-sec/possum/pkg/model"
)

// Formatter defines the contract for rendering scan results.
type Formatter interface {
	Format(writer io.Writer, results []model.ScanResult) error
}

// Summary calculates statistics across a set of scan results.
type Summary struct {
	TotalEvaluated      int
	PassCount           int
	FailCount           int
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
