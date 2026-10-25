package scanner

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/possum-sec/possum/pkg/model"
)

type mockScanner struct {
	name    string
	results []model.ScanResult
	err     error
	delay   time.Duration
}

func (m *mockScanner) Name() string { return m.name }
func (m *mockScanner) Scan(ctx context.Context) ([]model.ScanResult, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.results, m.err
}

func TestEngineConcurrentExecution(t *testing.T) {
	s1 := &mockScanner{
		name: "scanner-1",
		results: []model.ScanResult{
			{ResourceID: "r1", Severity: model.SeverityHigh, Status: model.StatusFail, Category: model.CategorySecurity},
		},
	}
	s2 := &mockScanner{
		name: "scanner-2",
		results: []model.ScanResult{
			{ResourceID: "r2", Severity: model.SeverityCritical, Status: model.StatusFail, Category: model.CategoryFinOps},
		},
	}
	s3 := &mockScanner{
		name: "scanner-3",
		err:  errors.New("network error"),
	}

	var progressCount int32
	engine := NewEngine(EngineConfig{
		MaxWorkers: 2,
		OnProgress: func(s Scanner, count int, err error) {
			atomic.AddInt32(&progressCount, 1)
		},
	})

	results, err := engine.Execute(context.Background(), []Scanner{s1, s2, s3})
	if err != nil {
		t.Fatalf("Engine.Execute failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 aggregated results, got %d", len(results))
	}
	if atomic.LoadInt32(&progressCount) != 3 {
		t.Errorf("Expected progress callback called 3 times, got %d", progressCount)
	}
}

func TestEngineFiltering(t *testing.T) {
	s1 := &mockScanner{
		name: "scanner-1",
		results: []model.ScanResult{
			{RuleID: "chk_1", Severity: model.SeverityHigh, Category: model.CategorySecurity},
			{RuleID: "chk_2", Severity: model.SeverityLow, Category: model.CategoryFinOps},
			{RuleID: "chk_3", Severity: model.SeverityCritical, Category: model.CategorySecurity},
		},
	}

	engine := NewEngine()

	// Filter by Severity Critical
	critResults, _ := engine.Execute(context.Background(), []Scanner{s1}, model.FilterOptions{
		Severities: []model.Severity{model.SeverityCritical},
	})
	if len(critResults) != 1 || critResults[0].RuleID != "chk_3" {
		t.Errorf("Expected only chk_3, got %v", critResults)
	}

	// Filter by Category FinOps
	finResults, _ := engine.Execute(context.Background(), []Scanner{s1}, model.FilterOptions{
		Categories: []model.Category{model.CategoryFinOps},
	})
	if len(finResults) != 1 || finResults[0].RuleID != "chk_2" {
		t.Errorf("Expected only chk_2, got %v", finResults)
	}
}
