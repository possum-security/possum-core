package scanner

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
)

type panicScanner struct {
	name string
	msg  string
}

func (p *panicScanner) Name() string { return p.name }
func (p *panicScanner) Scan(ctx context.Context) ([]model.ScanResult, error) {
	panic(p.msg)
}

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

	// Filter by Mode Quick (Critical & High only)
	quickResults, _ := engine.Execute(context.Background(), []Scanner{s1}, model.FilterOptions{
		Mode: model.ScanModeQuick,
	})
	if len(quickResults) != 2 {
		t.Errorf("Expected 2 results for quick mode (chk_1, chk_3), got %d", len(quickResults))
	}
}

type mockMetaScanner struct {
	mockScanner
	meta ScannerMeta
}

func (m *mockMetaScanner) Meta() ScannerMeta {
	return m.meta
}

func TestFilterScannersByMeta(t *testing.T) {
	s3Sc := &mockMetaScanner{
		mockScanner: mockScanner{name: "s3-scanner"},
		meta: ScannerMeta{
			Service:  "s3",
			CheckIDs: []string{"s3_bucket_level_public_access_block", "s3_bucket_default_encryption"},
		},
	}
	iamSc := &mockMetaScanner{
		mockScanner: mockScanner{name: "iam-scanner"},
		meta: ScannerMeta{
			Service:  "iam",
			CheckIDs: []string{"iam_root_access_key_check", "iam_mfa_enabled"},
		},
	}
	legacySc := &mockScanner{name: "legacy-scanner"}

	all := []Scanner{s3Sc, iamSc, legacySc}

	// Filter by service "s3"
	s3Filtered := FilterScannersByMeta(all, model.FilterOptions{Services: []string{"s3"}})
	// Should include s3Sc and legacySc (since legacy has no meta)
	if len(s3Filtered) != 2 {
		t.Errorf("Expected 2 scanners (s3Sc + legacySc), got %d", len(s3Filtered))
	}

	// Filter by check ID
	chkFiltered := FilterScannersByMeta(all, model.FilterOptions{Checks: []string{"iam_mfa_enabled"}})
	if len(chkFiltered) != 2 {
		t.Errorf("Expected 2 scanners (iamSc + legacySc), got %d", len(chkFiltered))
	}
}

func TestEngineExecuteWithReport_And_Enrichment(t *testing.T) {
	s1 := &mockScanner{
		name: "s1",
		results: []model.ScanResult{
			{RuleID: "s3_bucket_level_public_access_block", Severity: model.SeverityHigh, Status: model.StatusFail},
		},
	}
	s2 := &mockScanner{
		name: "s2",
		err:  errors.New("access denied"),
	}

	engine := NewEngine()
	report, err := engine.ExecuteWithReport(context.Background(), []Scanner{s1, s2})
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	if len(report.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(report.Results))
	}
	if len(report.Errors) != 1 {
		t.Errorf("expected 1 scanner error, got %d", len(report.Errors))
	}

	// Check catalog enrichment
	if report.Results[0].Title == "" {
		t.Errorf("expected enriched title, got empty")
	}

	// Check last errors
	lastErrs := engine.LastErrors()
	if len(lastErrs) != 1 {
		t.Errorf("expected 1 last error, got %d", len(lastErrs))
	}
}

func TestEnginePanicRecovery(t *testing.T) {
	pSc := &panicScanner{name: "bad-scanner", msg: "nil pointer dereference"}
	okSc := &mockScanner{
		name: "good-scanner",
		results: []model.ScanResult{
			{ResourceID: "r1", RuleID: "s3_bucket_level_public_access_block", Severity: model.SeverityHigh, Status: model.StatusFail},
		},
	}

	engine := NewEngine(EngineConfig{MaxWorkers: 2})
	rep, err := engine.ExecuteWithReport(context.Background(), []Scanner{pSc, okSc})
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 result from good-scanner, got %d", len(rep.Results))
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("expected 1 error from panicking scanner, got %d", len(rep.Errors))
	}
	if !strings.Contains(rep.Errors[0].Error(), "scanner bad-scanner panicked: nil pointer dereference") {
		t.Errorf("expected panic error message, got: %v", rep.Errors[0])
	}
}

func TestEnginePartialResultsPreservedOnError(t *testing.T) {
	partialSc := &mockScanner{
		name: "partial-scanner",
		results: []model.ScanResult{
			{ResourceID: "bucket-1", RuleID: "s3_bucket_level_public_access_block", Severity: model.SeverityHigh, Status: model.StatusFail},
		},
		err: errors.New("throttled in us-west-2"),
	}

	engine := NewEngine()
	rep, err := engine.ExecuteWithReport(context.Background(), []Scanner{partialSc})
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	if len(rep.Results) != 1 {
		t.Fatalf("expected 1 partial result preserved, got %d", len(rep.Results))
	}
	if rep.Results[0].Title == "" {
		t.Errorf("expected partial result to be enriched with catalog title")
	}
	if len(rep.Errors) != 1 {
		t.Fatalf("expected 1 error recorded, got %d", len(rep.Errors))
	}
	if !strings.Contains(rep.Errors[0].Error(), "throttled in us-west-2") {
		t.Errorf("unexpected error message: %v", rep.Errors[0])
	}
}

func TestEngineTimeoutRecordsUnstartedScanners(t *testing.T) {
	slowSc := &mockScanner{
		name:  "slow-scanner-1",
		delay: 200 * time.Millisecond,
	}
	queuedSc1 := &mockScanner{
		name:  "queued-scanner-2",
		delay: 200 * time.Millisecond,
	}
	queuedSc2 := &mockScanner{
		name:  "queued-scanner-3",
		delay: 200 * time.Millisecond,
	}

	engine := NewEngine(EngineConfig{
		MaxWorkers: 1,
		Timeout:    30 * time.Millisecond,
	})

	rep, err := engine.ExecuteWithReport(context.Background(), []Scanner{slowSc, queuedSc1, queuedSc2})
	if err != nil {
		t.Fatalf("unexpected fatal error: %v", err)
	}

	if len(rep.Errors) != 3 {
		t.Fatalf("expected all 3 scanners (1 running + 2 queued) to report timeout errors, got %d: %v", len(rep.Errors), rep.Errors)
	}

	foundUnstarted := false
	for _, e := range rep.Errors {
		if strings.Contains(e.Error(), "did not complete before timeout") {
			foundUnstarted = true
		}
	}
	if !foundUnstarted {
		t.Errorf("expected unstarted scanner timeout error in %v", rep.Errors)
	}
}

