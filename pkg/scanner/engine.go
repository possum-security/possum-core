package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/rules"
)

// ProgressCallback notifies callers about scanner execution lifecycle.
type ProgressCallback func(scanner Scanner, count int, err error)

// ScanReport encapsulates execution results and non-fatal scanner errors.
type ScanReport struct {
	Results []model.ScanResult
	Errors  []error
}

// EngineConfig configures the scanner orchestrator.
type EngineConfig struct {
	MaxWorkers    int
	Timeout       time.Duration
	OnProgress    ProgressCallback
	FailOnError   bool
	DisableEnrich bool
}

// Engine orchestrates concurrent execution of security and FinOps scanners.
type Engine struct {
	config     EngineConfig
	mu         sync.RWMutex
	lastErrors []error
}

// NewEngine creates an Engine instance with default or custom config.
func NewEngine(cfg ...EngineConfig) *Engine {
	config := EngineConfig{
		MaxWorkers: 10,
		Timeout:    10 * time.Minute,
	}
	if len(cfg) > 0 {
		if cfg[0].MaxWorkers > 0 {
			config.MaxWorkers = cfg[0].MaxWorkers
		}
		if cfg[0].Timeout > 0 {
			config.Timeout = cfg[0].Timeout
		}
		config.OnProgress = cfg[0].OnProgress
		config.FailOnError = cfg[0].FailOnError
		config.DisableEnrich = cfg[0].DisableEnrich
	}
	return &Engine{config: config}
}

// LastErrors returns any scanner execution errors from the most recent run.
func (e *Engine) LastErrors() []error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	res := make([]error, len(e.lastErrors))
	copy(res, e.lastErrors)
	return res
}

// ExecuteWithReport runs the scanners concurrently and returns both results and errors.
func (e *Engine) ExecuteWithReport(ctx context.Context, scanners []Scanner, filter ...model.FilterOptions) (ScanReport, error) {
	if len(scanners) == 0 {
		return ScanReport{}, nil
	}

	var filterOpt model.FilterOptions
	if len(filter) > 0 {
		filterOpt = filter[0]
		scanners = FilterScannersByMeta(scanners, filterOpt)
	}

	execCtx := ctx
	var cancel context.CancelFunc
	if e.config.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, e.config.Timeout)
		defer cancel()
	}

	semaphore := make(chan struct{}, e.config.MaxWorkers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allResults []model.ScanResult
	var scanErrors []error

	for _, s := range scanners {
		wg.Add(1)
		go func(sc Scanner) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-execCtx.Done():
				return
			}
			defer func() { <-semaphore }()

			results, err := sc.Scan(execCtx)

			mu.Lock()
			if err != nil {
				scanErrors = append(scanErrors, fmt.Errorf("%s: %w", sc.Name(), err))
			} else {
				allResults = append(allResults, results...)
			}
			mu.Unlock()

			if e.config.OnProgress != nil {
				count := 0
				if err == nil {
					count = len(results)
				}
				e.config.OnProgress(sc, count, err)
			}
		}(s)
	}

	wg.Wait()

	// Store errors on Engine instance for caller inspection
	e.mu.Lock()
	e.lastErrors = scanErrors
	e.mu.Unlock()

	// Enrich with metadata from RuleCatalog (TSK-02)
	if !e.config.DisableEnrich {
		catalog := rules.GetDefaultCatalog()
		catalog.EnrichResults(allResults)
	}

	if len(filter) > 0 {
		allResults = ApplyFilters(allResults, filterOpt)
	}

	report := ScanReport{
		Results: allResults,
		Errors:  scanErrors,
	}

	if e.config.FailOnError && len(scanErrors) > 0 {
		return report, errors.Join(scanErrors...)
	}

	return report, nil
}

// Execute runs the provided scanners concurrently and aggregates results.
func (e *Engine) Execute(ctx context.Context, scanners []Scanner, filter ...model.FilterOptions) ([]model.ScanResult, error) {
	report, err := e.ExecuteWithReport(ctx, scanners, filter...)
	return report.Results, err
}

// FilterScannersByMeta pre-filters scanners based on requested services and check IDs.
func FilterScannersByMeta(scanners []Scanner, filter model.FilterOptions) []Scanner {
	if len(filter.Services) == 0 && len(filter.Checks) == 0 {
		return scanners
	}

	var target []Scanner
	serviceMap := make(map[string]struct{}, len(filter.Services))
	for _, s := range filter.Services {
		serviceMap[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}

	checkMap := make(map[string]struct{}, len(filter.Checks))
	for _, c := range filter.Checks {
		checkMap[strings.TrimSpace(c)] = struct{}{}
	}

	for _, sc := range scanners {
		metaSc, isMeta := sc.(MetaScanner)
		if !isMeta {
			// Scanner does not provide metadata, include by default to be conservative
			target = append(target, sc)
			continue
		}

		meta := metaSc.Meta()
		svcLower := strings.ToLower(meta.Service)
		nameLower := strings.ToLower(sc.Name())

		svcMatched := len(serviceMap) == 0
		if !svcMatched {
			if _, ok := serviceMap[svcLower]; ok {
				svcMatched = true
			} else {
				for s := range serviceMap {
					if strings.Contains(nameLower, s) || strings.Contains(svcLower, s) {
						svcMatched = true
						break
					}
				}
			}
		}

		chkMatched := len(checkMap) == 0
		if !chkMatched {
			for _, cid := range meta.CheckIDs {
				if _, ok := checkMap[cid]; ok {
					chkMatched = true
					break
				}
			}
		}

		if (len(serviceMap) > 0 && svcMatched) || (len(checkMap) > 0 && chkMatched) {
			target = append(target, sc)
		}
	}

	return target
}

// ApplyFilters filters a list of results based on FilterOptions.
func ApplyFilters(results []model.ScanResult, filter model.FilterOptions) []model.ScanResult {
	if len(filter.Services) == 0 && len(filter.Severities) == 0 && len(filter.Categories) == 0 && len(filter.Checks) == 0 && filter.Mode == "" && filter.Compliance == "" {
		return results
	}

	serviceMap := make(map[string]struct{}, len(filter.Services))
	for _, s := range filter.Services {
		serviceMap[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}

	sevMap := make(map[model.Severity]struct{}, len(filter.Severities))
	for _, s := range filter.Severities {
		sevMap[strings.ToUpper(strings.TrimSpace(s))] = struct{}{}
	}

	catMap := make(map[model.Category]struct{}, len(filter.Categories))
	for _, c := range filter.Categories {
		catMap[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}

	chkMap := make(map[string]struct{}, len(filter.Checks))
	for _, chk := range filter.Checks {
		chkMap[strings.TrimSpace(chk)] = struct{}{}
	}

	var filtered []model.ScanResult
	for _, r := range results {
		// ScanMode filter: quick mode filters for CRITICAL and HIGH only
		if strings.EqualFold(filter.Mode, model.ScanModeQuick) {
			if !model.MeetsThreshold(r.Severity, model.SeverityHigh) {
				continue
			}
		}

		if len(chkMap) > 0 {
			if _, ok := chkMap[r.RuleID]; !ok {
				continue
			}
		}

		if len(sevMap) > 0 {
			if _, ok := sevMap[strings.ToUpper(r.Severity)]; !ok {
				continue
			}
		}

		if len(catMap) > 0 {
			if _, ok := catMap[strings.ToUpper(r.Category)]; !ok {
				continue
			}
		}

		filtered = append(filtered, r)
	}

	return filtered
}
