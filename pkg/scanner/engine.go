package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/possum-sec/possum/pkg/model"
)

// ProgressCallback notifies callers about scanner execution lifecycle.
type ProgressCallback func(scanner Scanner, count int, err error)

// EngineConfig configures the scanner orchestrator.
type EngineConfig struct {
	MaxWorkers int
	Timeout    time.Duration
	OnProgress ProgressCallback
}

// Engine orchestrates concurrent execution of security and FinOps scanners.
type Engine struct {
	config EngineConfig
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
	}
	return &Engine{config: config}
}

// Execute runs the provided scanners concurrently and aggregates results.
func (e *Engine) Execute(ctx context.Context, scanners []Scanner, filter ...model.FilterOptions) ([]model.ScanResult, error) {
	if len(scanners) == 0 {
		return nil, nil
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

	if len(filter) > 0 {
		allResults = ApplyFilters(allResults, filter[0])
	}

	return allResults, nil
}

// ApplyFilters filters a list of results based on FilterOptions.
func ApplyFilters(results []model.ScanResult, filter model.FilterOptions) []model.ScanResult {
	if len(filter.Services) == 0 && len(filter.Severities) == 0 && len(filter.Categories) == 0 && len(filter.Checks) == 0 {
		return results
	}

	serviceMap := make(map[string]struct{}, len(filter.Services))
	for _, s := range filter.Services {
		serviceMap[s] = struct{}{}
	}

	sevMap := make(map[model.Severity]struct{}, len(filter.Severities))
	for _, s := range filter.Severities {
		sevMap[s] = struct{}{}
	}

	catMap := make(map[model.Category]struct{}, len(filter.Categories))
	for _, c := range filter.Categories {
		catMap[c] = struct{}{}
	}

	chkMap := make(map[string]struct{}, len(filter.Checks))
	for _, chk := range filter.Checks {
		chkMap[chk] = struct{}{}
	}

	var filtered []model.ScanResult
	for _, r := range results {
		if len(chkMap) > 0 {
			if _, ok := chkMap[r.RuleID]; !ok {
				continue
			}
		}

		if len(sevMap) > 0 {
			if _, ok := sevMap[r.Severity]; !ok {
				continue
			}
		}

		if len(catMap) > 0 {
			if _, ok := catMap[r.Category]; !ok {
				continue
			}
		}

		filtered = append(filtered, r)
	}

	return filtered
}
