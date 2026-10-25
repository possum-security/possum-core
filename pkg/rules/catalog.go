package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/possum-sec/possum/pkg/rules/embedded"
)

type rawIndexFile struct {
	TotalChecks   int                      `json:"total_checks"`
	TotalServices int                      `json:"total_services"`
	Services      []string                 `json:"services"`
	Checks        map[string]CheckMetadata `json:"checks"`
}

// RuleCatalog provides in-memory access to security checks and misconfiguration metadata.
type RuleCatalog struct {
	mu        sync.RWMutex
	checks    map[string]CheckMetadata
	sortedIDs []string
	services  []string
	total     int
}

var (
	defaultCatalogInstance *RuleCatalog
	defaultCatalogOnce     sync.Once
)

// NewRuleCatalog loads the catalog, preferring embedded files, or an optional filesystem path.
func NewRuleCatalog(optionalPath ...string) (*RuleCatalog, error) {
	var filePath string
	if len(optionalPath) > 0 && optionalPath[0] != "" {
		filePath = optionalPath[0]
	}

	var data []byte
	var err error

	if filePath != "" {
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read rules catalog file at %s: %w", filePath, err)
		}
	} else {
		data, err = embedded.RulesFS.ReadFile("index.json")
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded index.json: %w", err)
		}
	}

	var raw rawIndexFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse rules catalog JSON: %w", err)
	}

	checksMap := make(map[string]CheckMetadata, len(raw.Checks))
	var sortedIDs []string

	for id, chk := range raw.Checks {
		checkID := chk.CheckID
		if checkID == "" {
			checkID = id
			chk.CheckID = id
		}
		checksMap[checkID] = chk
		sortedIDs = append(sortedIDs, checkID)
	}
	sort.Strings(sortedIDs)

	catalog := &RuleCatalog{
		checks:    checksMap,
		sortedIDs: sortedIDs,
		services:  raw.Services,
		total:     len(checksMap),
	}

	return catalog, nil
}

// GetDefaultCatalog returns the singleton embedded RuleCatalog instance.
func GetDefaultCatalog() *RuleCatalog {
	defaultCatalogOnce.Do(func() {
		cat, err := NewRuleCatalog()
		if err != nil {
			cat = &RuleCatalog{
				checks: make(map[string]CheckMetadata),
			}
		}
		defaultCatalogInstance = cat
	})
	return defaultCatalogInstance
}

// GetCheck returns metadata for a single check by its ID.
func (c *RuleCatalog) GetCheck(checkID string) (CheckMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	chk, ok := c.checks[checkID]
	return chk, ok
}

// TotalChecks returns the total number of security checks.
func (c *RuleCatalog) TotalChecks() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.total
}

// ListServices returns all known service names.
func (c *RuleCatalog) ListServices() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	res := make([]string, len(c.services))
	copy(res, c.services)
	return res
}

// ListChecks filters and returns a slice of CheckMetadata matching filter criteria.
func (c *RuleCatalog) ListChecks(filter CheckFilter) []CheckMetadata {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var matched []CheckMetadata
	searchTerm := strings.ToLower(filter.Search)

	for _, id := range c.sortedIDs {
		chk := c.checks[id]

		if filter.ServiceName != "" && !strings.EqualFold(chk.ServiceName, filter.ServiceName) {
			continue
		}

		if filter.Severity != "" && !strings.EqualFold(chk.Severity, filter.Severity) {
			continue
		}

		if filter.ResourceType != "" && !strings.EqualFold(chk.ResourceType, filter.ResourceType) {
			continue
		}

		if searchTerm != "" {
			match := strings.Contains(strings.ToLower(chk.CheckID), searchTerm) ||
				strings.Contains(strings.ToLower(chk.CheckTitle), searchTerm) ||
				strings.Contains(strings.ToLower(chk.Description), searchTerm) ||
				strings.Contains(strings.ToLower(chk.ServiceName), searchTerm)
			if !match {
				continue
			}
		}

		matched = append(matched, chk)
	}

	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			return nil
		}
		matched = matched[filter.Offset:]
	}

	if filter.Limit > 0 && len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
	}

	return matched
}
