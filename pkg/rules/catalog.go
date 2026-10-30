package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/rules/embedded"
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

	// Alias iam_role_admin_access to iam_role_administratoraccess_policy
	if adminCheck, ok := checksMap["iam_role_administratoraccess_policy"]; ok {
		aliasCheck := adminCheck
		aliasCheck.CheckID = "iam_role_admin_access"
		checksMap["iam_role_admin_access"] = aliasCheck
		sortedIDs = append(sortedIDs, "iam_role_admin_access")
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

// EnrichResult decorates a ScanResult with rich human-readable titles, descriptions,
// actionable remediation recommendations, and compliance framework mappings from the catalog.
func (c *RuleCatalog) EnrichResult(r *model.ScanResult) {
	if r == nil || r.RuleID == "" {
		return
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	meta, ok := c.checks[r.RuleID]
	if !ok {
		return
	}

	if r.Title == "" && meta.CheckTitle != "" {
		r.Title = meta.CheckTitle
	}
	if r.Description == "" && meta.Description != "" {
		r.Description = meta.Description
	}
	if r.Remediation == "" {
		if meta.Remediation.Recommendation.Text != "" {
			r.Remediation = meta.Remediation.Recommendation.Text
		} else if meta.Remediation.Code.CLI != "" {
			r.Remediation = meta.Remediation.Code.CLI
		} else if meta.Remediation.Code.Terraform != "" {
			r.Remediation = meta.Remediation.Code.Terraform
		}
	}
	if r.Category == "" && len(meta.Categories) > 0 {
		r.Category = meta.Categories[0]
	}
	if len(r.Compliance) == 0 && len(meta.ComplianceFrameworks) > 0 {
		r.Compliance = make([]string, len(meta.ComplianceFrameworks))
		copy(r.Compliance, meta.ComplianceFrameworks)
	}
}

// EnrichResults enriches a slice of ScanResult structs in-place and returns the slice.
func (c *RuleCatalog) EnrichResults(results []model.ScanResult) []model.ScanResult {
	for i := range results {
		c.EnrichResult(&results[i])
	}
	return results
}

// GetChecksByFramework returns all check IDs associated with a specific compliance framework
// (e.g. "cis-3.0", "cis_3.0_aws", "pci_dss", "soc2", "iso27001_2022_aws").
func (c *RuleCatalog) GetChecksByFramework(framework string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	target := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(framework, "-", "_"), ".", "_"))
	var matched []string

	for _, id := range c.sortedIDs {
		chk := c.checks[id]
		for _, fw := range chk.ComplianceFrameworks {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(fw, "-", "_"), ".", "_"))
			if strings.Contains(normalized, target) || strings.Contains(target, normalized) {
				matched = append(matched, id)
				break
			}
		}
	}

	return matched
}

// ListComplianceFrameworks returns a deduplicated, sorted list of all compliance framework identifiers.
func (c *RuleCatalog) ListComplianceFrameworks() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	frameworkMap := make(map[string]struct{})
	for _, chk := range c.checks {
		for _, fw := range chk.ComplianceFrameworks {
			if fw != "" {
				frameworkMap[fw] = struct{}{}
			}
		}
	}

	frameworks := make([]string, 0, len(frameworkMap))
	for fw := range frameworkMap {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)
	return frameworks
}
