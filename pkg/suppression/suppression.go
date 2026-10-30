package suppression

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"gopkg.in/yaml.v3"
)

// DefaultIgnoreFileNames defines the default filenames looked up for suppressions.
var DefaultIgnoreFileNames = []string{
	".possumignore",
	".possumignore.yaml",
	".possumignore.yml",
}

// Suppression represents a rule exemption for a specific resource or pattern.
type Suppression struct {
	RuleID     string `yaml:"rule_id" json:"rule_id"`
	ResourceID string `yaml:"resource_id" json:"resource_id"`
	Reason     string `yaml:"reason" json:"reason"`
	ExpiresAt  string `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`
}

// Config represents the top-level schema of a YAML ignore configuration.
type Config struct {
	Suppressions []Suppression `yaml:"suppressions"`
}

// Loader parses suppression rules from various sources.
type Loader struct{}

// NewLoader creates a new suppression loader.
func NewLoader() *Loader {
	return &Loader{}
}

// Load parses suppressions from an io.Reader. Supports both YAML format and text-based line format.
func (l *Loader) Load(r io.Reader) ([]Suppression, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read suppression content: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return []Suppression{}, nil
	}

	// Try parsing as YAML Config containing "suppressions" key
	var cfg Config
	if err := yaml.Unmarshal(trimmed, &cfg); err == nil && len(cfg.Suppressions) > 0 {
		if err := validateSuppressions(cfg.Suppressions); err != nil {
			return nil, err
		}
		return cfg.Suppressions, nil
	}

	// Try parsing as a YAML array of suppressions: [ { rule_id: ... } ]
	var list []Suppression
	if err := yaml.Unmarshal(trimmed, &list); err == nil && len(list) > 0 && list[0].RuleID != "" {
		if err := validateSuppressions(list); err != nil {
			return nil, err
		}
		return list, nil
	}

	// Fallback: parse as line-based text format:
	// Format: <rule_id> <resource_id> [expires_at] <reason>
	supps, err := parseTextLines(trimmed)
	if err != nil {
		return nil, err
	}
	if err := validateSuppressions(supps); err != nil {
		return nil, err
	}
	return supps, nil
}

func validateSuppressions(supps []Suppression) error {
	for i, s := range supps {
		if strings.TrimSpace(s.RuleID) == "" {
			return fmt.Errorf("suppression entry %d requires a non-empty rule_id", i+1)
		}
		if strings.TrimSpace(s.Reason) == "" {
			return fmt.Errorf("suppression for rule %q requires a non-empty reason", s.RuleID)
		}
		if strings.TrimSpace(s.ExpiresAt) != "" {
			if _, err := s.ParseExpiry(); err != nil {
				return fmt.Errorf("suppression for rule %q has invalid expires_at: %w", s.RuleID, err)
			}
		}
	}
	return nil
}

// LoadFile reads suppressions from a given file path.
func (l *Loader) LoadFile(path string) ([]Suppression, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open ignore file %s: %w", path, err)
	}
	defer f.Close()
	return l.Load(f)
}

// DiscoverAndLoad searches standard ignore filenames in the specified directory.
// Returns empty slice without error if none are found.
func (l *Loader) DiscoverAndLoad(dir string) ([]Suppression, string, error) {
	for _, name := range DefaultIgnoreFileNames {
		candidate := filepath.Join(dir, name)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			supps, err := l.LoadFile(candidate)
			if err != nil {
				return nil, candidate, fmt.Errorf("error reading %s: %w", candidate, err)
			}
			return supps, candidate, nil
		}
	}
	return nil, "", nil
}

// parseTextLines parses text-based ignore lines.
func parseTextLines(data []byte) ([]Suppression, error) {
	var suppressions []Suppression
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip inline comments if preceded by whitespace
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		ruleID := parts[0]
		resourceID := "*"
		var reason string
		var expiresAt string

		if len(parts) >= 2 {
			resourceID = parts[1]
		}

		if len(parts) >= 3 {
			// Check if part 2 looks like a date token (YYYY-MM-DD or RFC3339)
			if isDateString(parts[2]) {
				expiresAt = parts[2]
				if len(parts) >= 4 {
					reason = strings.Join(parts[3:], " ")
				}
			} else {
				reason = strings.Join(parts[2:], " ")
			}
		}

		suppressions = append(suppressions, Suppression{
			RuleID:     ruleID,
			ResourceID: resourceID,
			Reason:     reason,
			ExpiresAt:  expiresAt,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading line format: %w", err)
	}

	return suppressions, nil
}

func isDateString(s string) bool {
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		allDigits := true
		for _, idx := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
			if s[idx] < '0' || s[idx] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && (len(s) == 10 || s[10] == 'T') {
			return true
		}
	}
	return false
}

// ParseExpiry parses the expiration string into a time.Time.
// Dates formatted as YYYY-MM-DD are treated as expiring at the end of that day (23:59:59 UTC).
func (s Suppression) ParseExpiry() (*time.Time, error) {
	exp := strings.TrimSpace(s.ExpiresAt)
	if exp == "" {
		return nil, nil
	}

	// YYYY-MM-DD
	if len(exp) == 10 {
		t, err := time.Parse("2006-01-02", exp)
		if err != nil {
			return nil, err
		}
		// End of the specified day UTC
		endOfDay := time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, time.UTC)
		return &endOfDay, nil
	}

	// RFC3339
	if t, err := time.Parse(time.RFC3339, exp); err == nil {
		return &t, nil
	}

	// Datetime format "2006-01-02 15:04:05"
	if t, err := time.Parse("2006-01-02 15:04:05", exp); err == nil {
		return &t, nil
	}

	return nil, fmt.Errorf("unrecognized expiry date format: %q (expected YYYY-MM-DD or RFC3339)", exp)
}

// IsExpired returns true if an expiration date is configured and current time is past expiration
// or if the configured expiration date cannot be parsed.
func (s Suppression) IsExpired(now time.Time) bool {
	if strings.TrimSpace(s.ExpiresAt) == "" {
		return false
	}
	exp, err := s.ParseExpiry()
	if err != nil || exp == nil {
		return true
	}
	return now.After(*exp)
}

// Matches checks whether the given scan result matches this suppression rule.
func (s Suppression) Matches(r model.ScanResult) bool {
	// Match Rule ID
	if s.RuleID != "" && s.RuleID != "*" {
		if !strings.EqualFold(s.RuleID, r.RuleID) {
			return false
		}
	}

	return matchesResource(s.ResourceID, r)
}

func matchesResource(pattern string, r model.ScanResult) bool {
	if pattern == "" || pattern == "*" {
		return true
	}

	candidates := resourceCandidates(r)
	isGlob := strings.ContainsAny(pattern, "*?")

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if pattern == c {
			return true
		}
		if isGlob {
			if matched, err := filepath.Match(pattern, c); err == nil && matched {
				return true
			}
			// Also support glob matching across '/' separators in ARNs
			if strings.Contains(c, "/") {
				normPattern := strings.ReplaceAll(pattern, "/", ":")
				normCand := strings.ReplaceAll(c, "/", ":")
				if matched, err := filepath.Match(normPattern, normCand); err == nil && matched {
					return true
				}
			}
		}
	}

	return false
}

func resourceCandidates(r model.ScanResult) []string {
	candidates := []string{r.ResourceID}

	if dn := extractDisplayName(r); dn != "" && dn != r.ResourceID {
		candidates = append(candidates, dn)
	}

	if strings.HasPrefix(r.ResourceID, "arn:") {
		parts := strings.SplitN(r.ResourceID, ":", 6)
		if len(parts) == 6 && parts[5] != "" {
			resPart := parts[5]
			candidates = append(candidates, resPart)
			if idx := strings.LastIndex(resPart, ":"); idx != -1 && idx+1 < len(resPart) {
				candidates = append(candidates, resPart[idx+1:])
			}
			if idx := strings.Index(resPart, "/"); idx != -1 && idx+1 < len(resPart) {
				candidates = append(candidates, resPart[idx+1:])
			}
			if idx := strings.LastIndex(resPart, "/"); idx != -1 && idx+1 < len(resPart) {
				candidates = append(candidates, resPart[idx+1:])
			}
		}
	}

	return candidates
}

func extractDisplayName(r model.ScanResult) string {
	if m, ok := r.Metrics.(map[string]interface{}); ok {
		if dn, ok := m["DisplayName"].(string); ok && dn != "" {
			return dn
		}
		if dn, ok := m["display_name"].(string); ok && dn != "" {
			return dn
		}
	}
	if r.Metadata != nil {
		if dn, ok := r.Metadata["DisplayName"].(string); ok && dn != "" {
			return dn
		}
		if dn, ok := r.Metadata["display_name"].(string); ok && dn != "" {
			return dn
		}
	}
	return ""
}

// Filter evaluates scan results against suppressions at time.Now().
// Matched non-expired results are marked with StatusSuppressed and SuppressedReason.
// Expired suppressions are ignored.
func Filter(results []model.ScanResult, suppressions []Suppression) []model.ScanResult {
	return ApplySuppressionsAt(results, suppressions, time.Now())
}

// ApplySuppressions applies suppressions to results in-place or returns updated results.
func ApplySuppressions(results []model.ScanResult, suppressions []Suppression) []model.ScanResult {
	return ApplySuppressionsAt(results, suppressions, time.Now())
}

// ApplySuppressionsAt evaluates suppressions using a specific point in time (for deterministic testing).
func ApplySuppressionsAt(results []model.ScanResult, suppressions []Suppression, now time.Time) []model.ScanResult {
	if len(suppressions) == 0 || len(results) == 0 {
		return results
	}

	out := make([]model.ScanResult, len(results))
	copy(out, results)

	for i := range out {
		// Only evaluate findings that are in FAIL status (or not already PASS)
		if out[i].Status == model.StatusPass {
			continue
		}

		for _, sup := range suppressions {
			if sup.IsExpired(now) {
				continue
			}

			if sup.Matches(out[i]) {
				out[i].Status = model.StatusSuppressed
				reason := sup.Reason
				if reason == "" {
					reason = "Suppressed by .possumignore"
				}
				out[i].SuppressedReason = reason
				break
			}
		}
	}

	return out
}
