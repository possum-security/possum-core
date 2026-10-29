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

	"github.com/amirmahdy/possum-core/pkg/model"
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
		return cfg.Suppressions, nil
	}

	// Try parsing as a YAML array of suppressions: [ { rule_id: ... } ]
	var list []Suppression
	if err := yaml.Unmarshal(trimmed, &list); err == nil && len(list) > 0 && list[0].RuleID != "" {
		return list, nil
	}

	// Fallback: parse as line-based text format:
	// Format: <rule_id> <resource_id> [expires_at] [reason]
	return parseTextLines(trimmed)
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
		reason := "Suppressed via ignore file"
		var expiresAt string

		if len(parts) >= 2 {
			resourceID = parts[1]
		}

		if len(parts) >= 3 {
			// Check if part 2 looks like a date: YYYY-MM-DD
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
	if len(s) == 10 && s[4] == '-' && s[7] == '-' {
		_, err := time.Parse("2006-01-02", s)
		return err == nil
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

// IsExpired returns true if an expiration date is configured and current time is past expiration.
func (s Suppression) IsExpired(now time.Time) bool {
	exp, err := s.ParseExpiry()
	if err != nil || exp == nil {
		return false
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

	// Match Resource ID
	if s.ResourceID != "" && s.ResourceID != "*" {
		if s.ResourceID == r.ResourceID {
			return true
		}
		// Glob pattern match (e.g. "arn:aws:s3:::my-bucket-*", "*-public")
		if matched, err := filepath.Match(s.ResourceID, r.ResourceID); err == nil && matched {
			return true
		}
		// Substring check if glob did not match
		if strings.Contains(r.ResourceID, s.ResourceID) {
			return true
		}
		return false
	}

	return true
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
