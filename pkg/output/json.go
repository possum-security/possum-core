package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
)

// JSONEnvelope encapsulates results along with metadata and summary.
type JSONEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	Timestamp     time.Time          `json:"timestamp"`
	Summary       Summary            `json:"summary"`
	Results       []model.ScanResult `json:"results"`
}

// JSONFormatter serializes results as pretty-printed JSON.
type JSONFormatter struct {
	Envelope bool
}

// NewJSONFormatter creates a new JSONFormatter.
func NewJSONFormatter(envelope bool) *JSONFormatter {
	return &JSONFormatter{Envelope: envelope}
}

// Format writes formatted JSON to the writer.
func (f *JSONFormatter) Format(w io.Writer, results []model.ScanResult) error {
	if results == nil {
		results = []model.ScanResult{}
	}
	SortResults(results)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if f.Envelope {
		envelope := JSONEnvelope{
			SchemaVersion: "1.0",
			Timestamp:     time.Now().UTC(),
			Summary:       CalculateSummary(results),
			Results:       results,
		}
		return encoder.Encode(envelope)
	}

	return encoder.Encode(results)
}

// LoadResults decodes scan results from r, accepting either a JSONEnvelope object
// ({"timestamp": ..., "summary": ..., "results": [...]}) or a raw JSON array ([...]).
func LoadResults(r io.Reader) ([]model.ScanResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read findings JSON: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty findings JSON input")
	}

	switch trimmed[0] {
	case '[':
		var results []model.ScanResult
		if err := json.Unmarshal(trimmed, &results); err != nil {
			return nil, fmt.Errorf("failed to parse findings JSON array: %w", err)
		}
		if results == nil {
			results = []model.ScanResult{}
		}
		return results, nil

	case '{':
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return nil, fmt.Errorf("failed to parse findings JSON object: %w", err)
		}
		_, hasResults := raw["results"]
		_, hasSummary := raw["summary"]
		_, hasTimestamp := raw["timestamp"]
		if !hasResults && !hasSummary && !hasTimestamp {
			return nil, fmt.Errorf("unrecognized findings JSON object: missing 'results' field")
		}

		var env JSONEnvelope
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("failed to parse findings JSON envelope: %w", err)
		}
		if env.Results == nil {
			return []model.ScanResult{}, nil
		}
		return env.Results, nil

	default:
		return nil, fmt.Errorf("invalid findings JSON: expected array or envelope object")
	}
}

// LoadResultsFromFile reads a ScanResult slice from a JSON scan file (either JSONEnvelope or raw array).
func LoadResultsFromFile(path string) ([]model.ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer f.Close()

	results, err := LoadResults(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON from %s: %w", path, err)
	}
	return results, nil
}
