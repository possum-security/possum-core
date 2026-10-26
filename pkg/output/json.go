package output

import (
	"encoding/json"
	"io"
	"time"

	"github.com/amirmahdy/possum-core/pkg/model"
)

// JSONEnvelope encapsulates results along with metadata and summary.
type JSONEnvelope struct {
	Timestamp time.Time          `json:"timestamp"`
	Summary   Summary            `json:"summary"`
	Results   []model.ScanResult `json:"results"`
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
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if f.Envelope {
		envelope := JSONEnvelope{
			Timestamp: time.Now().UTC(),
			Summary:   CalculateSummary(results),
			Results:   results,
		}
		return encoder.Encode(envelope)
	}

	return encoder.Encode(results)
}
