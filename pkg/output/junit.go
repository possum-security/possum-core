package output

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/possum-security/possum-core/pkg/model"
)

// JUnitTestSuites represents the root testsuites XML element.
type JUnitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Name     string           `xml:"name,attr"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Errors   int              `xml:"errors,attr"`
	Suites   []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite represents a testsuite element.
type JUnitTestSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	TestCases []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase represents an individual testcase element.
type JUnitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
}

// JUnitFailure represents a failure element inside a testcase.
type JUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// JUnitFormatter serializes scan results into JUnit XML format.
type JUnitFormatter struct{}

// NewJUnitFormatter creates a new JUnitFormatter.
func NewJUnitFormatter() *JUnitFormatter {
	return &JUnitFormatter{}
}

// Format renders results into JUnit XML.
func (f *JUnitFormatter) Format(w io.Writer, results []model.ScanResult) error {
	SortResults(results)
	var testCases []JUnitTestCase
	failures := 0

	for _, r := range results {
		tc := JUnitTestCase{
			Name:      fmt.Sprintf("[%s] %s", r.RuleID, r.ResourceID),
			ClassName: fmt.Sprintf("possum.%s.%s", r.Category, r.ResourceType),
			Time:      "0.010",
		}

		if r.Status == model.StatusFail {
			failures++
			msg := r.Description
			if msg == "" {
				msg = fmt.Sprintf("Rule %s failed on %s", r.RuleID, r.ResourceID)
			}
			details := fmt.Sprintf("Severity: %s\nCategory: %s\nRemediation: %s",
				r.Severity, r.Category, r.Remediation)

			tc.Failure = &JUnitFailure{
				Message: msg,
				Type:    r.Severity,
				Content: details,
			}
		}

		testCases = append(testCases, tc)
	}

	suite := JUnitTestSuite{
		Name:      "possum-cloud-scan",
		Tests:     len(results),
		Failures:  failures,
		Errors:    0,
		TestCases: testCases,
	}

	suites := JUnitTestSuites{
		Name:     "possum",
		Tests:    len(results),
		Failures: failures,
		Errors:   0,
		Suites:   []JUnitTestSuite{suite},
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(suites)
}
