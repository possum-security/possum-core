package output

import (
	"bytes"
	"testing"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGraph_MermaidFormatter(t *testing.T) {
	results := []model.ScanResult{
		{
			RuleID:       "s3_bucket_level_public_access_block",
			ResourceID:   "public-bucket",
			ResourceType: "S3",
			Status:       model.StatusFail,
			Severity:     model.SeverityHigh,
			Nodes: []model.Node{
				{ID: "public-bucket", NodeType: "S3"},
				{ID: "INTERNET", NodeType: "ThreatActor"},
			},
			Edges: []model.Edge{
				{From: "INTERNET", To: "public-bucket", Relation: "exposes"},
			},
		},
	}

	formatter := NewMermaidFormatter()
	var buf bytes.Buffer
	err := formatter.Format(&buf, results)
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "```mermaid")
	assert.Contains(t, out, "flowchart TD")
	assert.Contains(t, out, "public_bucket")
	assert.Contains(t, out, "-->|exposes|")
}

func TestGraph_HTMLFormatter(t *testing.T) {
	results := []model.ScanResult{
		{
			RuleID:       "s3_bucket_level_public_access_block",
			ResourceID:   "public-bucket",
			ResourceType: "S3",
			Status:       model.StatusFail,
			Severity:     model.SeverityHigh,
			CostWasteMo:  12.50,
		},
		{
			RuleID:       "iam_root_mfa_enabled",
			ResourceID:   "RootAccount",
			ResourceType: "IAM",
			Status:       model.StatusPass,
			Severity:     model.SeverityInfo,
		},
	}

	formatter := NewHTMLFormatter()
	var buf bytes.Buffer
	err := formatter.Format(&buf, results)
	require.NoError(t, err)

	html := buf.String()
	assert.Contains(t, html, "<!DOCTYPE html>")
	assert.Contains(t, html, "Possum Core")
	assert.Contains(t, html, "public-bucket")
	assert.Contains(t, html, "$12.50/mo")
	assert.Contains(t, html, "<svg class=\"graph-canvas\"")
	assert.Contains(t, html, "INTERNET")
}
