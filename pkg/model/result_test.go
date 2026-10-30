package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSeverityComparison(t *testing.T) {
	tests := []struct {
		name      string
		current   Severity
		threshold Severity
		expected  bool
	}{
		{"Critical meets Critical", SeverityCritical, SeverityCritical, true},
		{"Critical meets High", SeverityCritical, SeverityHigh, true},
		{"High meets High", SeverityHigh, SeverityHigh, true},
		{"High meets Critical", SeverityHigh, SeverityCritical, false},
		{"Medium meets Low", SeverityMedium, SeverityLow, true},
		{"Low meets Medium", SeverityLow, SeverityMedium, false},
		{"Info meets High", SeverityInfo, SeverityHigh, false},
		{"Unknown threshold never matches", SeverityCritical, "HGIH", false},
		{"Unknown severity never matches", "HGIH", SeverityLow, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MeetsThreshold(tt.current, tt.threshold)
			if got != tt.expected {
				t.Errorf("MeetsThreshold(%s, %s) = %v; expected %v", tt.current, tt.threshold, got, tt.expected)
			}
		})
	}
}

func TestParseSeverityAndValidateScanMode(t *testing.T) {
	if SeverityLevel("HGIH") != -1 {
		t.Errorf("expected -1 for unknown severity, got %d", SeverityLevel("HGIH"))
	}

	for _, valid := range []string{"critical", "HIGH", "Medium", "low", "INFO"} {
		if _, err := ParseSeverity(valid); err != nil {
			t.Errorf("expected valid severity %q, got error: %v", valid, err)
		}
	}
	if _, err := ParseSeverity("HGIH"); err == nil {
		t.Errorf("expected error for typo severity 'HGIH'")
	}

	for _, validMode := range []string{"", "quick", "STANDARD", "Deep"} {
		if _, err := ValidateScanMode(validMode); err != nil {
			t.Errorf("expected valid scan mode %q, got error: %v", validMode, err)
		}
	}
	if _, err := ValidateScanMode("turbo"); err == nil {
		t.Errorf("expected error for invalid scan mode 'turbo'")
	}
}

func TestScanResultJSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	result := ScanResult{
		ResourceID:   "vol-0123456789abcdef0",
		ResourceType: "AWS::EC2::Volume",
		Region:       "us-east-1",
		RuleID:       "ebs_volume_unused_attached",
		Title:        "Unattached EBS Volume",
		Severity:     SeverityHigh,
		Status:       StatusFail,
		Category:     CategoryFinOps,
		IsOrphaned:   true,
		CostWasteMo:  45.50,
		Description:  "EBS volume is not attached to any EC2 instance.",
		Remediation:  "Delete or snapshot the volume if no longer required.",
		EvaluatedAt:  now,
		Nodes: []Node{
			{ID: "vol-0123456789abcdef0", NodeType: "AWS::EC2::Volume"},
		},
		Edges: []Edge{
			{From: "vol-0123456789abcdef0", To: "ec2", Relation: "DETACHED"},
		},
		Metadata: map[string]interface{}{
			"size_gb": float64(100),
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var parsed ScanResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if parsed.ResourceID != result.ResourceID {
		t.Errorf("ResourceID mismatch: expected %s, got %s", result.ResourceID, parsed.ResourceID)
	}
	if parsed.Severity != result.Severity {
		t.Errorf("Severity mismatch: expected %s, got %s", result.Severity, parsed.Severity)
	}
	if parsed.CostWasteMo != result.CostWasteMo {
		t.Errorf("CostWasteMo mismatch: expected %f, got %f", result.CostWasteMo, parsed.CostWasteMo)
	}
	if len(parsed.Nodes) != 1 || parsed.Nodes[0].ID != "vol-0123456789abcdef0" {
		t.Errorf("Nodes mismatch: expected 1 node with id, got %v", parsed.Nodes)
	}
}
