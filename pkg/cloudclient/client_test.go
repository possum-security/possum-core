package cloudclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/possum-sec/possum/pkg/model"
)

func TestBuildBundle(t *testing.T) {
	results := []model.ScanResult{
		{
			ResourceID:   "vol-12345",
			ResourceType: "AWS::EC2::Volume",
			Region:       "us-east-1",
			RuleID:       "ebs_unused",
			Severity:     model.SeverityHigh,
			Status:       model.StatusFail,
			Category:     model.CategoryFinOps,
			CostWasteMo:  25.0,
			Nodes:        []model.Node{{ID: "vol-12345", NodeType: "AWS::EC2::Volume"}},
			Edges:        []model.Edge{{From: "vol-12345", To: "ec2", Relation: "DETACHED"}},
		},
		{
			ResourceID:   "s3-bucket",
			ResourceType: "AWS::S3::Bucket",
			Region:       "us-east-1",
			RuleID:       "s3_public",
			Severity:     model.SeverityCritical,
			Status:       model.StatusPass,
			Category:     model.CategorySecurity,
		},
	}

	bundle := BuildBundle("123456789012", "scan_test_1", results)

	if bundle.AccountID != "123456789012" {
		t.Errorf("Expected account ID 123456789012, got %s", bundle.AccountID)
	}
	if bundle.Summary.TotalEvaluated != 2 {
		t.Errorf("Expected 2 evaluated, got %d", bundle.Summary.TotalEvaluated)
	}
	if bundle.Summary.HighCount != 1 {
		t.Errorf("Expected 1 high, got %d", bundle.Summary.HighCount)
	}
	if bundle.Summary.PassCount != 1 {
		t.Errorf("Expected 1 pass, got %d", bundle.Summary.PassCount)
	}
	if bundle.Summary.MonthlyWasteDollars != 25.0 {
		t.Errorf("Expected $25.00 waste, got %f", bundle.Summary.MonthlyWasteDollars)
	}
	if len(bundle.GraphFragments.Nodes) != 1 {
		t.Errorf("Expected 1 node, got %d", len(bundle.GraphFragments.Nodes))
	}
	if len(bundle.GraphFragments.Edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(bundle.GraphFragments.Edges))
	}
}

func TestUploadBundleSuccess(t *testing.T) {
	receivedAuth := ""
	receivedEndpoint := ""
	var receivedBundle ScanBundle

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedEndpoint = r.URL.Path

		if err := json.NewDecoder(r.Body).Decode(&receivedBundle); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "pos_test_key_123", WithHTTPClient(ts.Client()))
	bundle := BuildBundle("123456789012", "scan_test_1", []model.ScanResult{
		{
			ResourceID: "res-1",
			Status:     model.StatusPass,
		},
	})

	err := client.UploadBundle(context.Background(), bundle)
	if err != nil {
		t.Fatalf("UploadBundle failed: %v", err)
	}

	if receivedEndpoint != "/api/v1/ci/scans" {
		t.Errorf("Expected endpoint /api/v1/ci/scans, got %s", receivedEndpoint)
	}
	if receivedAuth != "Bearer pos_test_key_123" {
		t.Errorf("Expected Authorization 'Bearer pos_test_key_123', got %s", receivedAuth)
	}
	if receivedBundle.AccountID != "123456789012" {
		t.Errorf("Expected AccountID 123456789012, got %s", receivedBundle.AccountID)
	}
}

func TestUploadBundleMissingAPIKey(t *testing.T) {
	client := NewClient("https://example.com", "")
	err := client.UploadBundle(context.Background(), ScanBundle{})
	if err == nil {
		t.Error("Expected error when APIKey is empty, got nil")
	}
}
