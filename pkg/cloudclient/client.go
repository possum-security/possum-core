package cloudclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/version"
)

// Client handles communication with the Possum SecaaS Platform.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// Option modifies Client settings.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.HTTPClient = httpClient
	}
}

// NewClient creates a new SecaaS platform API client.
func NewClient(baseURL, apiKey string, opts ...Option) *Client {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		baseURL = "https://app.possum.io"
	}

	c := &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// BuildBundle creates a complete ScanBundle from scan results and local runtime context.
func BuildBundle(accountID, scanID string, results []model.ScanResult) ScanBundle {
	if scanID == "" {
		scanID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
	}

	summary := SummaryPayload{
		TotalEvaluated: len(results),
	}

	var allNodes []model.Node
	var allEdges []model.Edge

	for _, r := range results {
		if r.Status == model.StatusPass {
			summary.PassCount++
		} else {
			switch r.Severity {
			case model.SeverityCritical:
				summary.CriticalCount++
			case model.SeverityHigh:
				summary.HighCount++
			case model.SeverityMedium:
				summary.MediumCount++
			case model.SeverityLow:
				summary.LowCount++
			}
		}
		summary.MonthlyWasteDollars += r.CostWasteMo

		if len(r.Nodes) > 0 {
			allNodes = append(allNodes, r.Nodes...)
		}
		if len(r.Edges) > 0 {
			allEdges = append(allEdges, r.Edges...)
		}
	}

	return ScanBundle{
		Version:     "1.0.0",
		AccountID:   accountID,
		ScanID:      scanID,
		TriggeredAt: time.Now().UTC(),
		ClientInfo: ClientInfo{
			Version: version.Version,
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
		},
		GitContext: DetectGitContext(),
		Summary:    summary,
		Results:    results,
		GraphFragments: GraphFragments{
			Nodes: allNodes,
			Edges: allEdges,
		},
	}
}

// UploadBundle transmits the scan bundle to the SecaaS ingestion endpoint.
func (c *Client) UploadBundle(ctx context.Context, bundle ScanBundle) error {
	if c.APIKey == "" {
		return fmt.Errorf("cloud ingestion requires POSSUM_API_KEY")
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to serialize scan bundle: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v1/ci/scans", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("X-Possum-Client-Version", version.Version)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload scan results to %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloud ingestion API rejected scan (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// DetectGitContext detects git repository context from environment variables or local git.
func DetectGitContext() GitContext {
	ctx := GitContext{
		Repository: os.Getenv("GITHUB_REPOSITORY"),
		CommitSHA:  os.Getenv("GITHUB_SHA"),
		Branch:     os.Getenv("GITHUB_REF_NAME"),
		Author:     os.Getenv("GITHUB_ACTOR"),
	}

	// GitLab CI fallbacks
	if ctx.Repository == "" {
		ctx.Repository = os.Getenv("CI_PROJECT_PATH")
	}
	if ctx.CommitSHA == "" {
		ctx.CommitSHA = os.Getenv("CI_COMMIT_SHA")
	}
	if ctx.Branch == "" {
		ctx.Branch = os.Getenv("CI_COMMIT_REF_NAME")
	}
	if ctx.Author == "" {
		ctx.Author = os.Getenv("GITLAB_USER_EMAIL")
	}

	// Local Git CLI fallback
	if ctx.CommitSHA == "" {
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			ctx.CommitSHA = strings.TrimSpace(string(out))
		}
	}
	if ctx.Branch == "" {
		if out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output(); err == nil {
			ctx.Branch = strings.TrimSpace(string(out))
		}
	}

	return ctx
}
