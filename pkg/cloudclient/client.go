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

	sanitizedResults := sanitizeScanResults(results)

	summary := SummaryPayload{
		TotalEvaluated: len(sanitizedResults),
	}

	var allNodes []model.Node
	var allEdges []model.Edge

	for _, r := range sanitizedResults {
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
		Results:    sanitizedResults,
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

	bundle.GitContext.Author = sanitizeGitAuthor(bundle.GitContext.Author)
	bundle.Results = sanitizeScanResults(bundle.Results)
	bundle.GraphFragments.Nodes = sanitizeNodes(bundle.GraphFragments.Nodes)

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
		ctx.Author = os.Getenv("GITLAB_USER_LOGIN")
	}
	ctx.Author = sanitizeGitAuthor(ctx.Author)

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

var sensitiveKeyTokens = []string{
	"secret",
	"password",
	"passwd",
	"token",
	"private",
	"credential",
	"api_key",
	"apikey",
	"access_key",
	"session_key",
	"auth",
	"email",
	"ssn",
	"credit_card",
	"user_data",
	"userdata",
	"env",
	"raw_policy",
	"policy_document",
}

func sanitizeGitAuthor(author string) string {
	trimmed := strings.TrimSpace(author)
	if trimmed == "" || strings.Contains(trimmed, "@") {
		return ""
	}
	return trimmed
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, tok := range sensitiveKeyTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func isSensitiveValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	if strings.Contains(trimmed, "-----BEGIN ") ||
		strings.HasPrefix(trimmed, "AKIA") ||
		strings.HasPrefix(trimmed, "ASIA") ||
		strings.HasPrefix(strings.ToLower(trimmed), "bearer ") {
		return true
	}
	// Check for email pattern (user@domain.tld) without matching ARNs or repo@digest
	if atIdx := strings.Index(trimmed, "@"); atIdx > 0 && !strings.HasPrefix(trimmed, "arn:") && !strings.Contains(trimmed, "sha256:") {
		domain := trimmed[atIdx+1:]
		if strings.Contains(domain, ".") && !strings.ContainsAny(trimmed, " /:") {
			return true
		}
	}
	return false
}

func sanitizeMap(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		if isSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}
		switch tv := v.(type) {
		case string:
			if isSensitiveValue(tv) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = tv
			}
		case map[string]interface{}:
			out[k] = sanitizeMap(tv)
		case map[string]string:
			sub := make(map[string]interface{}, len(tv))
			for sk, sv := range tv {
				sub[sk] = sv
			}
			out[k] = sanitizeMap(sub)
		default:
			out[k] = v
		}
	}
	return out
}

func sanitizeNodes(nodes []model.Node) []model.Node {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]model.Node, len(nodes))
	for i, n := range nodes {
		out[i] = n
		out[i].Data = sanitizeMap(n.Data)
	}
	return out
}

func sanitizeScanResults(results []model.ScanResult) []model.ScanResult {
	if len(results) == 0 {
		return nil
	}
	out := make([]model.ScanResult, len(results))
	for i, r := range results {
		cp := r
		cp.Metadata = sanitizeMap(r.Metadata)
		if m, ok := r.Metrics.(map[string]interface{}); ok {
			cp.Metrics = sanitizeMap(m)
		}
		cp.Nodes = sanitizeNodes(r.Nodes)
		out[i] = cp
	}
	return out
}
