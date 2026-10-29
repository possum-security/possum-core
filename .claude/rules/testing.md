---
paths: ["**/*_test.go"]
---

# Testing Standards (`possum-core`)

## Test Execution & Race Detection
- All tests must pass with the Go race detector enabled:
  ```bash
  go test -v -race ./...
  ```
- Tests must be completely self-contained, deterministic, and safe for concurrent execution. When testing concurrent primitives (`AWSCacheTransport`, `ThrottledTransport`, `scanner.Engine`), instantiate isolated instances (e.g., new `AWSCache` or `MemoryTelemetryRecorder`) rather than mutating global singletons across parallel tests.

## Table-Driven Tests
- Prefer table-driven tests with `t.Run(tt.name, func(t *testing.T) { ... })` for functions with multiple input/output permutations, edge cases, or PASS/FAIL scanner scenarios:
  ```go
  tests := []struct {
      name     string
      input    string
      expected string
  }{
      {name: "valid case", input: "foo", expected: "bar"},
  }
  for _, tt := range tests {
      t.Run(tt.name, func(t *testing.T) {
          got := Fn(tt.input)
          assert.Equal(t, tt.expected, got)
      })
  }
  ```

## Mocking AWS SDK Clients (Zero Live Cloud Calls)
- Unit tests must **never** make live network requests to AWS endpoints or rely on local `~/.aws` credentials.
- For scanner unit tests (`pkg/scanner/aws/secaas/*_test.go`, `pkg/scanner/aws/finops/*_test.go`):
  - Implement a lightweight mock struct satisfying the scanner's `<Service>Client` interface (e.g., `mockAccessAnalyzerClient`, `mockECRClient`).
  - Inject the mock using `New<Service>ScannerWithClient(mockClient, ...)`.
  - Test at minimum: passing/compliant resource state (`Status: "PASS"`), failing/orphaned resource state (`Status: "FAIL"`), and AWS API error propagation where relevant.
- For HTTP transport / middleware tests (`cache_test.go`, `throttled_transport_test.go`):
  - Use a custom `http.RoundTripper` (e.g., `mockRoundTripper` with `atomic.Int32` call counters) instead of real network sockets.
- If testing code paths that invoke `NewClientConfig`, set `AWS_MOCK_MODE=true` or use an `httptest.Server` via `AWS_ENDPOINT_URL`.

## Deterministic Assertions & Metadata Verification
- Use `github.com/stretchr/testify/require` for preconditions that must halt the test on failure (e.g., `require.NoError(t, err)`, `require.Len(t, results, 1)`) and `github.com/stretchr/testify/assert` for field assertions (`Status`, `RuleID`, `Severity`, `ResourceID`, `IsOrphaned`, `Metrics`).
- Do not assert on wall-clock timestamps (`EvaluatedAt`, `Timestamp`) with exact equality; use relative time offsets (e.g., `time.Now().AddDate(0, 0, -200)`) or non-zero checks.
- Keep `pkg/scanner/aws/secaas/meta_test.go` updated whenever adding a new SecaaS scanner to verify `Meta()` returns non-empty `ID`, `Service`, `CheckIDs`, and `Category: model.CategorySecOps`.
