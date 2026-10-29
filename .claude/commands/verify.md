---
description: Run full test suite with race detector, linter, and build verification
---

Run the full verification pipeline for `possum-core` in order, diagnosing and fixing any issues before proceeding to the next stage:

1. **Unit & Integration Tests (with Race Detector)**
   Run:
   ```bash
   go test -v -race ./...
   ```
   - Verify that all scanner unit tests (`pkg/scanner/aws/secaas/...`, `pkg/scanner/aws/finops/...`, `pkg/scanner/iac/...`), engine concurrency tests (`pkg/scanner/engine_test.go`), rule catalog tests (`pkg/rules/...`), and remediation tests (`pkg/remediation/...`) pass with zero data races.
   - Ensure `TestSecaaS_AllScannersImplementMetaScanner` (`pkg/scanner/aws/secaas/meta_test.go`) and `TestFinOps_MetaScannersContract` (`pkg/scanner/aws/finops/rules_test.go`) pass.
   - If any test fails or reports a race condition, inspect the failing package, fix the root cause, and re-run `go test -v -race ./...`.

2. **Static Analysis & Linter**
   Run:
   ```bash
   golangci-lint run ./...
   ```
   - Fix any reported lint issues (unchecked errors, unused variables/fields, ineffassign, staticcheck, or vet warnings).
   - If `golangci-lint` is not installed in the environment, run `go vet ./...` as a fallback and report that `golangci-lint` was unavailable.

3. **Build Verification**
   Run:
   ```bash
   make build
   ```
   - Verify that `go build` compiles `./cmd/possum` cleanly into `bin/possum` with version ldflags.
   - Optionally smoke-test `./bin/possum --help` to confirm the CLI initializes properly.

Report a concise summary of test results, linter status, and build output.
