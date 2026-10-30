# Contributing to Possum Core

Thank you for contributing to **Possum Core**! This document outlines the development setup, architectural conventions, and pull request workflow.

## Prerequisites

- **Go**: `1.26` or newer
- **Make**: GNU Make
- **golangci-lint**: Optional, for local linting (`make lint`)

## Quick Development Workflow

```bash
# 1. Build the CLI binary into ./bin/possum
make build

# 2. Run the full test suite with the race detector enabled
make test

# 3. Run static analysis and linters
make lint
```

## Architecture & Adding a New Scanner

### 1. AWS SecaaS or FinOps Scanners
All live AWS scanners live under `pkg/scanner/aws/secaas/` (security posture, IAM, DSPM, AI security) or `pkg/scanner/aws/finops/` (cloud waste and right-sizing).

Each scanner must:
1. Implement `scanner.Scanner` (`Name() string`, `Scan(ctx context.Context) ([]scanner.ScanResult, error)`) and `scanner.MetaScanner` (`Meta() scanner.ScannerMeta`).
2. Provide two constructors:
   - `New<Service>Scanner(cfg aws.Config, ...)` for production use.
   - `New<Service>ScannerWithClient(client <Service>Client, ...)` accepting a narrow interface for unit testing with mock clients.
3. Respect context cancellation and resource limits via `scanner.ShouldStop(ctx, currentCount, limit)` inside pagination loops.
4. Register the scanner in `pkg/scanner/aws/factory.go`:
   - `GetRegionalScanners(...)` for per-region checks (`Scope: model.ScopeRegional`).
   - `GetGlobalScanners(...)` for account-wide checks (`Scope: model.ScopeGlobal`).
5. Ensure all emitted `RuleID`s are listed in `ScannerMeta.CheckIDs` and exist in `pkg/rules/embedded/index.json` (or `pkg/scanner/aws/finops/rules.go`).

### 2. IaC & Custom Policy Rules
- IaC checks for Terraform (`.tf`, `.tf.json`, `tfplan.json`), CloudFormation (`.yaml`, `.yml`, `.json`), and Kubernetes manifests (`.yaml`, `.yml`, `.json`) live in `pkg/scanner/iac/`.
- Every IaC `ScanResult` must populate `Metrics["File"]` and `Metrics["Line"]` (> 0) and include `file:line` in `Description`.
- Declarative custom policy evaluation lives in `pkg/rules/custom/`.

## Testing Guidelines

- Write deterministic, table-driven unit tests (`*_test.go`) without requiring live AWS credentials or network access.
- Verify concurrency safety with `go test -race ./...`.

## Pull Request Checklist

- [ ] `go vet ./...` and `make test` pass with `-race`.
- [ ] New rules/scanners include unit tests covering both `PASS` and `FAIL` conditions.
- [ ] Documentation (`README.md`, `CLAUDE.md`, `docs/`) is updated if CLI flags or capabilities change.
- [ ] Commit messages follow conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
