# Possum Core — Claude Code Guide

Possum Core (`github.com/amirmahdy/possum-core`) is a fast, developer-first Cloud Security (SecaaS/CSPM/IAM/DSPM) and FinOps Waste Scanner written in Go (1.26+). It correlates security misconfigurations, attack paths, and cloud infrastructure waste into a unified developer workflow across live AWS accounts and Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes).

## Common Commands

### Build, Test & Lint
```bash
# Build binary into bin/possum
make build

# Run full test suite with race detector
make test

# Run linter (golangci-lint)
make lint

# Run tests for a single package or specific test
go test -v -race ./pkg/scanner/... -run TestEngine
go test -v -race ./pkg/scanner/aws/finops/... -run TestEBS
```

### CLI Subcommands
- `possum scan aws` — Execute security and FinOps scans against live AWS environments (supports `--all-regions`, `--org`, `--compliance`, `--fail-on`, `--output table|json|sarif|html|mermaid`).
- `possum scan iac [path]` — Shift-left static analysis for Terraform (`.tf`), CloudFormation, and Kubernetes manifests.
- `possum rules list|info` — Browse and inspect the 655+ embedded security and FinOps rules catalog.
- `possum diff <base.json> <head.json>` — Compare two scan reports for CI/CD PR regression detection.
- `possum remediate <report.json>` — Generate executable CLI/Terraform remediation scripts from findings.
- `possum tui [report.json]` — Launch interactive terminal UI for exploring findings and waste metrics.
- `possum cloud` — Authenticate and sync telemetry with Possum Cloud.
- `possum version` — Print version, git commit, and build timestamp.

## Architecture & Package Map

- `cmd/possum/` — Cobra CLI entrypoints (`main.go`, `scan_aws.go`, `scan_iac.go`, `rules.go`, `diff.go`, `remediate.go`, `tui.go`, `cloud.go`). Uses `model.ErrThresholdExceeded` for exit code `1` and runtime errors for exit code `2`.
- `pkg/model/` — Core domain types: `ScanResult`, `Severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `Status` (`PASS`, `FAIL`, `SUPPRESSED`), `Category` (`SECURITY`, `SECAAS`, `FINOPS`, `IAM`, `DSPM`), attack graph `Node`/`Edge` models, and `FilterOptions`.
- `pkg/scanner/` — Core `Scanner` and `MetaScanner` interfaces (`scanner.go`) and the concurrent worker pool `Engine` (`engine.go`) that handles pre-filtering, rate-limited execution, error aggregation, and rule catalog enrichment.
- `pkg/scanner/aws/` — Shared AWS infrastructure: `throttled_transport.go` (per-service token-bucket rate limiting and exponential backoff), `cache.go` (`SharedCache` using `singleflight` to deduplicate API calls across scanners), `arn.go` (canonical ARN builders), `regions.go` (multi-region discovery), and `org.go` (AWS Organizations multi-account STS assume-role).
- `pkg/scanner/aws/secaas/` — AWS Security scanners covering IAM, S3, EC2, EKS, RDS, KMS, Lambda, GuardDuty, Bedrock/SageMaker AI security, DSPM, and attack graph generation.
- `pkg/scanner/aws/finops/` — AWS FinOps & waste scanners (unattached EBS, idle RDS/NAT Gateways/ELBs, orphaned EIPs/ENIs, S3 lifecycle, Cost Explorer anomalies, right-sizing).
- `pkg/scanner/iac/` — Offline IaC parsers and scanners for Terraform, CloudFormation, and Kubernetes YAML, plus custom YAML/CEL policy evaluation.
- `pkg/rules/` — Embedded rule catalog (`pkg/rules/embedded/index.json`) with `RuleCatalog.EnrichResults()` to populate titles, descriptions, compliance mappings, and remediation guidance.
- `pkg/output/` — Report formatters (`table`, `json`, `sarif`, `csv`, and interactive `html`/`mermaid` attack graphs) and summary calculators.
- `pkg/remediation/` — Safe shell and Terraform remediation generator from scan findings.
- `pkg/suppression/` — `.possumignore` parser supporting rule ID, resource ARN/glob, and expiration-based finding suppressions.
- `pkg/diff/` — Baseline comparison engine computing new, fixed, and unchanged findings plus monthly cost deltas.
- `pkg/tui/` — Interactive terminal UI explorer for navigating scan reports.
- `pkg/cloudclient/` — HTTP client and payload uploader for Possum Cloud integration.
- `pkg/config/` — `.possum.yaml` configuration loader and CLI flag merger.

## Key Engineering Conventions

1. **Concurrency & Rate Limiting**:
   - All AWS API calls flow through the custom `ThrottledTransport` (`pkg/scanner/aws/throttled_transport.go`) and `SharedCache` (`pkg/scanner/aws/cache.go`). Never bypass the shared AWS config or duplicate expensive Describe/List calls when `SharedCache` (`singleflight`) can share data across SecaaS and FinOps scanners.
   - Always respect `ctx.Done()` and `scanner.ShouldStop(ctx, count, limit)` inside pagination loops.
2. **Result Modeling & Enrichment**:
   - Every emitted `model.ScanResult` must populate `ResourceID` (prefer canonical ARNs via `pkg/scanner/aws/arn.go`), `ResourceType`, `Region`, `RuleID`, `Severity`, `Status` (`PASS`/`FAIL`), and `Category`.
   - FinOps findings must set `Category: model.CategoryFinOps` and populate `CostWasteMo` when `IsOrphaned` or waste is detected.
   - The `Engine` automatically enriches results against `pkg/rules.GetDefaultCatalog()` unless `DisableEnrich` is set.
3. **Error Handling & Exit Codes**:
   - Scanners should return wrapped errors (`fmt.Errorf("%s: %w", s.Name(), err)`) rather than panicking or calling `os.Exit`.
   - CLI commands must return `model.ErrThresholdExceeded` when `--fail-on` thresholds are breached so `main.go` exits cleanly with code `1` (versus `2` for execution errors).
4. **Testing**:
   - Write deterministic, table-driven unit tests using mock AWS client interfaces (`*_test.go`).
   - Always ensure tests pass with `-race` (`go test -v -race ./...`) since `Engine` and multi-region/multi-account runners execute concurrently.
