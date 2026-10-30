# Possum Core — Claude Code Guide

Possum Core (`github.com/possum-security/possum-core`) is a fast, single-binary, agentless Cloud Security (SecaaS/CSPM/IAM/DSPM/AI) and FinOps Waste Scanner written in Go (1.26+). It correlates security misconfigurations, attack paths, and cloud infrastructure waste into a unified developer workflow across live AWS accounts and Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes).

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
- `possum scan aws` — Execute security and FinOps scans against live AWS environments (supports `--region`, `--regions`, `--all-regions`, `--organization` / `--org`, `--services`, `--checks`, `--compliance`, `--mode quick|standard|deep`, `--fail-on`, `--fail-on-error`, `--format table|json|sarif|junit|csv|mermaid|html`, `--output <file>`, `--ignore-file`).
- `possum scan iac <directory-or-file>` — Shift-left static analysis for Terraform (`.tf`, `.tf.json`, `tfplan.json`), CloudFormation (`.yaml`, `.yml`, `.json`), and Kubernetes manifests (`.yaml`, `.yml`, `.json`) with `--format`, `--output`, `--fail-on`, and `--custom-rules`.
- `possum rules list|get|info` — Browse (`possum rules list --service <svc> --severity <sev> --search <q>`) and inspect (`possum rules get <rule_id>` / `possum rules info <rule_id>`) the 655+ embedded security and FinOps rules catalog.
- `possum diff <baseline.json> <head.json>` — Compare two scan reports for CI/CD PR regression detection (`--format markdown-pr|table|json`).
- `possum remediate [findings.json]` — Generate safe executable shell remediation scripts from findings (`--dry-run`, `--confirm`, `--export`).
- `possum tui [findings.json]` — Launch interactive terminal UI for exploring findings and waste metrics.
- `possum cloud login|status|logout` — Authenticate and manage connection with Possum Cloud.
- `possum version` — Print version, git commit, and build timestamp.

## Architecture & Package Map

- `cmd/possum/` — Cobra CLI entrypoints (`main.go`, `scan.go`, `scan_aws.go`, `scan_iac.go`, `rules.go`, `diff.go`, `remediate.go`, `tui.go`, `cloud.go`, `version.go`). Uses `model.ErrThresholdExceeded` for exit code `1` and runtime errors for exit code `2`.
- `pkg/model/` — Core domain types (`result.go`, `graph.go`, `target.go`): `ScanResult`, `Severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `Status` (`PASS`, `FAIL`, `SUPPRESSED`), `Category` (`SECURITY`, `SECAAS`, `FINOPS`, `IAM`, `DSPM`), attack graph `Node`/`Edge` models, and `FilterOptions`.
- `pkg/scanner/` — Core `Scanner` and `MetaScanner` interfaces (`scanner.go`) and the concurrent worker pool `Engine` (`engine.go`) that handles pre-filtering, rate-limited execution, error aggregation, and rule catalog enrichment.
- `pkg/scanner/aws/` — Shared AWS infrastructure (`client.go`, `factory.go`, `throttled_transport.go`, `cache.go`, `arn.go`, `regions.go`, `org.go`, `cloudwatch_util.go`). Registers 50 AWS scanners in `factory.go` (41 regional + 9 global).
- `pkg/scanner/aws/secaas/` — 34 AWS Security scanners (28 regional + 6 global) covering IAM, S3, EC2, VPC, EKS, ECS, ECR, RDS, KMS, Lambda, DynamoDB, API Gateway, ELB, SNS/SQS, Cognito, CloudFormation, ACM, CloudWatch, CloudTrail, CloudFront, Route53, Account, Access Analyzer, Config, Macie, GuardDuty, OpenSearch, Secrets Manager, Glue, Redshift, Neptune, Bedrock, and SageMaker.
- `pkg/scanner/aws/finops/` — 16 AWS FinOps & waste scanners (13 regional + 3 global) covering unattached EBS, unassigned EIPs, orphaned ENIs, idle EC2/RDS/NAT Gateways/ELBs/Redshift/DynamoDB/ECS/Lambda, ECR image sprawl, failed CloudFormation stacks, S3 lifecycle, CloudFront waste, and Cost Explorer anomalies.
- `pkg/scanner/iac/` — Offline IaC parsers and scanners for Terraform (`.tf`, `.tf.json`, `tfplan.json`), CloudFormation (`.yaml`, `.yml`, `.json`), and Kubernetes manifests (`.yaml`, `.yml`, `.json`) with `File` and `Line` location metrics.
- `pkg/rules/` — Embedded 655-rule catalog (`pkg/rules/embedded/index.json`) with `RuleCatalog.EnrichResults()` and the declarative custom policy engine (`pkg/rules/custom/`).
- `pkg/output/` — Report formatters (`table`, `json`, `sarif`, `junit`, `csv`, `mermaid`, and interactive `html` attack graphs) and summary calculators.
- `pkg/remediation/` — Safe shell remediation script generator from scan findings.
- `pkg/suppression/` — `.possumignore` parser supporting rule ID, resource ARN/glob, and expiration-based finding suppressions.
- `pkg/diff/` — Baseline comparison engine computing new, resolved, and unchanged findings plus monthly cost deltas.
- `pkg/tui/` — Interactive terminal UI explorer for navigating scan reports.
- `pkg/cloudclient/` — HTTP client and payload uploader for Possum Cloud integration.
- `pkg/config/` — `.possum.yaml` configuration loader and CLI flag merger.

## Key Engineering Conventions

1. **Concurrency & Rate Limiting**:
   - All AWS API calls flow through `ThrottledTransport` (`pkg/scanner/aws/throttled_transport.go`) and `AWSCacheTransport` (`pkg/scanner/aws/cache.go`). Never bypass the shared AWS config or duplicate expensive Describe/List calls when `AWSCacheTransport` (`singleflight`) can share data across SecaaS and FinOps scanners.
   - Always respect `ctx.Done()` and `scanner.ShouldStop(ctx, count, limit)` inside pagination loops.
2. **Result Modeling & Enrichment**:
   - Every emitted `model.ScanResult` must populate `ResourceID` (prefer canonical ARNs via `pkg/scanner/aws/arn.go`), `ResourceType`, `Region`, `RuleID`, `Severity`, `Status` (`PASS`/`FAIL`), and `Category`.
   - FinOps findings must set `Category: model.CategoryFinOps` and populate `CostWasteMo` when `IsOrphaned` or waste is detected.
   - IaC findings must populate `Metrics["File"]` and `Metrics["Line"]` (> 0).
   - The `Engine` automatically enriches results against `pkg/rules.GetDefaultCatalog()` unless `DisableEnrich` is set.
3. **Error Handling & Exit Codes**:
   - Scanners should return wrapped errors (`fmt.Errorf("%s: %w", s.Name(), err)`) rather than panicking or calling `os.Exit`.
   - CLI commands must return `model.ErrThresholdExceeded` when `--fail-on` thresholds are breached so `main.go` exits cleanly with code `1` (versus `2` for execution errors).
4. **Testing**:
   - Write deterministic, table-driven unit tests using mock AWS client interfaces (`*_test.go`).
   - Always ensure tests pass with `-race` (`go test -v -race ./...`) since `Engine` and multi-region/multi-account runners execute concurrently.
