# Changelog

All notable changes to **Possum Core** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **IaC Scanner (`pkg/scanner/iac`)**:
  - Added CloudFormation `.yaml`, `.yml`, and `.json` template scanning for S3, Security Groups, RDS, EBS, and IAM wildcard policies.
  - Added Kubernetes manifest scanning (`Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`) for privileged containers, root execution, missing resource limits, and host namespace sharing.
  - Added `planned_values.root_module` and `.tf.json` support alongside `resource_changes` for Terraform JSON plans.
  - Populated `Metrics["File"]` and `Metrics["Line"]` (`file:line`) on all IaC findings.
- **Custom Policy Engine (`pkg/rules/custom`)**:
  - Added recursive-descent expression parser supporting `&&`, `||`, `and`, `or`, `!`, parentheses, `==`, `!=`, `<`, `<=`, `>`, `>=`, `in [...]`, `not in [...]`, `.contains(...)`, `.startsWith(...)`, `.endsWith(...)`, and nested field/map lookups (`resource.tags['env']`).
  - Added strict rule compilation and runtime evaluation error surfacing via `ValidateRule`, `LoadRule`, `LoadDirectory`, `Evaluate`, and `EvaluateRule`.
- **Documentation & Repository Tooling**:
  - Added `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.golangci.yml`, and `install.sh`.
  - Added `docs/iam-policy.json`, `docs/architecture.md`, and `docs/examples/` (`.possum.yaml`, `.possumignore`, `custom-rules.yaml`).

### Fixed
- Fixed Terraform security group scanner flagging `egress` `0.0.0.0/0` blocks as open inbound access.
- Fixed Terraform security group port matching using integer range checks (`[fromPort, toPort]`) so `from_port = 2200` no longer false-positives on SSH port `22`.

## [0.1.0] - 2026-10-29

### Added
- Concurrent AWS Security (SecaaS/CSPM/IAM/DSPM/AI) and FinOps waste scanning engine with 50 AWS scanners (41 regional + 9 global) and 655 embedded rules.
- Per-service token-bucket rate limiting (`ThrottledTransport`) and `singleflight`-deduplicated `AWSCacheTransport`.
- Multi-region (`--all-regions`, `--regions`) and AWS Organizations multi-account (`--organization`) scanning.
- Output formatters: `table`, `json`, `sarif`, `junit`, `mermaid`, and interactive `html` attack graph.
- Baseline regression diffing (`possum diff`), safe remediation script generation (`possum remediate`), `.possumignore` suppressions, and interactive terminal UI (`possum tui`).
