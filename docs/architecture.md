# Possum Core Architecture

Possum Core is a single-binary, agentless Cloud Security (SecaaS/CSPM/IAM/DSPM/AI) and FinOps Waste Scanner written in Go. It correlates cloud security misconfigurations, attack paths, and cloud infrastructure waste across live AWS accounts and shift-left Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes).

```
┌───────────────────────────────────────────────────────────────────────────┐
│                               Possum CLI                                  │
│   scan aws │ scan iac │ rules │ diff │ remediate │ tui │ cloud │ version  │
└──────┬────────────┬───────────────────────────────────────────────────────┘
       │            │
       │            ▼
       │     ┌──────────────────────────────────────────────────────────────┐
       │     │                 Shift-Left IaC & Policy Engine               │
       │     │  • Terraform (.tf, .tf.json, tfplan.json)                    │
       │     │  • CloudFormation (.yaml, .yml, .json)                       │
       │     │  • Kubernetes Manifests (.yaml, .yml, .json)                 │
       │     │  • Custom Policy Engine (pkg/rules/custom)                   │
       │     └──────────────────────────────┬───────────────────────────────┘
       ▼                                    │
┌─────────────────────────────────────────┐ │
│        Concurrent Scanner Engine        │ │
│  • Pre-Filtering (Service/Check/Mode)   │ │
│  • Worker Pool & Context Timeouts       │ │
│  • 41 Regional + 9 Global AWS Scanners  │ │
└──────┬───────────────────────────┬──────┘ │
       │                           │        │
       ▼                           ▼        ▼
┌────────────────────────────┐  ┌───────────────────────────────────────────┐
│  AWS Client Transport      │  │     Enrichment, Suppression & Output      │
│  1. ThrottledTransport     │  │  • Embedded 655-Rule Catalog Enrichment   │
│     (Per-service token     │  │  • Canonical ARN Standardization          │
│      buckets & backoff)    │  │  • .possumignore Rule Suppressions        │
│  2. AWSCacheTransport      │  │  • Formatters: Table, JSON, SARIF,        │
│     (singleflight dedup    │  │    JUnit, Mermaid, Interactive HTML       │
│      & multi-tier TTLs)    │  └───────────────────────────────────────────┘
└────────────────────────────┘
```

## Core Subsystems

### 1. CLI Layer (`cmd/possum/`)
- Built on Cobra with deterministic exit codes:
  - `0`: Scan succeeded with no findings breaching `--fail-on` threshold.
  - `1`: Findings met or exceeded `--fail-on` severity threshold (`model.ErrThresholdExceeded`), or `possum diff` detected regressions.
  - `2`: Runtime or configuration error (`model.ErrScannerExecution`).
- Merges `.possum.yaml` configuration defaults (`pkg/config/`) with explicit CLI flags.

### 2. Concurrent Scanner Engine (`pkg/scanner/`)
- `Engine` orchestrates scanner execution across a bounded worker pool (`--workers`, default `10`) with per-scan timeouts (`--timeout`, default `10m`).
- Pre-filters `MetaScanner` implementations by `--services`, `--checks`, `--compliance`, and `--mode` (`quick` skips `CostHeavy` scanners) before invoking AWS APIs.
- Automatically enriches emitted `model.ScanResult` items with titles, descriptions, compliance mappings, and remediation steps from the embedded catalog (`pkg/rules/embedded/index.json`).

### 3. AWS Transport Pipeline (`pkg/scanner/aws/`)
- **`ThrottledTransport` (`throttled_transport.go`)**: Enforces per-service token-bucket rate limits (e.g., IAM 5 req/s, STS 10 req/s, EC2 20 req/s, S3 30 req/s), fails fast when context deadline is nearly exhausted, and records API call telemetry.
- **`AWSCacheTransport` (`cache.go`)**: Deduplicates concurrent in-flight read-only AWS API requests (`Describe*`, `List*`, `Get*`) across SecaaS and FinOps scanners using `singleflight.Group` and caches responses in memory with service-appropriate TTLs.
- **Multi-Region & AWS Organizations (`regions.go`, `org.go`)**: Supports `--all-regions` auto-discovery and `--organization` cross-account STS role assumption.

### 4. SecaaS & FinOps Scanners (`pkg/scanner/aws/secaas/`, `pkg/scanner/aws/finops/`)
- **41 Regional Scanners**:
  - 13 FinOps scanners: EIP, EBS, EC2, RDS, NAT Gateway, ELB, ECR, Lambda, ECS, CloudFormation, DynamoDB, Redshift, ENI.
  - 28 SecaaS scanners: Lambda, DynamoDB, VPC, KMS, API Gateway, RDS, ELB, Messaging (SNS/SQS), EKS, Cognito, CloudFormation, ACM, VPC Advanced, CloudWatch, EC2, Access Analyzer, Config, Macie, GuardDuty, OpenSearch, ECR Security, ECS Security, Secrets Manager, Glue, Redshift, Neptune, Bedrock, SageMaker.
- **9 Global Scanners**:
  - 3 FinOps scanners: Cost Explorer, CloudFront, S3.
  - 6 SecaaS scanners: IAM, S3, CloudTrail, CloudFront, Route53, Account.

### 5. Shift-Left IaC Scanner & Custom Policy Engine (`pkg/scanner/iac/`, `pkg/rules/custom/`)
- **`pkg/scanner/iac/`**: Offline static analysis for Terraform (`.tf`, `.tf.json`, `tfplan.json`), CloudFormation (`.yaml`, `.yml`, `.json`), and Kubernetes manifests (`.yaml`, `.yml`, `.json`), reporting `File` and 1-based `Line` metrics on every finding.
- **`pkg/rules/custom/`**: Declarative YAML policy engine supporting both string expressions (`&&`, `||`, `and`, `or`, `!`, comparisons, `in`, `.contains()`, `.startsWith()`, nested map/tag access) and structured `and`/`or`/`not` condition trees.

### 6. Suppressions, Diffing, Remediation & Output (`pkg/suppression/`, `pkg/diff/`, `pkg/remediation/`, `pkg/output/`)
- **Suppressions (`pkg/suppression/`)**: `.possumignore` parser supporting YAML and line-based formats, glob matching on resource ARNs, and expiration dates (`expires_at`).
- **Baseline Diffing (`pkg/diff/`)**: Compares baseline and head JSON reports to compute new findings, resolved findings, and net monthly waste delta.
- **Remediation (`pkg/remediation/`)**: Generates safe shell scripts with dry-run and interactive confirmation guards.
- **Output (`pkg/output/`)**: Formats scan results as ANSI `table`, `json`, OASIS `sarif` v2.1.0, `junit` XML, `mermaid` graphs, and interactive `html` attack path visualizations.
