---
paths: ["pkg/scanner/**", "pkg/rules/**"]
---

# Scanner & Rules Architecture

## Scanner Interfaces & Registration
- Every scanner in `pkg/scanner/aws/secaas/` and `pkg/scanner/aws/finops/` must implement `scanner.Scanner` (`Name() string`, `Scan(ctx context.Context) ([]scanner.ScanResult, error)`) and `scanner.MetaScanner` (`Meta() scanner.ScannerMeta`).
- Provide two constructors per scanner:
  1. `New<Service>Scanner(cfg aws.Config, ...)` for production use with `aws.Config`.
  2. `New<Service>ScannerWithClient(client <Service>Client, ...)` accepting a narrow local client interface (defining only the AWS SDK methods the scanner calls) to support unit testing without live AWS calls.
- Register new scanners in `pkg/scanner/aws/factory.go` (50 total scanners: 41 regional + 9 global):
  - Regional scanners (13 FinOps + 28 SecaaS) go in `GetRegionalScanners(...)` (`Scope: model.ScopeRegional`).
  - Account-wide scanners (3 FinOps + 6 SecaaS: CostExplorer, CloudFront, S3, IAM, CloudTrail, Route53, Account) go in `GetGlobalScanners(...)` (`Scope: model.ScopeGlobal`).

## SecaaS vs. FinOps vs. IaC Scanner Conventions
- **SecaaS Scanners (`pkg/scanner/aws/secaas/`)**:
  - `Meta()` must set `Category: model.CategorySecOps`, valid `Service` name, `ExecutionCost` (`CostLight`, `CostMedium`, `CostHeavy`), and `CheckIDs` matching all `RuleID`s emitted by `Scan`.
  - Emit `scanner.ScanResult` for both `PASS` (`Severity: "INFO"`) and `FAIL` states, populating `Metrics["StatusExtended"]`, `Metrics["SecurityIssues"]`, `Metrics["Recommendation"]`, and graph `Nodes` / `Edges` where applicable.
- **FinOps Scanners (`pkg/scanner/aws/finops/`)**:
  - Define canonical rule ID constants in `pkg/scanner/aws/finops/rules.go` (e.g., `RuleEIPUnassigned = "ec2_elastic_ip_unassigned"`).
  - Construct results via `BuildFinOpsResult(FinOpsResultParams{...})` in `pkg/scanner/aws/finops/rules.go`. This guarantees `Category: model.CategoryFinOps`, sets `Status: FAIL` + `CostWasteMo` when `IsOrphaned: true` (or `Status: PASS` + `CostWasteMo: 0` when `false`), and populates `Metrics["DisplayName"]`.
- **IaC Scanners (`pkg/scanner/iac/`)**:
  - Supports Terraform (`.tf`, `.tf.json`, `tfplan.json` with `resource_changes` and `planned_values`), CloudFormation (`.yaml`, `.yml`, `.json`), and Kubernetes manifests (`.yaml`, `.yml`, `.json`).
  - Every IaC finding must attach `"File"` and 1-based `"Line"` (> 0) in `Metrics` (`map[string]interface{}`) and include `file:line` in `Description`.

## Rule Catalog & Custom Policy Engine (`pkg/rules/`)
- `pkg/rules/embedded/embed.go` embeds `pkg/rules/embedded/index.json` (655 checks across 89 services) via `//go:embed index.json` (`embedded.RulesFS`).
- `pkg/rules/catalog.go` loads `index.json` into `RuleCatalog` (`GetDefaultCatalog()`), indexing `CheckMetadata` by `check_id`.
- Every `RuleID` emitted by an AWS scanner and listed in `ScannerMeta.CheckIDs` must correspond to a `check_id` key in `pkg/rules/embedded/index.json` (or a canonical FinOps constant in `pkg/scanner/aws/finops/rules.go`).
- During `Engine.ExecuteWithReport`, `RuleCatalog.EnrichResults` automatically populates missing `Title`, `Description`, `Remediation`, `Category`, and `Compliance` fields on each `ScanResult` from `index.json`.
- Custom JSON unmarshalers in `pkg/rules/types.go` support both `PascalCase` and `snake_case` field names in rule definitions and normalize `Severity` to uppercase.
- `pkg/rules/custom/` provides the declarative YAML policy engine supporting expression conditions (`&&`, `||`, `and`, `or`, `!`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `in [...]`, `not in [...]`, `.contains(...)`, `.startsWith(...)`, `.endsWith(...)`, nested field/map access like `resource.tags['env']`) and structured `and`/`or`/`not` condition trees, surfacing rule compilation and evaluation errors via `ValidateRule`, `LoadRule`, `LoadDirectory`, and `Evaluate`.

## AWS Client Caching & Throttling (`pkg/scanner/aws/`)
- Always build `aws.Config` via `NewClientConfig(ctx, ClientOptions{...})` in `pkg/scanner/aws/client.go`.
- Transport pipeline order:
  1. `ThrottledTransport` (`throttled_transport.go`): enforces per-service token bucket rate limits (`DefaultServiceRates`, e.g., IAM 5 req/s, STS 10 req/s, EC2 20 req/s, S3 30 req/s), fails fast if context deadline has `< 200ms` remaining, and records `APICallEvent` telemetry in `MemoryTelemetryRecorder`.
  2. `AWSCacheTransport` (`cache.go`): caches read-only AWS calls (`GET`/`HEAD`, or `POST` with `Describe*`/`List*`/`Get*` actions) keyed by `possum:aws:<accountID>:<sha256>`, deduplicates concurrent in-flight misses via `singleflight.Group`, and applies multi-tier TTLs (Cost Explorer 12h, IAM/identity 20m, CloudWatch 15m, regional inventory 5m). Disable via `AWS_DISABLE_CACHE=true`.

## Canonical ARN Formatting (`pkg/scanner/aws/arn.go`)
- Use `FormatARN(service, region, accountID, resourceType, resourceID)` and `StandardizeResultARN(&result, defaultAccountID, defaultRegion)` to ensure `ScanResult.ResourceID` and graph `Nodes`/`Edges` use canonical AWS ARNs (`arn:aws:...`).
- `StandardizeResultARN` preserves the original human-readable identifier in `Metrics["DisplayName"]` before rewriting `ResourceID`, `Nodes[i].ID`, `Edges[i].From`, and `Edges[i].To`.
- Respect service-specific ARN formats (e.g., `arn:aws:s3:::<bucket>` with no region/account, `arn:aws:iam::<account>:role/<name>` with no region).
