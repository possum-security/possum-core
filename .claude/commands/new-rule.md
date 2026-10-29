---
description: Scaffold a new security (SecaaS) or FinOps rule and its unit tests
argument-hint: <service> <rule-id> <secaas|finops>
---

Scaffold and implement a new AWS scanner check in `possum-core` using `$ARGUMENTS` (expected format: `<service> <rule-id> <secaas|finops>`).

## Step-by-Step Implementation Workflow

1. **Parse `$ARGUMENTS`**
   - Extract `<service>` (e.g., `kms`, `s3`, `ec2`, `rds`), `<rule-id>` (snake_case, e.g., `kms_cmk_rotation_enabled` or `ebs_volume_unused_attached`), and `<category>` (`secaas` or `finops`).
   - If any argument is missing or ambiguous, inspect existing scanners in `pkg/scanner/aws/secaas/` and `pkg/scanner/aws/finops/` to match naming conventions.

2. **Implement the Check in `pkg/scanner/aws/secaas/` or `pkg/scanner/aws/finops/`**
   - **If `secaas`** (`pkg/scanner/aws/secaas/<service>.go`):
     - Define or extend the narrowed AWS SDK v2 client interface (`<Service>Client`) with only the required read-only API methods.
     - Ensure `<Service>Scanner` provides `New<Service>Scanner(cfg aws.Config)` and `New<Service>ScannerWithClient(client <Service>Client, ...)` constructors.
     - Implement `scanner.MetaScanner` (`Name() string`, `Scan(ctx context.Context) ([]scanner.ScanResult, error)`, and `Meta() scanner.ScannerMeta` with `Category: model.CategorySecOps`, `Service: "<service>"`, and `<rule-id>` included in `CheckIDs`).
     - Respect `ResourceLimit` from `ctx.Value("ResourceLimit").(int)` or `scanner.GetResourceLimit(ctx)` and use AWS SDK v2 paginators where applicable.
     - Use safe SDK pointer dereferencing (`aws.ToString`, `aws.ToBool`, `aws.ToInt32`, etc.) and emit `scanner.ScanResult` for both `PASS` (`Severity: "INFO"`) and `FAIL` outcomes with `StatusExtended` in `Metrics` and resource graph `Nodes` (`[]model.Node`).
   - **If `finops`** (`pkg/scanner/aws/finops/<service>.go`):
     - Add the canonical rule ID constant `Rule<Service><CheckName> = "<rule-id>"` in `pkg/scanner/aws/finops/rules.go`.
     - Define or extend `<Service>Client` and `<Service>Scanner` (with `var _ scanner.MetaScanner = (*<Service>Scanner)(nil)` compile-time check).
     - Append the rule constant to `Meta().CheckIDs` with `Category: model.CategoryFinOps`.
     - Compute accurate monthly waste (`Cost` in USD/month) and construct results via `BuildFinOpsResult(FinOpsResultParams{...})`, populating `Metrics["EstimatedMonthlyCost"]` and `Metrics["Recommendation"]`.
   - **If adding a brand-new scanner struct**:
     - Register it in `pkg/scanner/aws/factory.go` (`GetRegionalScanners` or `GetGlobalScanners`).
     - Register it in `pkg/scanner/aws/secaas/meta_test.go` (`TestSecaaS_AllScannersImplementMetaScanner`) or `pkg/scanner/aws/finops/rules_test.go` (`TestFinOps_MetaScannersContract`).

3. **Register Rule Metadata in `pkg/rules/embedded/index.json`**
   - Add an entry under `"checks"` keyed by `<rule-id>` matching `rules.CheckMetadata` (`pkg/rules/types.go`):
     - `CheckID`, `CheckTitle`, `ServiceName`, `SubServiceName`, `Severity` (`critical`, `high`, `medium`, `low`), `ResourceType`, `Description`, `Risk`
     - `Remediation`: `Code` (`CLI`, `NativeIaC`, `Other`, `Terraform`) and `Recommendation` (`Text`, `Url`)
     - `Categories` and `ComplianceFrameworks`
   - Ensure `<service>` is listed in `"services"` and update `"total_checks"` if appropriate.
   - If the rule is a declarative custom policy rule, also support `custom.Rule` (`pkg/rules/custom/types.go`) conventions.

4. **Wire Up Automated CLI Remediation (If Applicable)**
   - Inspect `DeriveCLICommand(r model.ScanResult) string` in `pkg/remediation/remediation.go`.
   - If `<rule-id>` has a deterministic, safe AWS CLI remediation command (or requires a commented manual review command like security group ingress revocation), add a `case "<rule-id>":` branch formatting the CLI command with `r.ResourceID` and `regionFlag`.

5. **Add Table-Driven Unit Tests**
   - In `pkg/scanner/aws/<secaas|finops>/<service>_test.go`, create or extend mock client structs implementing `<Service>Client`.
   - Write table-driven unit tests covering:
     - Compliant resource (`Status == model.StatusPass`, `CostWasteMo == 0` for FinOps)
     - Non-compliant / orphaned resource (`Status == model.StatusFail`, expected `Severity`, `RuleID`, and `CostWasteMo` / `Metrics`)
     - Edge cases (nil SDK fields, AWS-managed resources skipped, API errors, pagination/limits)
   - Run `go test -v -race ./pkg/scanner/aws/... ./pkg/rules/... ./pkg/remediation/...` to verify everything passes.
