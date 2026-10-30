# Possum Core — Open-Source Roadmap & Improvement Task Catalog

This document details all identified bugs, architectural improvements, and feature expansions for **Possum Core**, prioritized and sorted using an **ROI vs. Complexity Matrix**.

---

## 🧭 Prioritization Matrix Summary

```
                      HIGH ROI
                         │
     [Tier 1: Quick Wins]│ [Tier 2: Strategic Core]
     • Fix FinOps Model  │ • Multi-Region Scanning
     • Catalog Enrich    │ • Rule Suppressions (.possumignore)
     • Surface Errors    │ • Config File (.possum.yaml)
     • Open-Source Lic.  │ • Compliance Frameworks (--compliance)
     • Cobra Exit Flow   │ • MetaScanner Pre-filtering
                         │ • Scan Diff Mode (possum diff)
   ──────────────────────┼───────────────────────
     [Tier 4: Ergonomics]│ [Tier 3 & 5: Big Bets]
     • Dead Code Cleanup │ • Local Attack Graph Export (Mermaid/HTML)
     • CLI Remediate Gen │ • Shift-Left IaC Scanning (possum scan iac)
     • Terminal TUI      │ • Multi-Account / AWS Organizations
                         │ • Custom Policy Engine (CEL / Rego)
                         │
                      LOW ROI
       LOW COMPLEXITY  ──┼──  HIGH COMPLEXITY
```

### Master Task Inventory

| Task ID | Task Title | Category | ROI | Complexity | Status | Target Version |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-01** | Fix FinOps Result Modeling & Fields Population | Bug / Data Model | **Critical** | **Low** | ✅ **Completed** | v0.2.0 |
| **TSK-02** | Wire RuleCatalog Metadata Enrichment into Engine | Architecture | **High** | **Low** | ✅ **Completed** | v0.2.0 |
| **TSK-03** | Surface & Aggregate Scanner Execution Errors | Reliability | **High** | **Low** | ✅ **Completed** | v0.2.0 |
| **TSK-04** | Adopt OSI-Approved Open-Source License (Apache 2.0 / MIT) | Governance | **Critical** | **Very Low** | ✅ **Completed** | v0.2.0 |
| **TSK-05** | Refactor CLI `os.Exit(1)` into Clean Cobra Error Flow | CLI / Testing | **Medium** | **Low** | ✅ **Completed** | v0.2.0 |
| **TSK-06** | Implement `MetaScanner` for Targeted Pre-Filtering | Performance | **High** | **Medium** | ✅ **Completed** | v0.3.0 |
| **TSK-07** | Multi-Region & Auto-Discovery Scanning (`--all-regions`) | Core Capability | **Very High** | **Medium** | ✅ **Completed** | v0.3.0 |
| **TSK-08** | Rule Suppression & Ignore System (`.possumignore`) | DevSecOps | **Very High** | **Medium** | ✅ **Completed** | v0.3.0 |
| **TSK-09** | Configuration File Support (`.possum.yaml`) | Ergonomics | **High** | **Medium** | ✅ **Completed** | v0.3.0 |
| **TSK-10** | Compliance Framework Filtering (`--compliance`) | Compliance | **High** | **Medium** | ✅ **Completed** | v0.3.0 |
| **TSK-11** | Scan Diffing & PR Regression Detection (`possum diff`) | CI/CD | **High** | **Medium** | ✅ **Completed** | v0.4.0 |
| **TSK-12** | Local Offline Attack Graph Visualization (Mermaid / HTML) | Feature / UX | **High** | **Medium** | ✅ **Completed** | v0.4.0 |
| **TSK-13** | Multi-Account & AWS Organizations Scanning | Enterprise | **High** | **High** | ✅ **Completed** | v0.4.0 |
| **TSK-14** | Shift-Left Infrastructure-as-Code Scanning (`possum scan iac`) | Expansion | **Very High**| **High** | ✅ **Completed** | v0.5.0 |
| **TSK-15** | Standardize Resource IDs on Canonical AWS ARNs | Data Integrity | **Medium** | **Medium** | ✅ **Completed** | v0.3.0 |
| **TSK-16** | Automated Remediation Script Generator (`possum remediate`) | Automation | **Medium** | **Low-Med** | ✅ **Completed** | v0.4.0 |
| **TSK-17** | Dead Code & Unused Abstractions Cleanup | Refactoring | **Low-Med**| **Low** | ✅ **Completed** | v0.3.0 |
| **TSK-18** | Interactive Terminal UI Mode (`possum tui`) | UX | **Medium** | **Medium** | ✅ **Completed** | v0.5.0 |
| **TSK-19** | Declarative Custom Policy Engine (CEL / YAML) | Extensibility | **High** | **High** | ✅ **Completed** | v0.6.0 |

---

## 🚀 Tier 1: Quick Wins (High ROI, Low Complexity)

### TSK-01: Fix FinOps Result Modeling & Fields Population
* **Problem**: Across all 13 FinOps scanners (`ebs`, `ec2`, `eip`, `natgateway`, `rds`, `elb`, `lambda`, `eni`, `cloudformation`, `dynamodb`, `redshift`, `cloudfront`, `s3`, `cost_explorer`), constructed `ScanResult` structs omit `RuleID`, `Category`, `Status`, `Severity`, and `CostWasteMo`.
  * Active, healthy resources have `Status == ""` which causes `CalculateSummary()` to increment `FailCount++`.
  * Terminal table renders blank columns for `SEVERITY`, `CATEGORY`, and `RULE ID`.
  * Total waste calculation reports `$0.00/mo` because `CostWasteMo` is not transferred from `Metrics["EstimatedMonthlyCost"]`.
  * SARIF reports export healthy resources as security failures with blank rule IDs.
* **Affected Files**:
  * `pkg/scanner/aws/finops/*.go`
  * `pkg/output/formatter.go`
  * `pkg/scanner/aws/finops/*_test.go`
* **Implementation Steps**:
  1. Define canonical rule IDs for each FinOps check in `pkg/model/` or `pkg/scanner/aws/finops/rules.go` (e.g. `ebs_volume_unused_attached`, `ec2_elastic_ip_unassigned`, `natgateway_idle`, `rds_instance_idle`, `lambda_function_unused`).
  2. In each FinOps scanner, when `isOrphaned == true`:
     * Set `Status: model.StatusFail`
     * Set `Category: model.CategoryFinOps`
     * Set `Severity: model.SeverityMedium` (or `SeverityHigh` depending on risk)
     * Set `CostWasteMo: cost`
     * Set `RuleID: canonicalRuleID`
     * Set `Description` and `Remediation`
  3. When `isOrphaned == false`:
     * Set `Status: model.StatusPass`
     * Set `Category: model.CategoryFinOps`
     * Set `CostWasteMo: 0`
     * Set `Severity: model.SeverityInfo`
  4. Update unit tests to assert `Status`, `RuleID`, and `CostWasteMo`.
* **Definition of Done**: Running `possum scan aws` produces non-zero waste summaries for unattached assets, displays `FINOPS` in the category column, and correctly marks active resources as `PASS`.

---

### TSK-02: Wire RuleCatalog Metadata Enrichment into Engine
* **Problem**: The embedded catalog in `pkg/rules/embedded/index.json` has 655 rules with titles, risks, recommendations, and Terraform snippets, but it is never consulted during scan execution. SARIF reports fallback to `r.Title = r.RuleID`, and results lack remediation details.
* **Affected Files**:
  * `pkg/scanner/engine.go`
  * `pkg/rules/catalog.go`
  * `pkg/output/sarif.go`
* **Implementation Steps**:
  1. Add an enrichment method in `pkg/rules/catalog.go`:
     ```go
     func (c *RuleCatalog) EnrichResult(r *model.ScanResult)
     ```
  2. For any finding where `r.RuleID` exists in the catalog:
     * If `r.Title == ""`, set `r.Title = meta.CheckTitle`
     * If `r.Description == ""`, set `r.Description = meta.Description`
     * If `r.Remediation == ""`, set `r.Remediation = meta.Remediation.Recommendation.Text`
     * If `r.Category == "" && len(meta.Categories) > 0`, set `r.Category = meta.Categories[0]`
  3. In `Engine.Execute()`, iterate over `allResults` after goroutine synchronization and apply `catalog.EnrichResult(&r)`.
* **Definition of Done**: SARIF and JSON exports contain human-readable titles, detailed descriptions, and actionable remediation URLs for all standard rules.

---

### TSK-03: Surface & Aggregate Scanner Execution Errors
* **Problem**: In `Engine.Execute()`, individual scanner errors (such as AWS `AccessDeniedException` or context timeouts) are added to `scanErrors []error`, but `Execute` terminates with `return allResults, nil`. Users receive no indication that their credentials lacked permissions.
* **Affected Files**:
  * `pkg/scanner/engine.go`
  * `cmd/possum/scan_aws.go`
* **Implementation Steps**:
  1. Change `Engine.Execute` return signature or error handling to return an aggregated multi-error (using Go 1.20+ `errors.Join(scanErrors...)`) or retain partial results with an `ExecutionReport` struct:
     ```go
     type ScanReport struct {
         Results []model.ScanResult
         Errors  []error
     }
     ```
  2. In `cmd/possum/scan_aws.go`, if errors occurred:
     * If `--fail-on-error` is specified, abort and exit with code 2.
     * Print warning banners to `os.Stderr` displaying which services failed and why.
     * Include error counts in the summary banner.
* **Definition of Done**: If a user runs Possum with read-only permissions that deny CloudTrail or GuardDuty, the CLI explicitly reports warnings rather than falsely claiming 0 findings.

---

### TSK-04: Adopt OSI-Approved Open-Source License
* **Problem**: `LICENSE` currently enforces non-commercial usage ("MIT Non-Commercial License"). This blocks enterprise adoption, community packaging (Homebrew official core, Arch AUR, Debian), and corporate security evaluation.
* **Affected Files**:
  * `LICENSE`
  * `README.md`
* **Implementation Steps**:
  1. Replace `LICENSE` with standard **Apache License 2.0** (recommended for cloud security tools with patent protection) or standard **MIT License**.
  2. Update `README.md` badge and license section to reflect official OSI-approved open-source status.
  3. Clearly document the boundary: `possum-core` (CLI scanner engine) is 100% free open-source software; `possum-cloud` (hosted multi-account dashboards, SaaS attack graph, automated Terraform PR bots) is the commercial offering.
* **Definition of Done**: `LICENSE` matches standard Apache 2.0 / MIT text and passes automated OSS compliance scanners.

---

### TSK-05: Refactor CLI `os.Exit(1)` into Clean Cobra Error Flow
* **Problem**: In `cmd/possum/scan_aws.go`, `--fail-on` triggers a direct `os.Exit(1)` at line 190. This skips `defer` statements (like closing output files or flushing buffers) and terminates the entire process, making automated CLI unit testing impossible.
* **Affected Files**:
  * `cmd/possum/scan_aws.go`
  * `cmd/possum/main.go`
* **Implementation Steps**:
  1. Define a sentinel error in `pkg/model/`:
     ```go
     var ErrThresholdExceeded = errors.New("scan findings meet or exceed failure threshold")
     ```
  2. Return `ErrThresholdExceeded` from `runScanAWS` instead of calling `os.Exit(1)`.
  3. In `cmd/possum/main.go`, inspect returned error:
     ```go
     if errors.Is(err, model.ErrThresholdExceeded) {
         os.Exit(1)
     } else if err != nil {
         os.Exit(2)
     }
     ```
* **Definition of Done**: Unit tests can execute `rootCmd.Execute()` and test exit conditions without terminating the Go test runner process.

---

## ⚡ Tier 2: Strategic Core Milestones (High ROI, Medium Complexity)

### TSK-06: Implement `MetaScanner` for Targeted Pre-Filtering
* **Problem**: `MetaScanner` and `ScannerMeta` are defined in `pkg/scanner/scanner.go` but no scanner implements them. Specifying `--checks s3_bucket_level_public_access_block` executes all 49 scanners and filters results at the very end, resulting in dozens of unnecessary AWS API calls.
* **Affected Files**:
  * `pkg/scanner/scanner.go`
  * `pkg/scanner/aws/secaas/*.go`
  * `pkg/scanner/aws/finops/*.go`
  * `cmd/possum/scan_aws.go`
* **Implementation Steps**:
  1. Implement `Meta() ScannerMeta` on all scanners, listing `ID`, `Service`, `ExecutionCost`, and supported `CheckIDs`.
  2. In `cmd/possum/scan_aws.go`, before calling `engine.Execute`:
     * If `--services` or `--checks` are provided, filter the `targetScanners` list against `sc.Meta().Service` and `sc.Meta().CheckIDs`.
     * Only instantiate and pass relevant scanners into the worker pool.
* **Definition of Done**: Running `possum scan aws --checks s3_bucket_level_public_access_block` executes in <2 seconds and only invokes the S3 scanner.

---

### TSK-07: Multi-Region & Auto-Discovery Scanning (`--all-regions`)
* **Problem**: Possum only scans a single region per run. Multi-region architectures and regional sprawl are left uninspected unless the user writes wrapper shell scripts.
* **Affected Files**:
  * `cmd/possum/scan_aws.go`
  * `pkg/scanner/aws/factory.go`
  * `pkg/scanner/aws/client.go`
* **Implementation Steps**:
  1. Add CLI flags:
     * `--all-regions` (boolean): Auto-discover all enabled regions using `ec2:DescribeRegions`.
     * `--regions` (string): Comma-separated region list (`us-east-1,us-west-2,eu-west-1`).
  2. Refactor scan execution:
     * Execute `GetGlobalScanners(cfg)` **once** using the primary region.
     * Concurrently execute `GetRegionalScanners(regionalCfg)` across target regions with a region-worker pool.
  3. Aggregate results and display region breakdowns in terminal and JSON outputs.
* **Definition of Done**: `possum scan aws --all-regions` discovers all active AWS regions in the account and scans them concurrently.

---

### TSK-08: Rule Suppression & Ignore System (`.possumignore`)
* **Problem**: In real-world enterprise CI/CD, specific findings are approved exceptions or false positives. Without a suppression mechanism, `--fail-on` blocks deployments and frustrates developers.
* **Affected Files**:
  * `pkg/suppression/` (new package)
  * `pkg/scanner/engine.go`
  * `cmd/possum/scan_aws.go`
* **Implementation Steps**:
  1. Create `pkg/suppression` supporting `.possumignore` (or YAML format):
     ```yaml
     suppressions:
       - rule_id: s3_bucket_level_public_access_block
         resource_id: "my-static-assets-bucket"
         reason: "Public static website assets bucket"
         expires_at: "2026-12-31"
     ```
  2. Evaluate suppressions after scan execution:
     * Suppressed results have `Status = "SUPPRESSED"` and do not count toward `FailCount` or `--fail-on` threshold.
  3. Display suppressed finding count in table summary.
* **Definition of Done**: Suppressed rules do not trigger exit code 1 in CI/CD, and expired suppressions automatically fail once the date passes.

---

### TSK-09: Configuration File Support (`.possum.yaml`)
* **Problem**: Developers and CI pipelines have to maintain long flag chains (`--region us-east-1 --fail-on HIGH --format sarif --workers 15`).
* **Affected Files**:
  * `pkg/config/` (new package)
  * `cmd/possum/main.go`
  * `cmd/possum/scan_aws.go`
* **Implementation Steps**:
  1. Implement config file discovery checking (in order):
     1. `--config <path>`
     2. `./.possum.yaml`
     3. `~/.config/possum/config.yaml`
  2. Support configuration schema:
     ```yaml
     version: "1"
     scan:
       regions: ["us-east-1", "eu-west-1"]
       services: ["s3", "iam", "ec2"]
       fail_on: "HIGH"
       workers: 15
       timeout: "15m"
     output:
       format: "table"
     finops:
       ecr_retention_days: 90
     ```
  3. Merge file configuration with CLI flags (CLI flags take precedence).
* **Definition of Done**: Running `possum scan aws` without flags in a repo containing `.possum.yaml` automatically adopts the configured parameters.

---

### TSK-10: Compliance Framework Filtering (`--compliance`)
* **Problem**: Catalog checks contain compliance mappings (`cis_1.4_aws`, `cis_3.0_aws`, `pci_dss`, `soc2`, `iso27001_2022_aws`), but users cannot run compliance-focused audits.
* **Affected Files**:
  * `cmd/possum/scan_aws.go`
  * `pkg/rules/catalog.go`
* **Implementation Steps**:
  1. Add flag `--compliance` (e.g. `possum scan aws --compliance cis-3.0`).
  2. In `pkg/rules/catalog.go`, add `GetChecksByFramework(framework string) []string`.
  3. Map the returned check IDs into the scan filter options.
  4. In the output table, group or tag results by compliance section.
* **Definition of Done**: `possum scan aws --compliance cis-3.0` executes only the rules mapped to CIS Benchmark v3.0 and produces a compliance summary.

---

### TSK-11: Scan Diffing & PR Regression Detection (`possum diff`)
* **Problem**: Running a full scan in a Pull Request displays hundreds of pre-existing organizational issues rather than focusing on the pull request's delta.
* **Affected Files**:
  * `cmd/possum/diff.go` (new command)
  * `pkg/diff/` (new package)
* **Implementation Steps**:
  1. Implement `possum diff <baseline.json> <head.json>`:
     * Identify **New Findings** (introduced by current PR).
     * Identify **Resolved Findings** (fixed by current PR).
     * Calculate **Net Cost Waste Delta** ($ saved or added per month).
  2. Provide GitHub Markdown PR comment output format (`--format markdown-pr`).
* **Definition of Done**: Running `possum diff` produces a concise PR comment summarizing new security flaws and budget impact.

---

## 🔮 Tier 3: High-Value Differentiators & Big Bets

### TSK-12: Local Offline Attack Graph Visualization
* **Problem**: `ScanResult` generates `Nodes` and `Edges` for attack topology, but users can only visualize this by uploading their data to the commercial Possum Cloud.
* **Affected Files**:
  * `pkg/output/graph_mermaid.go` (new)
  * `pkg/output/graph_html.go` (new)
  * `cmd/possum/scan_aws.go`
* **Implementation Steps**:
  1. Implement `--format mermaid`: Renders attack path graphs as Mermaid syntax code blocks.
  2. Implement `--format html`: Generates a self-contained HTML file embedding Cytoscape.js or D3.js to visualize nodes (Internet, Public IPs, Roles, Buckets) and edges offline.
* **Definition of Done**: `possum scan aws --format html -o topology.html` produces an interactive visual graph viewable in any local browser without internet access.

---

### TSK-13: Multi-Account & AWS Organizations Scanning
* **Problem**: Scanning multiple accounts requires manual scripting outside the tool.
* **Affected Files**:
  * `cmd/possum/scan_aws.go`
  * `pkg/scanner/aws/org.go` (new)
* **Implementation Steps**:
  1. Add `--organization` flag.
  2. Use AWS Organizations API (`organizations:ListAccounts`) from management/audit account.
  3. Assume a cross-account role (e.g., `OrganizationAccountAccessRole`) in each active account.
  4. Execute scans concurrently per account and output an aggregated multi-account report.
* **Definition of Done**: Running `possum scan aws --organization --role OrganizationAccountAccessRole` audits all active member accounts in the organization.

---

### TSK-14: Shift-Left Infrastructure-as-Code Scanning (`possum scan iac`)
* **Problem**: Possum only scans live cloud environments. Catching security flaws and cost waste during PR review *before* deployment requires IaC parsing.
* **Affected Files**:
  * `cmd/possum/scan_iac.go` (new)
  * `pkg/scanner/iac/` (new package)
* **Implementation Steps**:
  1. Integrate HCL parser (or evaluate Terraform JSON plan files generated via `terraform show -json`).
  2. Evaluate existing security checks (public buckets, unencrypted volumes, open security groups) against the plan graph.
  3. Calculate projected monthly cost waste (oversized instances, unattached disks) before `terraform apply`.
* **Definition of Done**: `possum scan iac ./terraform/` or `possum scan iac tfplan.json` identifies misconfigurations and costs prior to deployment.

---

## 🛠️ Tier 4 & 5: Ergonomics, Refactoring & Long-Term Bets

### TSK-15: Standardize Resource IDs on Canonical AWS ARNs
* **Problem**: Resources are currently represented by short names (e.g. `bucket-name`, `vol-0123`, `RootAccount`), leading to potential ID collisions when aggregating multi-region/multi-account scans.
* **Affected Files**:
  * `pkg/scanner/aws/secaas/*.go`
  * `pkg/scanner/aws/finops/*.go`
* **Implementation Steps**:
  1. Ensure every scanner constructs canonical ARN format: `arn:aws:<service>:<region>:<account-id>:<resource-type>/<resource-id>`.
  2. Retain short display names in `Metrics["DisplayName"]`.
* **Definition of Done**: All emitted findings and graph nodes have unique ARN identifiers.

---

### TSK-16: Automated Remediation Script Generator (`possum remediate`)
* **Problem**: Remediating findings requires copying AWS CLI snippets one-by-one from rule descriptions.
* **Affected Files**:
  * `cmd/possum/remediate.go` (new)
  * `pkg/remediation/` (new package)
* **Implementation Steps**:
  1. Add command `possum remediate --dry-run` or `--export script.sh`.
  2. Extract `Remediation.Code.CLI` from findings and generate a safe bash script with variable substitution and confirmation prompts.
* **Definition of Done**: `possum remediate --export fix.sh` creates an executable shell script to patch detected vulnerabilities.

---

### TSK-17: Dead Code & Unused Abstractions Cleanup
* **Problem**: Unused types (`ScanModeQuick`, `ScanModeDeep`, `ScanTarget` in `pkg/model/target.go`, `ExecutionCost` in `pkg/scanner/scanner.go`) exist without implementation.
* **Affected Files**:
  * `pkg/model/target.go`
  * `pkg/scanner/scanner.go`
* **Implementation Steps**:
  1. Either hook `ScanMode` into CLI (`--mode quick` runs CRITICAL/HIGH, `--mode standard` runs all) or remove unused enum types.
  2. Clean up dead references to keep the codebase lean.
* **Definition of Done**: No orphaned types or unreferenced constants exist in `pkg/model` or `pkg/scanner`.

---

### TSK-18: Interactive Terminal UI Mode (`possum tui`)
* **Problem**: Scrolling through terminal tables with 50+ findings is cumbersome.
* **Affected Files**:
  * `cmd/possum/tui.go` (new)
  * `pkg/tui/` (new package)
* **Implementation Steps**:
  1. Build an interactive TUI using [Bubbletea](https://github.com/charmbracelet/bubbletea).
  2. Allow arrow-key navigation through findings, filtering by severity/service, and pressing `Enter` to view full remediation instructions and Terraform snippets.
* **Definition of Done**: `possum tui` opens an interactive console browser for scan results.

---

### TSK-19: Declarative Custom Policy Engine (CEL / YAML)
* **Problem**: Adding new checks currently requires writing compiled Go code and mocking AWS SDK interfaces.
* **Affected Files**:
  * `pkg/rules/custom/` (new package)
* **Implementation Steps**:
  1. Embed Google's Common Expression Language (CEL) runtime.
  2. Allow users to define custom checks in `.possum/rules/*.yaml`:
     ```yaml
     id: custom_s3_retention_tag
     service: s3
     severity: HIGH
     condition: "resource.tags['Retention'] in ['30d', '90d', '365d']"
     message: "S3 bucket must have a compliant Retention tag"
     ```
* **Definition of Done**: Custom YAML checks are automatically loaded and evaluated alongside built-in scanners.
