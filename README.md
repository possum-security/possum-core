# Possum Core

> **Developer-First Cloud Security & FinOps Scanner**  
> Unifying Cloud Security Posture and Cost Optimization.

[![CI](https://github.com/possum-security/possum-core/actions/workflows/ci.yml/badge.svg)](https://github.com/possum-security/possum-core/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://opensource.org/licenses/Apache-2.0)

Possum is a single static binary, agentless CLI engine designed to detect cloud security misconfigurations, attack paths, and cloud financial waste across live AWS environments and Infrastructure-as-Code (Terraform, CloudFormation, and Kubernetes).

---

## ⚡ Quick Start

### Installation

```bash
# Via Homebrew
brew install possum-security/tap/possum

# Via Go install (requires Go 1.26+)
go install github.com/possum-security/possum-core/cmd/possum@latest

# Direct Download (Linux / macOS amd64 & arm64 with SHA-256 verification)
curl -sSfL https://raw.githubusercontent.com/possum-security/possum-core/main/install.sh | sh
```

### Basic Usage

```bash
# Scan AWS infrastructure in us-east-1
possum scan aws --region us-east-1

# Scan all enabled AWS regions or an entire AWS Organization
possum scan aws --all-regions
possum scan aws --organization --all-regions

# Filter by services or compliance framework and fail on HIGH/CRITICAL findings in CI/CD
possum scan aws --region us-east-1 --services s3,iam,ec2 --compliance cis-3.0 --fail-on HIGH

# Shift-left IaC scanning (Terraform .tf / tfplan.json, CloudFormation, Kubernetes manifests)
possum scan iac ./infra --fail-on HIGH

# Output SARIF format for GitHub Security Tab
possum scan aws --region us-east-1 --format sarif -o results.sarif

# Compare baseline vs PR scan reports for regressions and net waste delta
possum diff baseline.json head.json --format markdown-pr

# Generate safe, interactive remediation script from findings
possum remediate results.json --dry-run --confirm -e fix.sh

# Launch interactive terminal UI explorer
possum tui results.json

# Explore the 655-rule embedded security and FinOps catalog
possum rules list --service s3
possum rules get s3_bucket_level_public_access_block
```

---

## 📊 Output Formats

Possum supports multiple output formatters via `--format` / `-f`:
* `table` (Default): ANSI-colored terminal output with FinSecOps summaries.
* `json`: Full structured JSON report for automation and `possum diff` / `possum tui`.
* `sarif`: OASIS SARIF v2.1.0 standard for GitHub Security / CodeQL integrations.
* `junit`: JUnit XML format for CI/CD test reports (Jenkins, GitLab CI, Azure DevOps).
* `csv`: Comma-Separated Values export for spreadsheets and BI tools.
* `mermaid`: Mermaid.js attack path and infrastructure relationship graph.
* `html`: Standalone interactive HTML report with visual attack graphs and cost breakdowns.

---

## 📚 Documentation & Configuration

* **Architecture Overview**: [`docs/architecture.md`](docs/architecture.md)
* **Least-Privilege IAM Policy**: [`docs/iam-policy.json`](docs/iam-policy.json)
* **Example `.possum.yaml` Configuration**: [`docs/examples/.possum.yaml`](docs/examples/.possum.yaml)
* **Example `.possumignore` Suppressions**: [`docs/examples/.possumignore`](docs/examples/.possumignore)
* **Example Custom Policy Rule**: [`docs/examples/custom-rules.yaml`](docs/examples/custom-rules.yaml)

---

## ☁️ Possum Cloud (SecaaS Platform)

Want multi-account topology, attack graph visualization, financial blast radius calculations, and automated Terraform pull requests?

```bash
possum cloud login
possum scan aws --cloud --account-id <ACCOUNT_ID>
```

Learn more at [https://possum.io](https://possum.io).

---

## 📄 License

Possum Core is free and open-source software licensed under the [Apache License 2.0](LICENSE) (see [NOTICE](NOTICE) for third-party attributions). You are free to run, study, modify, and distribute this software for personal, academic, or commercial purposes.
