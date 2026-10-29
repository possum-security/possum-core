# Possum Core

> **Developer-First Cloud Security & FinOps Scanner**  
> Unifying Cloud Security Posture and Cost Optimization.

[![CI](https://github.com/amirmahdy/possum-core/actions/workflows/ci.yml/badge.svg)](https://github.com/amirmahdy/possum-core/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Open Source](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://opensource.org/licenses/Apache-2.0)

Possum is a zero-dependency, single-binary CLI engine designed to detect security misconfigurations and cloud financial waste in CI/CD and developer environments.

---

## ⚡ Quick Start

### Installation

```bash
# Via Homebrew
brew install possum-sec/tap/possum

# Via Go install
go install github.com/amirmahdy/possum-core/cmd/possum@latest

# Direct Download
curl -sSfL https://raw.githubusercontent.com/possum-sec/possum/main/install.sh | sh
```

### Basic Usage

```bash
# Scan AWS infrastructure in us-east-1
possum scan aws --region us-east-1

# Filter by services and fail on HIGH/CRITICAL findings in CI/CD
possum scan aws --region us-east-1 --services s3,iam,ec2 --fail-on HIGH

# Output SARIF format for GitHub Security Tab
possum scan aws --region us-east-1 --format sarif -o results.sarif

# Explore embedded rules catalog
possum rules list --service s3
possum rules get s3_bucket_level_public_access_block
```

---

## 📊 Output Formats

Possum supports multiple output formatters:
* `table` (Default): ANSI-colored terminal output with FinSecOps summaries.
* `json`: Full structured JSON for automation.
* `sarif`: OASIS SARIF v2.1.0 standard for GitHub Security / CodeQL integrations.
* `junit`: XML format for CI/CD test reports (Jenkins, GitLab CI, Azure DevOps).

---

## ☁️ Possum Cloud (SecaaS Platform)

Want multi-account topology, attack graph visualization, financial blast radius calculations, and automated Terraform pull requests?

```bash
possum scan aws --cloud --api-key <YOUR_POSSUM_API_KEY> --account-id <ACCOUNT_ID>
```

Learn more at [https://possum.io](https://possum.io).

---

## 📄 License

Possum Core is free and open-source software licensed under the [Apache License 2.0](LICENSE). You are free to run, study, modify, and distribute this software for personal, academic, or commercial purposes.

The hosted multi-account management dashboard, centralized security team attack graphs, and automated Terraform pull request bots are offered via Possum Cloud (commercial).
