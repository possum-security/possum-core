# Possum Core

> **Developer-First Cloud Security & FinOps Scanner**  
> Unifying Cloud Security Posture and Cost Optimization.

[![CI](https://github.com/possum-sec/possum/actions/workflows/ci.yml/badge.svg)](https://github.com/possum-sec/possum/actions)
[![License](https://img.shields.io/badge/License-Non--Commercial-blue.svg)](LICENSE)

Possum is a zero-dependency, single-binary CLI engine designed to detect security misconfigurations and cloud financial waste in CI/CD and developer environments.

---

## ⚡ Quick Start

### Installation

```bash
# Via Homebrew
brew install possum-sec/tap/possum

# Via Go install
go install github.com/possum-sec/possum/cmd/possum@latest

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

Possum is licensed under the [Non-Commercial License](LICENSE) (free for personal, educational, and research use; commercial use prohibited without permission).
