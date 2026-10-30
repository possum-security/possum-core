# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of Possum Core seriously. Please **do not** report security vulnerabilities through public GitHub issues, discussions, or pull requests.

### How to Report
- **Email**: Send a detailed report to `security@possum.io`.
- **GitHub Security Advisories**: Report privately via [GitHub Private Vulnerability Reporting](https://github.com/possum-security/possum-core/security/advisories/new).

Please include:
1. Type of issue (e.g., credential handling, command injection in remediation generator, IaC parser DoS, SSRF).
2. Affected package or file paths (e.g., `pkg/remediation/remediation.go`).
3. Step-by-step reproduction instructions or proof-of-concept input.
4. Impact assessment.

### Response Timeline
- **Acknowledgment**: Within 48 hours of submission.
- **Triage & Assessment**: Within 5 business days.
- **Remediation & Disclosure**: Coordinated fix and CVE/advisory publication within 30 days for High/Critical issues.

## Security Design Principles
- **Read-Only AWS Inspection**: `possum scan aws` uses strictly read-only `Describe*`, `List*`, and `Get*` AWS API calls (see [`docs/iam-policy.json`](docs/iam-policy.json)).
- **Safe Remediation Generation**: `possum remediate` defaults to `--dry-run=true` and `--confirm=true` and quotes shell arguments to prevent command injection.
- **Credential Hygiene**: Cloud credentials stored by `possum cloud login` are written with `0600` file permissions and `0700` directory permissions.
