package remediation

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
)

// ScriptOptions configures remediation script generation.
type ScriptOptions struct {
	DryRun       bool
	ConfirmEach  bool
	TargetRules  []string
	AccountID    string
	Region       string
	CustomBanner string
}

// Action represents an executable remediation step for a specific finding.
type Action struct {
	RuleID       string
	ResourceID   string
	ResourceType string
	Region       string
	Description  string
	CLICommand   string
	Severity     model.Severity
	Impact       string
}

// Generator generates safe bash remediation scripts.
type Generator struct{}

// NewGenerator creates a new remediation script generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// ExtractActions inspects scan findings and extracts corresponding remediation actions.
func (g *Generator) ExtractActions(results []model.ScanResult) []Action {
	var actions []Action

	for _, r := range results {
		// Only failed findings require remediation
		if r.Status != model.StatusFail {
			continue
		}

		cmd := DeriveCLICommand(r)
		if cmd == "" {
			continue
		}

		actions = append(actions, Action{
			RuleID:       r.RuleID,
			ResourceID:   r.ResourceID,
			ResourceType: r.ResourceType,
			Region:       r.Region,
			Description:  r.Title,
			CLICommand:   cmd,
			Severity:     r.Severity,
		})
	}

	return actions
}

// shellQuote wraps s in single quotes and escapes any embedded single quotes
// as '\'' so bash treats the entire value as a literal string without expansion.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// sanitizeComment strips newlines from a string before embedding it in a bash comment.
func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ensureCommentLines guarantees every line in a comment block starts with '#'.
func ensureCommentLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "#") {
			lines[i] = "# " + trimmed
		}
	}
	return strings.Join(lines, "\n")
}

// DeriveCLICommand derives a concrete AWS CLI command for a given finding.
func DeriveCLICommand(r model.ScanResult) string {
	if strings.TrimSpace(r.ResourceID) == "" || strings.ContainsRune(r.ResourceID, '\x00') || strings.ContainsRune(r.Region, '\x00') {
		return ""
	}

	resID := shellQuote(r.ResourceID)
	regionFlag := ""
	if r.Region != "" && r.Region != "global" {
		regionFlag = fmt.Sprintf(" --region %s", shellQuote(r.Region))
	}

	switch r.RuleID {
	// S3 public access
	case "s3_bucket_level_public_access_block":
		return fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'%s", resID, regionFlag)

	// S3 default encryption
	case "s3_bucket_default_encryption":
		return fmt.Sprintf("aws s3api put-bucket-encryption --bucket %s --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'%s", resID, regionFlag)

	// EBS unused volume cleanup
	case "ebs_volume_unused_attached":
		return fmt.Sprintf("aws ec2 delete-volume --volume-id %s%s", resID, regionFlag)

	// EIP unassigned release
	case "ec2_elastic_ip_unassigned":
		if strings.HasPrefix(r.ResourceID, "eipalloc-") {
			return fmt.Sprintf("aws ec2 release-address --allocation-id %s%s", resID, regionFlag)
		}
		return fmt.Sprintf("aws ec2 release-address --public-ip %s%s", resID, regionFlag)

	// CloudTrail enable
	case "cloudtrail_multi_region_logging":
		return fmt.Sprintf("aws cloudtrail start-logging --name %s%s", resID, regionFlag)

	// Security group revoke open 0.0.0.0/0
	case "ec2_security_group_open_to_world":
		return fmt.Sprintf("# Review and restrict open inbound CIDRs for security group %s:\n# aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port 22 --cidr '0.0.0.0/0'%s", sanitizeComment(r.ResourceID), sanitizeComment(resID), sanitizeComment(regionFlag))

	default:
		return ""
	}
}

// GenerateScript writes a complete, executable bash remediation script to w.
func (g *Generator) GenerateScript(w io.Writer, actions []Action, opts ScriptOptions) error {
	var sb strings.Builder

	sb.WriteString("#!/usr/bin/env bash\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString("# Possum Automated Cloud Remediation Script\n")
	sb.WriteString(fmt.Sprintf("# Generated at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	if opts.AccountID != "" {
		sb.WriteString(fmt.Sprintf("# Target AWS Account: %s\n", sanitizeComment(opts.AccountID)))
	}
	sb.WriteString("# =============================================================================\n")
	sb.WriteString("set -euo pipefail\n\n")

	sb.WriteString("# Verify AWS CLI is installed\n")
	sb.WriteString("if ! command -v aws >/dev/null 2>&1; then\n")
	sb.WriteString("    echo \"❌ Error: aws CLI is not installed or not in PATH.\" >&2\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("fi\n\n")

	if opts.DryRun {
		sb.WriteString("echo \"🔍 RUNNING IN DRY-RUN MODE: No changes will be applied.\"\n")
		sb.WriteString("DRY_RUN=true\n\n")
	} else {
		sb.WriteString("DRY_RUN=false\n\n")
	}

	sb.WriteString("run_cmd() {\n")
	sb.WriteString("    local desc=\"$1\"\n")
	sb.WriteString("    shift\n")
	sb.WriteString("    echo \"------------------------------------------------------------------\"\n")
	sb.WriteString("    echo \"👉 Action: $desc\"\n")
	sb.WriteString("    echo \"💻 Command: $*\"\n")
	sb.WriteString("    if [ \"$DRY_RUN\" = \"true\" ]; then\n")
	sb.WriteString("        echo \"[DRY RUN] Skipped execution.\"\n")
	sb.WriteString("        return 0\n")
	sb.WriteString("    fi\n")

	if opts.ConfirmEach {
		sb.WriteString("    read -r -p \"Apply this remediation? [y/N] \" response\n")
		sb.WriteString("    case \"$response\" in\n")
		sb.WriteString("        [yY][eE][sS]|[yY])\n")
		sb.WriteString("            \"$@\"\n")
		sb.WriteString("            echo \"✅ Applied.\"\n")
		sb.WriteString("            ;;\n")
		sb.WriteString("        *)\n")
		sb.WriteString("            echo \"⏩ Skipped by user.\"\n")
		sb.WriteString("            ;;\n")
		sb.WriteString("    esac\n")
	} else {
		sb.WriteString("    \"$@\"\n")
		sb.WriteString("    echo \"✅ Applied.\"\n")
	}
	sb.WriteString("}\n\n")

	sb.WriteString(fmt.Sprintf("echo \"🚀 Starting remediation for %d identified issues...\"\n\n", len(actions)))

	for i, act := range actions {
		cmd := DeriveCLICommand(model.ScanResult{
			RuleID:     act.RuleID,
			ResourceID: act.ResourceID,
			Region:     act.Region,
		})
		if cmd == "" {
			cmd = act.CLICommand
		}
		if cmd == "" {
			continue
		}

		desc := fmt.Sprintf("[%d/%d] %s (%s)", i+1, len(actions), act.RuleID, act.ResourceID)
		if strings.HasPrefix(cmd, "#") {
			sb.WriteString(fmt.Sprintf("# Manual review required for %s:\n", sanitizeComment(act.ResourceID)))
			sb.WriteString(fmt.Sprintf("%s\n\n", ensureCommentLines(cmd)))
		} else {
			sb.WriteString(fmt.Sprintf("run_cmd %s %s\n\n", shellQuote(desc), cmd))
		}
	}

	sb.WriteString("echo \"🎉 Remediation completed successfully.\"\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
