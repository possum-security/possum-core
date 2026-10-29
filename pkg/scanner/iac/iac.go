package iac

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amirmahdy/possum-core/pkg/model"
)

// ResourceChange represents a planned resource modification in a Terraform JSON plan.
type ResourceChange struct {
	Address      string       `json:"address"`
	Module       string       `json:"module_address,omitempty"`
	Mode         string       `json:"mode"`
	Type         string       `json:"type"`
	Name         string       `json:"name"`
	ProviderName string       `json:"provider_name"`
	Change       ChangeDetail `json:"change"`
}

// ChangeDetail represents actions and before/after states.
type ChangeDetail struct {
	Actions []string               `json:"actions"`
	Before  map[string]interface{} `json:"before,omitempty"`
	After   map[string]interface{} `json:"after,omitempty"`
}

// TerraformPlan represents top-level structure of `terraform show -json`.
type TerraformPlan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

// Scanner scans Terraform configurations and Terraform JSON plan files.
type Scanner struct{}

// NewScanner creates a new IaC scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

// ScanPath inspects a file or directory path (handling both .json plans and .tf directories).
func (s *Scanner) ScanPath(path string) ([]model.ScanResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect path %s: %w", path, err)
	}

	if !fi.IsDir() {
		// Single file: check if it's JSON plan or .tf file
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return s.ScanPlan(f)
		}
		return s.ScanTFFile(path)
	}

	// Directory: scan all .tf files
	return s.ScanTFDirectory(path)
}

// ScanPlan scans a Terraform JSON plan from an io.Reader.
func (s *Scanner) ScanPlan(r io.Reader) ([]model.ScanResult, error) {
	var plan TerraformPlan
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read plan data: %w", err)
	}

	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal terraform plan JSON: %w", err)
	}

	var results []model.ScanResult

	// Map to correlate related resources (like s3 bucket and its public access block)
	pabBuckets := make(map[string]bool)
	encBuckets := make(map[string]bool)

	for _, rc := range plan.ResourceChanges {
		if rc.Change.After == nil {
			continue
		}
		switch rc.Type {
		case "aws_s3_bucket_public_access_block":
			bucket := fmt.Sprintf("%v", rc.Change.After["bucket"])
			pabBuckets[bucket] = true
		case "aws_s3_bucket_server_side_encryption_configuration":
			bucket := fmt.Sprintf("%v", rc.Change.After["bucket"])
			encBuckets[bucket] = true
		}
	}

	for _, rc := range plan.ResourceChanges {
		// Ignore deleted resources
		if len(rc.Change.Actions) == 1 && rc.Change.Actions[0] == "delete" {
			continue
		}
		props := rc.Change.After
		if props == nil {
			props = rc.Change.Before
		}
		if props == nil {
			continue
		}

		findings := evaluateResourceFindings(rc.Type, rc.Address, props, pabBuckets, encBuckets)
		results = append(results, findings...)
	}

	return results, nil
}

// ScanTFDirectory scans all .tf files in a directory.
func (s *Scanner) ScanTFDirectory(dir string) ([]model.ScanResult, error) {
	var allResults []model.ScanResult
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".tf" {
			findings, err := s.ScanTFFile(path)
			if err == nil {
				allResults = append(allResults, findings...)
			}
		}
		return nil
	})
	return allResults, err
}

// ScanTFFile parses a single .tf file for common misconfigurations.
func (s *Scanner) ScanTFFile(path string) ([]model.ScanResult, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var results []model.ScanResult
	lines := strings.Split(string(content), "\n")
	currType := ""
	currName := ""
	blockLines := make([]string, 0)
	inBlock := false
	braceCount := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "resource ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				currType = strings.Trim(parts[1], "\"")
				currName = strings.Trim(parts[2], "\"")
				inBlock = true
				braceCount = 0
				blockLines = nil
			}
		}

		if inBlock {
			blockLines = append(blockLines, line)
			braceCount += strings.Count(line, "{")
			braceCount -= strings.Count(line, "}")
			if braceCount <= 0 && len(blockLines) > 1 {
				// Block finished
				address := fmt.Sprintf("%s.%s", currType, currName)
				findings := evaluateTFBlock(currType, address, path, strings.Join(blockLines, "\n"))
				results = append(results, findings...)
				inBlock = false
				currType = ""
				currName = ""
			}
		}
	}

	return results, nil
}

func evaluateResourceFindings(resType, address string, props map[string]interface{}, pabBuckets, encBuckets map[string]bool) []model.ScanResult {
	var findings []model.ScanResult

	switch resType {
	case "aws_s3_bucket":
		bucketName := address
		if b, ok := props["bucket"].(string); ok && b != "" {
			bucketName = b
		}

		// Check public access block
		if !pabBuckets[bucketName] && !pabBuckets[address] {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: "aws_s3_bucket",
				RuleID:       "s3_bucket_level_public_access_block",
				Title:        "Ensure S3 Bucket has Public Access Block Configured",
				Description:  fmt.Sprintf("S3 bucket %s does not define an aws_s3_bucket_public_access_block resource.", address),
				Remediation:  "Define an aws_s3_bucket_public_access_block resource with block_public_acls = true",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_security_group", "aws_security_group_rule":
		// Check for 0.0.0.0/0 ingress
		hasOpenIngress := false
		if cidrBlocks, ok := props["cidr_blocks"].([]interface{}); ok {
			for _, cidr := range cidrBlocks {
				if fmt.Sprintf("%v", cidr) == "0.0.0.0/0" {
					hasOpenIngress = true
					break
				}
			}
		}
		if ingressList, ok := props["ingress"].([]interface{}); ok {
			for _, ing := range ingressList {
				if ingMap, ok := ing.(map[string]interface{}); ok {
					if cBlocks, ok := ingMap["cidr_blocks"].([]interface{}); ok {
						for _, cidr := range cBlocks {
							if fmt.Sprintf("%v", cidr) == "0.0.0.0/0" {
								hasOpenIngress = true
								break
							}
						}
					}
				}
			}
		}

		if hasOpenIngress {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "Security Group has Unrestricted Ingress (0.0.0.0/0)",
				Description:  fmt.Sprintf("Resource %s opens inbound access to 0.0.0.0/0", address),
				Remediation:  "Restrict inbound CIDR ranges to authorized corporate subnets or VPC CIDR",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_ebs_volume":
		encrypted, _ := props["encrypted"].(bool)
		sizeGB, _ := props["size"].(float64)
		if sizeGB == 0 {
			if sInt, ok := props["size"].(int); ok {
				sizeGB = float64(sInt)
			}
		}
		costWaste := sizeGB * 0.08 // standard gp3/gp2 estimate

		if !encrypted {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: "aws_ebs_volume",
				RuleID:       "ebs_volume_encryption_enabled",
				Title:        "Ensure EBS Volume Encryption is Enabled",
				Description:  fmt.Sprintf("EBS volume %s is planned without encryption.", address),
				Remediation:  "Set encrypted = true on aws_ebs_volume resource",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				CostWasteMo:  costWaste,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_instance":
		instanceType, _ := props["instance_type"].(string)
		monthlyCost := estimateEC2Monthly(instanceType)
		// FinOps check: Alert on high-cost instances planned without tags
		tags, _ := props["tags"].(map[string]interface{})
		if len(tags) == 0 && monthlyCost > 100 {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: "aws_instance",
				RuleID:       "ec2_instance_untagged_cost",
				Title:        "High-Cost EC2 Instance Planned Without Cost Allocation Tags",
				Description:  fmt.Sprintf("EC2 instance %s (%s, est. $%.2f/mo) has no cost allocation tags.", address, instanceType, monthlyCost),
				Remediation:  "Add Environment, Owner, and CostCenter tags to the aws_instance resource",
				Severity:     model.SeverityMedium,
				Status:       model.StatusFail,
				Category:     model.CategoryFinOps,
				CostWasteMo:  monthlyCost,
				EvaluatedAt:  time.Now(),
			})
		}
	}

	return findings
}

func evaluateTFBlock(resType, address, path, blockText string) []model.ScanResult {
	var findings []model.ScanResult

	// Normalize spaces for robust pattern matching
	normText := strings.ReplaceAll(blockText, " ", "")

	switch resType {
	case "aws_s3_bucket":
		if strings.Contains(normText, "acl=\"public-read\"") || strings.Contains(normText, "acl=\"public-read-write\"") {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "s3_bucket_level_public_access_block",
				Title:        "S3 Bucket Configured with Public ACL",
				Description:  fmt.Sprintf("Bucket at %s has public read or write ACL.", path),
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_security_group":
		if strings.Contains(normText, "\"0.0.0.0/0\"") && (strings.Contains(normText, "from_port=22") || strings.Contains(normText, "from_port=0")) {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "Security Group Exposes Inbound Port 22 or All Traffic to 0.0.0.0/0",
				Description:  fmt.Sprintf("Security group in %s allows world ingress.", path),
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_ebs_volume":
		if strings.Contains(normText, "encrypted=false") || !strings.Contains(normText, "encrypted=true") {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ebs_volume_encryption_enabled",
				Title:        "EBS Volume Missing Default Encryption",
				Description:  fmt.Sprintf("EBS volume defined in %s does not enable encryption.", path),
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}
	}

	return findings
}

func estimateEC2Monthly(instanceType string) float64 {
	// Standard on-demand monthly cost estimations (730 hours/mo)
	switch strings.ToLower(instanceType) {
	case "t3.micro", "t4g.micro":
		return 7.50
	case "t3.small", "t4g.small":
		return 15.00
	case "t3.medium", "t4g.medium":
		return 30.00
	case "m5.large", "m6i.large":
		return 70.00
	case "m5.xlarge", "m6i.xlarge":
		return 140.00
	case "c5.2xlarge", "c6i.2xlarge":
		return 248.00
	case "p3.2xlarge", "g4dn.xlarge":
		return 384.00
	default:
		if strings.Contains(instanceType, "xlarge") {
			return 150.00
		}
		return 30.00
	}
}
