package iac

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
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

// PlannedValues represents the planned_values section of a Terraform JSON plan.
type PlannedValues struct {
	RootModule PlannedModule `json:"root_module"`
}

// PlannedModule represents a Terraform module in planned_values.
type PlannedModule struct {
	Resources    []PlannedResource `json:"resources"`
	ChildModules []PlannedModule   `json:"child_modules"`
}

// PlannedResource represents a planned resource in planned_values.root_module.
type PlannedResource struct {
	Address string                 `json:"address"`
	Mode    string                 `json:"mode"`
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Values  map[string]interface{} `json:"values"`
}

// TerraformPlan represents top-level structure of `terraform show -json` or `.tf.json`.
type TerraformPlan struct {
	FormatVersion    string                 `json:"format_version"`
	TerraformVersion string                 `json:"terraform_version"`
	ResourceChanges  []ResourceChange       `json:"resource_changes"`
	PlannedValues    *PlannedValues         `json:"planned_values,omitempty"`
	Resource         map[string]interface{} `json:"resource,omitempty"`
}

// Scanner scans Terraform, CloudFormation, and Kubernetes IaC files.
type Scanner struct{}

// NewScanner creates a new IaC scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

// ScanPath inspects a file or directory path (handling Terraform, CloudFormation, and Kubernetes manifests).
func (s *Scanner) ScanPath(path string) ([]model.ScanResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect path %s: %w", path, err)
	}

	if !fi.IsDir() {
		return s.scanSingleFile(path)
	}

	return s.ScanTFDirectory(path)
}

func (s *Scanner) scanSingleFile(path string) ([]model.ScanResult, error) {
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(lower))

	switch ext {
	case ".tf":
		return s.ScanTFFile(path)
	case ".json":
		return s.scanJSONFile(path)
	case ".yaml", ".yml":
		return s.scanYAMLFile(path)
	default:
		if strings.HasSuffix(lower, ".tf.json") {
			return s.scanJSONFile(path)
		}
		return s.ScanTFFile(path)
	}
}

func (s *Scanner) scanJSONFile(path string) ([]model.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawDoc map[string]interface{}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, fmt.Errorf("failed to parse JSON file %s: %w", path, err)
	}

	if isCloudFormationMap(rawDoc) {
		return evaluateCloudFormationTemplate(rawDoc, path, string(data), nil), nil
	}

	if isKubernetesMap(rawDoc) {
		return evaluateKubernetesManifest(rawDoc, path, string(data), nil), nil
	}

	return s.scanPlanData(data, path)
}

func (s *Scanner) scanYAMLFile(path string) ([]model.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfnResults, isCFN, err := scanCloudFormationYAML(data, path)
	if err == nil && isCFN {
		return cfnResults, nil
	}

	k8sResults, isK8s, err := scanKubernetesYAML(data, path)
	if err == nil && isK8s {
		return k8sResults, nil
	}

	return nil, nil
}

// ScanPlan scans a Terraform JSON plan from an io.Reader.
func (s *Scanner) ScanPlan(r io.Reader) ([]model.ScanResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read plan data: %w", err)
	}
	return s.scanPlanData(data, "tfplan.json")
}

func (s *Scanner) scanPlanData(data []byte, filePath string) ([]model.ScanResult, error) {
	var rawDoc map[string]interface{}
	if err := json.Unmarshal(data, &rawDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal terraform plan JSON: %w", err)
	}

	// If someone passed a CloudFormation or Kubernetes JSON to ScanPlan, handle it cleanly.
	if isCloudFormationMap(rawDoc) {
		return evaluateCloudFormationTemplate(rawDoc, filePath, string(data), nil), nil
	}
	if isKubernetesMap(rawDoc) {
		return evaluateKubernetesManifest(rawDoc, filePath, string(data), nil), nil
	}

	var plan TerraformPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("failed to unmarshal terraform plan JSON: %w", err)
	}

	contentStr := string(data)
	var results []model.ScanResult

	type evalItem struct {
		resType string
		address string
		name    string
		props   map[string]interface{}
	}
	var items []evalItem
	seenAddresses := make(map[string]bool)

	for _, rc := range plan.ResourceChanges {
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
		addr := rc.Address
		if addr == "" {
			addr = fmt.Sprintf("%s.%s", rc.Type, rc.Name)
		}
		seenAddresses[addr] = true
		items = append(items, evalItem{
			resType: rc.Type,
			address: addr,
			name:    rc.Name,
			props:   props,
		})
	}

	if plan.PlannedValues != nil {
		var collectModule func(mod PlannedModule)
		collectModule = func(mod PlannedModule) {
			for _, pr := range mod.Resources {
				if pr.Values == nil {
					continue
				}
				addr := pr.Address
				if addr == "" {
					addr = fmt.Sprintf("%s.%s", pr.Type, pr.Name)
				}
				if seenAddresses[addr] {
					continue
				}
				seenAddresses[addr] = true
				items = append(items, evalItem{
					resType: pr.Type,
					address: addr,
					name:    pr.Name,
					props:   pr.Values,
				})
			}
			for _, child := range mod.ChildModules {
				collectModule(child)
			}
		}
		collectModule(plan.PlannedValues.RootModule)
	}

	// Support .tf.json configuration files: {"resource": {"aws_s3_bucket": {"my_bucket": {...}}}}
	if plan.Resource != nil {
		for resType, byNameRaw := range plan.Resource {
			byName, ok := byNameRaw.(map[string]interface{})
			if !ok {
				continue
			}
			for resName, propsRaw := range byName {
				props, ok := propsRaw.(map[string]interface{})
				if !ok {
					continue
				}
				addr := fmt.Sprintf("%s.%s", resType, resName)
				if seenAddresses[addr] {
					continue
				}
				seenAddresses[addr] = true
				items = append(items, evalItem{
					resType: resType,
					address: addr,
					name:    resName,
					props:   props,
				})
			}
		}
	}

	// Map to correlate related resources (like s3 bucket and its public access block)
	pabBuckets := make(map[string]bool)
	encBuckets := make(map[string]bool)

	for _, item := range items {
		switch item.resType {
		case "aws_s3_bucket_public_access_block":
			bucket := fmt.Sprintf("%v", item.props["bucket"])
			pabBuckets[bucket] = true
		case "aws_s3_bucket_server_side_encryption_configuration":
			bucket := fmt.Sprintf("%v", item.props["bucket"])
			encBuckets[bucket] = true
		}
	}

	for _, item := range items {
		line := findLineInContent(contentStr, item.address, item.name, item.resType)
		findings := evaluateResourceFindings(item.resType, item.address, item.props, pabBuckets, encBuckets)
		for _, f := range findings {
			results = append(results, attachLocation(f, filePath, line))
		}
	}

	return results, nil
}

// ScanTFDirectory scans all supported IaC files (.tf, .json, .yaml, .yml) in a directory.
func (s *Scanner) ScanTFDirectory(dir string) ([]model.ScanResult, error) {
	var allResults []model.ScanResult
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if path != dir && (strings.HasPrefix(base, ".") || base == "node_modules" || base == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".tf":
			findings, err := s.ScanTFFile(path)
			if err == nil {
				allResults = append(allResults, findings...)
			}
		case ".json":
			findings, err := s.scanJSONFile(path)
			if err == nil {
				allResults = append(allResults, findings...)
			}
		case ".yaml", ".yml":
			findings, err := s.scanYAMLFile(path)
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
	blockStartLine := 1
	blockLines := make([]string, 0)
	inBlock := false
	braceCount := 0

	for idx, line := range lines {
		lineNum := idx + 1
		trimmed := strings.TrimSpace(line)
		if !inBlock && strings.HasPrefix(trimmed, "resource ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 3 {
				currType = strings.Trim(parts[1], "\"")
				currName = strings.Trim(parts[2], "\"")
				blockStartLine = lineNum
				inBlock = true
				braceCount = 0
				blockLines = nil
			}
		}

		if inBlock {
			blockLines = append(blockLines, line)
			braceCount += countBracesOutsideQuotes(line, '{')
			braceCount -= countBracesOutsideQuotes(line, '}')
			if braceCount <= 0 && len(blockLines) > 1 {
				address := fmt.Sprintf("%s.%s", currType, currName)
				findings := evaluateTFBlock(currType, address, path, strings.Join(blockLines, "\n"), blockStartLine)
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

	case "aws_security_group":
		// Only evaluate ingress rules (never egress).
		hasOpenIngress := false
		if ingressList, ok := props["ingress"].([]interface{}); ok {
			for _, ing := range ingressList {
				if ingMap, ok := ing.(map[string]interface{}); ok {
					if isMapRuleOpenIngress(ingMap) {
						hasOpenIngress = true
						break
					}
				}
			}
		}

		if hasOpenIngress {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "Security Group has Unrestricted Ingress (0.0.0.0/0 or ::/0)",
				Description:  fmt.Sprintf("Resource %s opens inbound access to the world", address),
				Remediation:  "Restrict inbound CIDR ranges to authorized corporate subnets or VPC CIDR",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
		ruleType := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", props["type"])))
		if resType == "aws_security_group_rule" && ruleType == "egress" {
			break
		}
		if isMapRuleOpenIngress(props) {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "Security Group Rule has Unrestricted Ingress (0.0.0.0/0 or ::/0)",
				Description:  fmt.Sprintf("Resource %s opens inbound access to the world", address),
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

	case "aws_db_instance", "aws_rds_cluster":
		if toBool(props["publicly_accessible"]) {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "rds_instance_no_public_access",
				Title:        "RDS Instance is Publicly Accessible",
				Description:  fmt.Sprintf("RDS resource %s has publicly_accessible enabled.", address),
				Remediation:  "Set publicly_accessible = false on RDS resource",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}
		if enc, exists := props["storage_encrypted"]; !exists || !toBool(enc) {
			findings = append(findings, model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "rds_instance_storage_encrypted",
				Title:        "RDS Storage Encryption Disabled",
				Description:  fmt.Sprintf("RDS resource %s does not enable storage encryption.", address),
				Remediation:  "Set storage_encrypted = true on RDS resource",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "aws_instance":
		instanceType, _ := props["instance_type"].(string)
		monthlyCost := estimateEC2Monthly(instanceType)
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

func evaluateTFBlock(resType, address, path, blockText string, blockStartLine int) []model.ScanResult {
	var findings []model.ScanResult

	normText := strings.ReplaceAll(blockText, " ", "")

	switch resType {
	case "aws_s3_bucket":
		if strings.Contains(normText, "acl=\"public-read\"") || strings.Contains(normText, "acl=\"public-read-write\"") {
			line := findOffsetLineInBlock(blockText, blockStartLine, "acl")
			findings = append(findings, attachLocation(model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "s3_bucket_level_public_access_block",
				Title:        "S3 Bucket Configured with Public ACL",
				Description:  fmt.Sprintf("Bucket at %s:%d has public read or write ACL.", path, line),
				Remediation:  "Remove public ACL and configure aws_s3_bucket_public_access_block",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			}, path, line))
		}

	case "aws_security_group":
		ingressBlocks := extractHCLSubBlocks(blockText, "ingress", blockStartLine)
		for _, ing := range ingressBlocks {
			if isHCLIngressSubBlockOpen(ing.text) {
				findings = append(findings, attachLocation(model.ScanResult{
					ResourceID:   address,
					ResourceType: resType,
					RuleID:       "ec2_security_group_open_to_world",
					Title:        "Security Group Exposes Sensitive Inbound Port or All Traffic to World",
					Description:  fmt.Sprintf("Security group in %s:%d allows unrestricted world ingress.", path, ing.startLine),
					Remediation:  "Restrict inbound CIDR blocks on port 22, 3389, or all ports",
					Severity:     model.SeverityCritical,
					Status:       model.StatusFail,
					Category:     model.CategorySecurity,
					EvaluatedAt:  time.Now(),
				}, path, ing.startLine))
				break
			}
		}

	case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
		attrs := parseHCLKeyValues(blockText)
		ruleType := strings.ToLower(attrs["type"])
		if resType == "aws_security_group_rule" && ruleType != "ingress" {
			break
		}
		if isHCLIngressSubBlockOpen(blockText) {
			findings = append(findings, attachLocation(model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "Security Group Rule Exposes Sensitive Inbound Port or All Traffic to World",
				Description:  fmt.Sprintf("Security group rule in %s:%d allows unrestricted world ingress.", path, blockStartLine),
				Remediation:  "Restrict inbound CIDR blocks on port 22, 3389, or all ports",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			}, path, blockStartLine))
		}

	case "aws_ebs_volume":
		if strings.Contains(normText, "encrypted=false") || !strings.Contains(normText, "encrypted=true") {
			line := findOffsetLineInBlock(blockText, blockStartLine, "encrypted")
			findings = append(findings, attachLocation(model.ScanResult{
				ResourceID:   address,
				ResourceType: resType,
				RuleID:       "ebs_volume_encryption_enabled",
				Title:        "EBS Volume Missing Default Encryption",
				Description:  fmt.Sprintf("EBS volume defined in %s:%d does not enable encryption.", path, line),
				Remediation:  "Set encrypted = true on aws_ebs_volume",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			}, path, line))
		}
	}

	return findings
}

type hclSubBlock struct {
	text      string
	startLine int
}

// extractHCLSubBlocks extracts sub-blocks of a given name (e.g. "ingress") from a resource block.
func extractHCLSubBlocks(blockText, targetName string, blockStartLine int) []hclSubBlock {
	var subBlocks []hclSubBlock
	lines := strings.Split(blockText, "\n")

	inSub := false
	subBraceCount := 0
	var currentLines []string
	subStart := blockStartLine

	for idx, line := range lines {
		if idx == 0 {
			continue // skip outer `resource "..." "..." {` line
		}
		trimmed := strings.TrimSpace(stripLineComment(line))
		if !inSub {
			// Match `ingress {` or `ingress = [`
			if strings.HasPrefix(trimmed, targetName) {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, targetName))
				if strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, "=") {
					inSub = true
					subStart = blockStartLine + idx
					subBraceCount = 0
					currentLines = nil
				}
			}
		}

		if inSub {
			currentLines = append(currentLines, line)
			subBraceCount += countBracesOutsideQuotes(line, '{') + countBracesOutsideQuotes(line, '[')
			subBraceCount -= countBracesOutsideQuotes(line, '}') + countBracesOutsideQuotes(line, ']')
			if subBraceCount <= 0 && len(currentLines) > 0 {
				subBlocks = append(subBlocks, hclSubBlock{
					text:      strings.Join(currentLines, "\n"),
					startLine: subStart,
				})
				inSub = false
				currentLines = nil
			}
		}
	}

	return subBlocks
}

func isHCLIngressSubBlockOpen(subBlockText string) bool {
	if !containsWorldCIDRInText(subBlockText) {
		return false
	}

	attrs := parseHCLKeyValues(subBlockText)
	protocol := attrs["protocol"]
	if protocol == "" {
		protocol = attrs["ip_protocol"]
	}

	fromStr, hasFrom := attrs["from_port"]
	toStr, hasTo := attrs["to_port"]

	hasPortRange := false
	fromPort, toPort := 0, 0

	if hasFrom {
		if v, err := strconv.Atoi(fromStr); err == nil {
			fromPort = v
			toPort = v
			hasPortRange = true
		}
	}
	if hasTo {
		if v, err := strconv.Atoi(toStr); err == nil {
			toPort = v
			if !hasPortRange {
				fromPort = v
			}
			hasPortRange = true
		}
	}

	return isSensitiveOrAllPorts(fromPort, toPort, hasPortRange, protocol)
}

func containsWorldCIDRInText(text string) bool {
	return strings.Contains(text, `"0.0.0.0/0"`) ||
		strings.Contains(text, `'0.0.0.0/0'`) ||
		strings.Contains(text, `"::/0"`) ||
		strings.Contains(text, `'::/0'`)
}

func parseHCLKeyValues(blockText string) map[string]string {
	res := make(map[string]string)
	for _, line := range strings.Split(blockText, "\n") {
		cleaned := strings.TrimSpace(stripLineComment(line))
		if cleaned == "" {
			continue
		}
		eqIdx := strings.Index(cleaned, "=")
		if eqIdx == -1 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(cleaned[:eqIdx]))
		val := strings.TrimSpace(cleaned[eqIdx+1:])
		val = strings.TrimSuffix(val, ",")
		val = strings.Trim(val, "\"'")
		res[key] = val
	}
	return res
}

func stripLineComment(line string) string {
	inQuotes := false
	var quoteChar byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if (ch == '"' || ch == '\'') && (i == 0 || line[i-1] != '\\') {
			if !inQuotes {
				inQuotes = true
				quoteChar = ch
			} else if ch == quoteChar {
				inQuotes = false
			}
		}
		if !inQuotes {
			if ch == '#' {
				return line[:i]
			}
			if ch == '/' && i+1 < len(line) && line[i+1] == '/' {
				return line[:i]
			}
		}
	}
	return line
}

func countBracesOutsideQuotes(line string, target byte) int {
	cleaned := stripLineComment(line)
	inQuotes := false
	var quoteChar byte
	count := 0
	for i := 0; i < len(cleaned); i++ {
		ch := cleaned[i]
		if (ch == '"' || ch == '\'') && (i == 0 || cleaned[i-1] != '\\') {
			if !inQuotes {
				inQuotes = true
				quoteChar = ch
			} else if ch == quoteChar {
				inQuotes = false
			}
			continue
		}
		if !inQuotes && ch == target {
			count++
		}
	}
	return count
}

func isMapRuleOpenIngress(m map[string]interface{}) bool {
	hasOpenCIDR := false
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks", "CidrIp", "CidrIpv6", "cidr_ipv4", "cidr_ipv6"} {
		val, exists := m[key]
		if !exists {
			continue
		}
		switch v := val.(type) {
		case string:
			if v == "0.0.0.0/0" || v == "::/0" {
				hasOpenCIDR = true
			}
		case []interface{}:
			for _, item := range v {
				s := fmt.Sprintf("%v", item)
				if s == "0.0.0.0/0" || s == "::/0" {
					hasOpenCIDR = true
					break
				}
			}
		case []string:
			for _, s := range v {
				if s == "0.0.0.0/0" || s == "::/0" {
					hasOpenCIDR = true
					break
				}
			}
		}
	}

	if !hasOpenCIDR {
		return false
	}

	fromPort, hasFrom := parseIntProp(m, "from_port", "FromPort")
	toPort, hasTo := parseIntProp(m, "to_port", "ToPort")
	hasPortRange := hasFrom || hasTo
	if hasFrom && !hasTo {
		toPort = fromPort
	} else if hasTo && !hasFrom {
		fromPort = toPort
	}

	protocol := ""
	for _, pk := range []string{"protocol", "ip_protocol", "IpProtocol"} {
		if pv, ok := m[pk]; ok && pv != nil {
			protocol = fmt.Sprintf("%v", pv)
			break
		}
	}

	return isSensitiveOrAllPorts(fromPort, toPort, hasPortRange, protocol)
}

func parseIntProp(m map[string]interface{}, keys ...string) (int, bool) {
	for _, k := range keys {
		val, exists := m[k]
		if !exists || val == nil {
			continue
		}
		switch v := val.(type) {
		case int:
			return v, true
		case int64:
			return int(v), true
		case float64:
			return int(v), true
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

// isSensitiveOrAllPorts checks if port 22 (SSH), 3389 (RDP), or all ports fall in [fromPort, toPort].
func isSensitiveOrAllPorts(fromPort, toPort int, hasPortRange bool, protocol string) bool {
	proto := strings.ToLower(strings.TrimSpace(strings.Trim(protocol, "\"'")))
	if proto == "-1" || proto == "all" {
		return true
	}
	if !hasPortRange {
		return true
	}
	if fromPort == -1 && toPort == -1 {
		return true
	}
	if fromPort == 0 && (toPort == 0 || toPort == 65535) {
		return true
	}
	if fromPort <= 22 && toPort >= 22 {
		return true
	}
	if fromPort <= 3389 && toPort >= 3389 {
		return true
	}
	return false
}

func toBool(val interface{}) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func attachLocation(r model.ScanResult, filePath string, line int) model.ScanResult {
	if filePath == "" {
		filePath = "tfplan.json"
	}
	if line <= 0 {
		line = 1
	}
	loc := fmt.Sprintf("%s:%d", filePath, line)
	if !strings.Contains(r.Description, loc) && !strings.Contains(r.ResourceID, loc) {
		if r.Description != "" {
			r.Description = fmt.Sprintf("%s (%s)", strings.TrimSuffix(r.Description, "."), loc)
		} else {
			r.Description = fmt.Sprintf("Detected at %s", loc)
		}
	}

	metricsMap := make(map[string]interface{})
	if existing, ok := r.Metrics.(map[string]interface{}); ok {
		for k, v := range existing {
			metricsMap[k] = v
		}
	}
	metricsMap["File"] = filePath
	metricsMap["Line"] = line
	r.Metrics = metricsMap
	return r
}

func findOffsetLineInBlock(blockText string, blockStartLine int, keyword string) int {
	lines := strings.Split(blockText, "\n")
	for idx, line := range lines {
		if strings.Contains(line, keyword) {
			return blockStartLine + idx
		}
	}
	return blockStartLine
}

func findLineInContent(content string, needles ...string) int {
	lines := strings.Split(content, "\n")
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		for idx, line := range lines {
			if strings.Contains(line, needle) {
				return idx + 1
			}
		}
	}
	return 1
}

func splitYAMLDocuments(data []byte) [][]byte {
	norm := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.Split(norm, []byte("\n---"))
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
