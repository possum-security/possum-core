package iac

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"gopkg.in/yaml.v3"
)

func isCloudFormationMap(doc map[string]interface{}) bool {
	if doc == nil {
		return false
	}
	if _, hasVer := doc["AWSTemplateFormatVersion"]; hasVer {
		return true
	}
	resMap, ok := doc["Resources"].(map[string]interface{})
	if !ok || len(resMap) == 0 {
		return false
	}
	for _, entry := range resMap {
		if m, ok := entry.(map[string]interface{}); ok {
			if t, ok := m["Type"].(string); ok {
				if strings.HasPrefix(t, "AWS::") || strings.HasPrefix(t, "Alexa::") || strings.HasPrefix(t, "Custom::") {
					return true
				}
			}
		}
	}
	return false
}

func scanCloudFormationYAML(data []byte, filePath string) ([]model.ScanResult, bool, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var rootNode yaml.Node
	if err := dec.Decode(&rootNode); err != nil {
		if err == io.EOF {
			return nil, false, nil
		}
		return nil, false, err
	}

	rawVal := yamlNodeToInterface(&rootNode)
	rawDoc, ok := rawVal.(map[string]interface{})
	if !ok || !isCloudFormationMap(rawDoc) {
		return nil, false, nil
	}

	results := evaluateCloudFormationTemplate(rawDoc, filePath, string(data), &rootNode)
	return results, true, nil
}

func evaluateCloudFormationTemplate(doc map[string]interface{}, filePath, content string, rootNode *yaml.Node) []model.ScanResult {
	var results []model.ScanResult

	resMap, ok := doc["Resources"].(map[string]interface{})
	if !ok {
		return nil
	}

	// Sort resource IDs for deterministic output ordering
	logicalIDs := make([]string, 0, len(resMap))
	for id := range resMap {
		logicalIDs = append(logicalIDs, id)
	}
	sort.Strings(logicalIDs)

	for _, logicalID := range logicalIDs {
		entry, ok := resMap[logicalID].(map[string]interface{})
		if !ok {
			continue
		}
		resType, _ := entry["Type"].(string)
		if resType == "" {
			continue
		}
		props, _ := entry["Properties"].(map[string]interface{})
		if props == nil {
			props = make(map[string]interface{})
		}

		line := 0
		if rootNode != nil {
			line = findYAMLKeyLine(rootNode, "Resources", logicalID)
		}
		if line <= 0 {
			line = findLineInContent(content, logicalID, resType)
		}

		findings := evaluateCFNResource(logicalID, resType, props)
		for _, f := range findings {
			results = append(results, attachLocation(f, filePath, line))
		}
	}

	return results
}

func evaluateCFNResource(logicalID, resType string, props map[string]interface{}) []model.ScanResult {
	var findings []model.ScanResult

	switch resType {
	case "AWS::S3::Bucket":
		pab, hasPAB := props["PublicAccessBlockConfiguration"].(map[string]interface{})
		pabComplete := false
		if hasPAB && pab != nil {
			pabComplete = toBool(pab["BlockPublicAcls"]) &&
				toBool(pab["BlockPublicPolicy"]) &&
				toBool(pab["IgnorePublicAcls"]) &&
				toBool(pab["RestrictPublicBuckets"])
		}
		acl, _ := props["AccessControl"].(string)
		isPublicACL := strings.EqualFold(acl, "PublicRead") || strings.EqualFold(acl, "PublicReadWrite")

		if !pabComplete || isPublicACL {
			sev := model.SeverityHigh
			if isPublicACL {
				sev = model.SeverityCritical
			}
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "s3_bucket_level_public_access_block",
				Title:        "CloudFormation S3 Bucket Missing PublicAccessBlockConfiguration",
				Description:  fmt.Sprintf("S3 bucket %s in CloudFormation template does not block public access.", logicalID),
				Remediation:  "Configure PublicAccessBlockConfiguration with BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets set to true",
				Severity:     sev,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

		if _, hasEnc := props["BucketEncryption"]; !hasEnc || props["BucketEncryption"] == nil {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "s3_bucket_default_encryption",
				Title:        "CloudFormation S3 Bucket Missing BucketEncryption",
				Description:  fmt.Sprintf("S3 bucket %s in CloudFormation template does not enable server-side encryption.", logicalID),
				Remediation:  "Add BucketEncryption with ServerSideEncryptionConfiguration (AES256 or aws:kms)",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "AWS::EC2::SecurityGroup":
		hasOpenIngress := false
		if ingRaw, exists := props["SecurityGroupIngress"]; exists && ingRaw != nil {
			switch v := ingRaw.(type) {
			case []interface{}:
				for _, item := range v {
					if ingMap, ok := item.(map[string]interface{}); ok {
						if isMapRuleOpenIngress(ingMap) {
							hasOpenIngress = true
							break
						}
					}
				}
			case map[string]interface{}:
				if isMapRuleOpenIngress(v) {
					hasOpenIngress = true
				}
			}
		}

		if hasOpenIngress {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "CloudFormation SecurityGroup Allows Unrestricted Inbound Traffic",
				Description:  fmt.Sprintf("SecurityGroup %s allows inbound access from 0.0.0.0/0 or ::/0 on sensitive or all ports.", logicalID),
				Remediation:  "Restrict SecurityGroupIngress CidrIp / CidrIpv6 to trusted IP ranges",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "AWS::EC2::SecurityGroupIngress":
		if isMapRuleOpenIngress(props) {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "ec2_security_group_open_to_world",
				Title:        "CloudFormation SecurityGroupIngress Allows Unrestricted Inbound Traffic",
				Description:  fmt.Sprintf("SecurityGroupIngress %s allows inbound access from 0.0.0.0/0 or ::/0.", logicalID),
				Remediation:  "Restrict CidrIp / CidrIpv6 to trusted IP ranges",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster":
		if toBool(props["PubliclyAccessible"]) {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "rds_instance_no_public_access",
				Title:        "CloudFormation RDS Instance is Publicly Accessible",
				Description:  fmt.Sprintf("RDS resource %s has PubliclyAccessible set to true.", logicalID),
				Remediation:  "Set PubliclyAccessible to false in Properties",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}
		if !toBool(props["StorageEncrypted"]) {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "rds_instance_storage_encrypted",
				Title:        "CloudFormation RDS Storage Encryption Disabled",
				Description:  fmt.Sprintf("RDS resource %s does not enable StorageEncrypted.", logicalID),
				Remediation:  "Set StorageEncrypted to true in Properties",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "AWS::EC2::Volume":
		if !toBool(props["Encrypted"]) {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "ebs_volume_encryption_enabled",
				Title:        "CloudFormation EBS Volume Not Encrypted",
				Description:  fmt.Sprintf("EBS Volume %s has Encrypted set to false or omitted.", logicalID),
				Remediation:  "Set Encrypted: true on AWS::EC2::Volume resource",
				Severity:     model.SeverityHigh,
				Status:       model.StatusFail,
				Category:     model.CategorySecurity,
				EvaluatedAt:  time.Now(),
			})
		}

	case "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role":
		if hasWildcardPolicyInCFNProps(props) {
			findings = append(findings, model.ScanResult{
				ResourceID:   logicalID,
				ResourceType: resType,
				RuleID:       "iam_policy_wildcard_action_resource",
				Title:        "CloudFormation IAM Policy Grants Wildcard (*) Action and Resource",
				Description:  fmt.Sprintf("IAM resource %s contains a policy statement with Effect Allow, Action '*', and Resource '*'.", logicalID),
				Remediation:  "Scope IAM actions and resource ARNs according to least-privilege principles",
				Severity:     model.SeverityCritical,
				Status:       model.StatusFail,
				Category:     model.CategoryIAM,
				EvaluatedAt:  time.Now(),
			})
		}
	}

	return findings
}

func hasWildcardPolicyInCFNProps(props map[string]interface{}) bool {
	var policyDocs []map[string]interface{}

	if doc, ok := props["PolicyDocument"].(map[string]interface{}); ok {
		policyDocs = append(policyDocs, doc)
	}
	if policies, ok := props["Policies"].([]interface{}); ok {
		for _, p := range policies {
			if pMap, ok := p.(map[string]interface{}); ok {
				if doc, ok := pMap["PolicyDocument"].(map[string]interface{}); ok {
					policyDocs = append(policyDocs, doc)
				}
			}
		}
	}

	for _, doc := range policyDocs {
		stmtRaw, exists := doc["Statement"]
		if !exists || stmtRaw == nil {
			continue
		}
		var stmts []map[string]interface{}
		switch v := stmtRaw.(type) {
		case []interface{}:
			for _, item := range v {
				if sm, ok := item.(map[string]interface{}); ok {
					stmts = append(stmts, sm)
				}
			}
		case map[string]interface{}:
			stmts = append(stmts, v)
		}

		for _, stmt := range stmts {
			effect := fmt.Sprintf("%v", stmt["Effect"])
			if !strings.EqualFold(strings.TrimSpace(effect), "Allow") {
				continue
			}
			if hasWildcardIAMValue(stmt["Action"]) && hasWildcardIAMValue(stmt["Resource"]) {
				return true
			}
		}
	}
	return false
}

func hasWildcardIAMValue(val interface{}) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		return trimmed == "*" || trimmed == "*:*"
	case []interface{}:
		for _, item := range v {
			s := strings.TrimSpace(fmt.Sprintf("%v", item))
			if s == "*" || s == "*:*" {
				return true
			}
		}
	case []string:
		for _, item := range v {
			s := strings.TrimSpace(item)
			if s == "*" || s == "*:*" {
				return true
			}
		}
	}
	return false
}

// yamlNodeToInterface converts a yaml.Node tree into standard Go maps/slices/scalars,
// gracefully preserving CloudFormation intrinsic function tags (!Ref, !Sub, !GetAtt, etc.).
func yamlNodeToInterface(node *yaml.Node) interface{} {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) > 0 {
			return yamlNodeToInterface(node.Content[0])
		}
		return nil
	case yaml.MappingNode:
		m := make(map[string]interface{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			k := node.Content[i].Value
			v := yamlNodeToInterface(node.Content[i+1])
			m[k] = v
		}
		return m
	case yaml.SequenceNode:
		s := make([]interface{}, 0, len(node.Content))
		for _, child := range node.Content {
			s = append(s, yamlNodeToInterface(child))
		}
		return s
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!null":
			return nil
		case "!!bool":
			return strings.EqualFold(node.Value, "true")
		case "!!int":
			if iv, err := strconv.Atoi(node.Value); err == nil {
				return iv
			}
			return node.Value
		case "!!float":
			if fv, err := strconv.ParseFloat(node.Value, 64); err == nil {
				return fv
			}
			return node.Value
		default:
			if strings.EqualFold(node.Value, "true") {
				return true
			}
			if strings.EqualFold(node.Value, "false") {
				return false
			}
			return node.Value
		}
	case yaml.AliasNode:
		if node.Alias != nil {
			return yamlNodeToInterface(node.Alias)
		}
		return node.Value
	default:
		return node.Value
	}
}

// findYAMLKeyLine traverses a yaml.Node mapping hierarchy for the given key path and returns its 1-based line number.
func findYAMLKeyLine(node *yaml.Node, keys ...string) int {
	if node == nil || len(keys) == 0 {
		return 0
	}
	curr := node
	if curr.Kind == yaml.DocumentNode && len(curr.Content) > 0 {
		curr = curr.Content[0]
	}

	lineFound := curr.Line
	for _, key := range keys {
		if curr.Kind != yaml.MappingNode {
			break
		}
		matched := false
		for i := 0; i+1 < len(curr.Content); i += 2 {
			kNode := curr.Content[i]
			vNode := curr.Content[i+1]
			if kNode.Value == key {
				lineFound = kNode.Line
				curr = vNode
				matched = true
				break
			}
		}
		if !matched {
			break
		}
	}
	return lineFound
}
