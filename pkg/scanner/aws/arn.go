package aws

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/possum-security/possum-core/pkg/model"
)

var azRegionRegex = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+[a-z]$`)

// NormalizeRegion normalizes an AWS region or availability zone string.
// - Treats "global" (case-insensitive) as "global".
// - Treats "" or "regional" (case-insensitive) as defaultRegion.
// - Strips trailing availability-zone letters (e.g. "us-east-1a" -> "us-east-1").
func NormalizeRegion(region, defaultRegion string) string {
	clean := strings.ToLower(strings.TrimSpace(region))
	if clean == "global" {
		return "global"
	}
	if clean == "" || clean == "regional" {
		clean = strings.ToLower(strings.TrimSpace(defaultRegion))
		if clean == "" || clean == "regional" {
			return ""
		}
		if clean == "global" {
			return "global"
		}
	}
	if azRegionRegex.MatchString(clean) {
		clean = clean[:len(clean)-1]
	}
	return clean
}

func isGlobalService(service string) bool {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "s3", "iam", "cloudfront", "route53", "organizations":
		return true
	default:
		return false
	}
}

func parseARNComponents(arnStr string) (service, region, accountID string) {
	if !IsARN(arnStr) {
		return "", "", ""
	}
	parts := strings.SplitN(strings.TrimSpace(arnStr), ":", 6)
	if len(parts) < 6 {
		return "", "", ""
	}
	return strings.ToLower(strings.TrimSpace(parts[2])), strings.TrimSpace(parts[3]), strings.TrimSpace(parts[4])
}

// IsARN returns true if the given string has the prefix of a canonical AWS ARN.
func IsARN(s string) bool {
	return strings.HasPrefix(s, "arn:aws:") ||
		strings.HasPrefix(s, "arn:aws-us-gov:") ||
		strings.HasPrefix(s, "arn:aws-cn:")
}

// FormatARN builds a canonical AWS ARN for a given service, region, account ID, resource type, and resource ID.
// Handles service-specific ARN formatting conventions (S3, IAM, CloudFront, Route53, etc.).
func FormatARN(service, region, accountID, resourceType, resourceID string) string {
	if IsARN(resourceID) {
		return resourceID
	}

	cleanSvc := strings.ToLower(strings.TrimSpace(service))
	cleanType := strings.TrimSpace(resourceType)
	cleanID := strings.TrimSpace(resourceID)
	cleanAcct := strings.TrimSpace(accountID)
	cleanRegion := NormalizeRegion(region, "")

	if cleanAcct == "" {
		cleanAcct = "123456789012"
	}
	if cleanRegion == "" || strings.EqualFold(cleanRegion, "global") {
		cleanRegion = ""
	}

	switch cleanSvc {
	case "s3":
		// S3: arn:aws:s3:::bucket-name
		return fmt.Sprintf("arn:aws:s3:::%s", cleanID)

	case "iam":
		// IAM is global across the account: arn:aws:iam::<account>:user/name or role/name
		resPrefix := "role"
		if strings.Contains(strings.ToLower(cleanType), "user") {
			resPrefix = "user"
		} else if strings.Contains(strings.ToLower(cleanType), "group") {
			resPrefix = "group"
		} else if strings.Contains(strings.ToLower(cleanType), "policy") {
			resPrefix = "policy"
		}
		if strings.Contains(cleanID, "/") {
			return fmt.Sprintf("arn:aws:iam::%s:%s", cleanAcct, cleanID)
		}
		return fmt.Sprintf("arn:aws:iam::%s:%s/%s", cleanAcct, resPrefix, cleanID)

	case "cloudfront":
		// CloudFront: arn:aws:cloudfront::<account>:distribution/<id>
		return fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", cleanAcct, cleanID)

	case "route53":
		// Route53: arn:aws:route53:::hostedzone/<id>
		return fmt.Sprintf("arn:aws:route53:::hostedzone/%s", cleanID)

	case "organizations":
		// Organizations: arn:aws:organizations::<account>:account/o-.../<id> or root/policy
		if strings.Contains(cleanID, "/") {
			return fmt.Sprintf("arn:aws:organizations::%s:%s", cleanAcct, cleanID)
		}
		return fmt.Sprintf("arn:aws:organizations::%s:account/%s", cleanAcct, cleanID)

	case "ec2":
		// EC2: arn:aws:ec2:<region>:<account>:<type>/<id>
		prefix := "instance"
		lowerID := strings.ToLower(cleanID)
		if strings.HasPrefix(lowerID, "vol-") {
			prefix = "volume"
		} else if strings.HasPrefix(lowerID, "snap-") {
			prefix = "snapshot"
		} else if strings.HasPrefix(lowerID, "sg-") {
			prefix = "security-group"
		} else if strings.HasPrefix(lowerID, "subnet-") {
			prefix = "subnet"
		} else if strings.HasPrefix(lowerID, "vpc-") {
			prefix = "vpc"
		} else if strings.HasPrefix(lowerID, "eni-") {
			prefix = "network-interface"
		} else if strings.HasPrefix(lowerID, "eipalloc-") {
			prefix = "elastic-ip"
		} else if strings.HasPrefix(lowerID, "nat-") {
			prefix = "natgateway"
		}
		if cleanRegion == "" {
			cleanRegion = "us-east-1"
		}
		return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", cleanRegion, cleanAcct, prefix, cleanID)

	case "rds":
		if cleanRegion == "" {
			cleanRegion = "us-east-1"
		}
		prefix := "db"
		if strings.Contains(strings.ToLower(cleanType), "cluster") {
			prefix = "cluster"
		} else if strings.Contains(strings.ToLower(cleanType), "snapshot") {
			prefix = "snapshot"
		}
		return fmt.Sprintf("arn:aws:rds:%s:%s:%s:%s", cleanRegion, cleanAcct, prefix, cleanID)

	case "lambda":
		if cleanRegion == "" {
			cleanRegion = "us-east-1"
		}
		return fmt.Sprintf("arn:aws:lambda:%s:%s:function:%s", cleanRegion, cleanAcct, cleanID)

	case "dynamodb":
		if cleanRegion == "" {
			cleanRegion = "us-east-1"
		}
		return fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", cleanRegion, cleanAcct, cleanID)

	case "kms":
		if cleanRegion == "" {
			cleanRegion = "us-east-1"
		}
		return fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", cleanRegion, cleanAcct, cleanID)

	default:
		if cleanRegion == "" {
			cleanRegion = "us-east-1"
		}
		resTypePart := strings.ToLower(cleanType)
		if resTypePart == "" {
			resTypePart = "resource"
		}
		return fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", cleanSvc, cleanRegion, cleanAcct, resTypePart, cleanID)
	}
}

// StandardizeResultARN ensures that a ScanResult and its associated graph Nodes and Edges
// have canonical AWS ARN identifiers while preserving human-readable names in Metrics["DisplayName"].
func StandardizeResultARN(r *model.ScanResult, defaultAccountID, defaultRegion string) {
	if r == nil {
		return
	}

	// 1. Capture DisplayName in Metrics if not already set
	rawMetrics, ok := r.Metrics.(map[string]interface{})
	if !ok || rawMetrics == nil {
		rawMetrics = make(map[string]interface{})
		r.Metrics = rawMetrics
	}
	if _, exists := rawMetrics["DisplayName"]; !exists {
		rawMetrics["DisplayName"] = r.ResourceID
	}

	// 2. Infer service from ResourceType, RuleID, or existing ARN
	arnSvc, arnRegion, arnAcct := parseARNComponents(r.ResourceID)
	service := inferService(r.ResourceType, r.RuleID)
	if service == "aws" && arnSvc != "" {
		service = arnSvc
	}

	// Populate AccountID if empty or placeholder
	acctID := strings.TrimSpace(r.AccountID)
	if (acctID == "" || acctID == "123456789012") && arnAcct != "" {
		acctID = arnAcct
	}
	if acctID == "" {
		acctID = strings.TrimSpace(defaultAccountID)
	}
	if acctID == "" {
		acctID = "123456789012"
	}
	r.AccountID = acctID

	// Normalize Region
	fallbackRegion := NormalizeRegion(defaultRegion, "us-east-1")
	if fallbackRegion == "" || strings.EqualFold(fallbackRegion, "global") {
		fallbackRegion = "us-east-1"
	}

	rawRegion := strings.TrimSpace(r.Region)
	if (rawRegion == "" || strings.EqualFold(rawRegion, "regional") || strings.EqualFold(rawRegion, "global")) && arnRegion != "" {
		rawRegion = arnRegion
	}

	if isGlobalService(service) {
		if rawRegion == "" || strings.EqualFold(rawRegion, "global") || strings.EqualFold(rawRegion, "regional") {
			r.Region = "global"
		} else {
			r.Region = NormalizeRegion(rawRegion, "global")
		}
	} else {
		if strings.EqualFold(rawRegion, "global") {
			r.Region = fallbackRegion
		} else {
			r.Region = NormalizeRegion(rawRegion, fallbackRegion)
		}
		if r.Region == "" {
			r.Region = fallbackRegion
		}
	}

	arnRegionForFormat := r.Region
	if isGlobalService(service) || strings.EqualFold(arnRegionForFormat, "global") {
		arnRegionForFormat = ""
	}

	oldID := r.ResourceID
	canonicalARN := FormatARN(service, arnRegionForFormat, r.AccountID, r.ResourceType, r.ResourceID)
	r.ResourceID = canonicalARN

	// 3. Update Nodes & Edges to use canonical ARNs where applicable
	for i := range r.Nodes {
		if r.Nodes[i].ID == oldID {
			r.Nodes[i].ID = canonicalARN
		}
	}
	for i := range r.Edges {
		if r.Edges[i].From == oldID {
			r.Edges[i].From = canonicalARN
		}
		if r.Edges[i].To == oldID {
			r.Edges[i].To = canonicalARN
		}
	}
}

// StandardizeResultsARN applies ARN standardization across a collection of scan results.
func StandardizeResultsARN(results []model.ScanResult, defaultAccountID, defaultRegion string) []model.ScanResult {
	for i := range results {
		StandardizeResultARN(&results[i], defaultAccountID, defaultRegion)
	}
	return results
}

func inferService(resourceType, ruleID string) string {
	resLower := strings.ToLower(resourceType)
	ruleLower := strings.ToLower(ruleID)

	candidates := []string{
		"s3", "iam", "ec2", "rds", "lambda", "dynamodb", "kms",
		"cloudfront", "cloudtrail", "cloudwatch", "route53", "elb",
		"vpc", "guardduty", "securityhub", "redshift", "ecs", "ecr",
		"sqs", "sns", "acm", "wafv2", "secretsmanager", "configservice",
		"organizations",
	}

	for _, cand := range candidates {
		if strings.Contains(resLower, cand) || strings.HasPrefix(ruleLower, cand+"_") {
			return cand
		}
	}

	return "aws"
}
