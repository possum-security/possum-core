package secaas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	graph "github.com/possum-security/possum-core/pkg/model"
	"github.com/possum-security/possum-core/pkg/scanner"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
)

// EventBridgeApi defines the mockable interface for Amazon EventBridge API operations.
type EventBridgeApi interface {
	ListEventBuses(ctx context.Context, params *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error)
}

// EventBridgeScanner evaluates Amazon EventBridge event bus security postures.
type EventBridgeScanner struct {
	client EventBridgeApi
	region string
}

// NewEventBridgeScanner creates an EventBridgeScanner with the provided AWS config.
func NewEventBridgeScanner(cfg aws.Config) *EventBridgeScanner {
	return &EventBridgeScanner{
		client: eventbridge.NewFromConfig(cfg),
		region: cfg.Region,
	}
}

// NewEventBridgeScannerWithClient creates an EventBridgeScanner with a custom/mock client.
func NewEventBridgeScannerWithClient(client EventBridgeApi, region string) *EventBridgeScanner {
	return &EventBridgeScanner{
		client: client,
		region: region,
	}
}

// Name returns the identifier name for the scanner.
func (s *EventBridgeScanner) Name() string {
	return "EventBridge-SecaaS-Scanner"
}

// Scan audits all EventBridge event buses in the configured region against security best practices.
func (s *EventBridgeScanner) Scan(ctx context.Context) ([]scanner.ScanResult, error) {
	limit := scanner.GetResourceLimit(ctx)
	processedCount := 0
	var results []scanner.ScanResult

	region := s.region
	if region == "" {
		region = "global"
	}

	var nextToken *string
	for {
		if scanner.ShouldStop(ctx, processedCount, limit) {
			break
		}
		output, err := s.client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list EventBridge event buses: %w", err)
		}

		for _, bus := range output.EventBuses {
			if scanner.ShouldStop(ctx, processedCount, limit) {
				break
			}
			processedCount++

			busName := aws.ToString(bus.Name)
			busArn := aws.ToString(bus.Arn)
			if busName == "" {
				busName = busArn
			}
			if busArn == "" {
				busArn = fmt.Sprintf("arn:aws:events:%s::event-bus/%s", region, busName)
			}
			if busName == "" {
				busName = "default"
			}

			busAccountID := extractAccountFromArn(busArn)
			nodes := []graph.Node{{ID: busArn, NodeType: "SecaaS-EventBridge"}}

			policyStr := aws.ToString(bus.Policy)
			if strings.Contains(policyStr, "%") {
				if decoded, err := url.QueryUnescape(policyStr); err == nil {
					policyStr = decoded
				}
			}

			isExposed := false
			hasCrossAccount := false

			if policyStr != "" {
				stmts, _ := parseEventBusPolicyStatements(policyStr)
				for _, stmt := range stmts {
					if !strings.EqualFold(stmt.Effect, "Allow") {
						continue
					}

					p := parseEventBusPrincipal(stmt.Principal)
					hasCond := len(stmt.Condition) > 0

					// 1. Rule: eventbridge_bus_exposed (HIGH)
					// Inspect event bus Policy. If policy grants Principal: "*" without condition: FAIL, else PASS
					if p.IsWildcard && !hasCond {
						isExposed = true
					}

					// 2. Rule: eventbridge_bus_cross_account_access (MEDIUM)
					// If event bus policy grants access to external account IDs outside trusted organization/account: FAIL, else PASS
					if !hasTrustedOrgOrAccountCondition(stmt.Condition, busAccountID) {
						if p.IsWildcard {
							hasCrossAccount = true
						}
						for _, acc := range p.AWSAccounts {
							if busAccountID == "" || acc != busAccountID {
								hasCrossAccount = true
								break
							}
						}
					}
				}
			}

			// 1. Evaluate eventbridge_bus_exposed
			if isExposed {
				results = append(results, scanner.ScanResult{
					ResourceID:   busName,
					ResourceType: "SecaaS-EventBridge",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "eventbridge_bus_exposed",
					Severity:     "HIGH",
					Metrics: map[string]interface{}{
						"EventBusName":   busName,
						"EventBusArn":    busArn,
						"StatusExtended": fmt.Sprintf("EventBridge event bus %s grants public access via wildcard Principal (*) without conditions.", busName),
						"SecurityIssues": []string{"Event bus allows public access via wildcard Principal (*) without conditions"},
						"Recommendation": "Remove public wildcard access or add restricting conditions to the event bus policy.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   busName,
					ResourceType: "SecaaS-EventBridge",
					Region:       region,
					Status:       "PASS",
					RuleID:       "eventbridge_bus_exposed",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"EventBusName":   busName,
						"EventBusArn":    busArn,
						"StatusExtended": fmt.Sprintf("EventBridge event bus %s does not grant public access without conditions.", busName),
					},
					Nodes: nodes,
				})
			}

			// 2. Evaluate eventbridge_bus_cross_account_access
			if hasCrossAccount {
				results = append(results, scanner.ScanResult{
					ResourceID:   busName,
					ResourceType: "SecaaS-EventBridge",
					Region:       region,
					Status:       "FAIL",
					RuleID:       "eventbridge_bus_cross_account_access",
					Severity:     "MEDIUM",
					Metrics: map[string]interface{}{
						"EventBusName":   busName,
						"EventBusArn":    busArn,
						"StatusExtended": fmt.Sprintf("EventBridge event bus %s policy grants access to external account IDs outside trusted organization/account.", busName),
						"SecurityIssues": []string{"Event bus policy grants cross-account access to external accounts outside trusted organization/account"},
						"Recommendation": "Apply least privilege on the event bus resource policy: allow only specific account IDs or org scope (e.g., aws:PrincipalOrgID) and avoid wildcard Principal or unauthorized external accounts.",
					},
					Nodes: nodes,
				})
			} else {
				results = append(results, scanner.ScanResult{
					ResourceID:   busName,
					ResourceType: "SecaaS-EventBridge",
					Region:       region,
					Status:       "PASS",
					RuleID:       "eventbridge_bus_cross_account_access",
					Severity:     "INFO",
					Metrics: map[string]interface{}{
						"EventBusName":   busName,
						"EventBusArn":    busArn,
						"StatusExtended": fmt.Sprintf("EventBridge event bus %s does not allow cross-account access outside trusted organization/account.", busName),
					},
					Nodes: nodes,
				})
			}
		}

		if output.NextToken == nil || *output.NextToken == "" {
			break
		}
		nextToken = output.NextToken
	}

	return results, nil
}

type eventBusPolicyDoc struct {
	Statement json.RawMessage `json:"Statement"`
}

type eventBusPolicyStatement struct {
	Sid       string                 `json:"Sid"`
	Effect    string                 `json:"Effect"`
	Principal json.RawMessage        `json:"Principal"`
	Action    interface{}            `json:"Action"`
	Resource  interface{}            `json:"Resource"`
	Condition map[string]interface{} `json:"Condition"`
}

func parseEventBusPolicyStatements(policyStr string) ([]eventBusPolicyStatement, error) {
	if strings.TrimSpace(policyStr) == "" {
		return nil, nil
	}
	var doc eventBusPolicyDoc
	if err := json.Unmarshal([]byte(policyStr), &doc); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(doc.Statement)
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] == '[' {
		var stmts []eventBusPolicyStatement
		if err := json.Unmarshal(raw, &stmts); err != nil {
			return nil, err
		}
		return stmts, nil
	} else if raw[0] == '{' {
		var single eventBusPolicyStatement
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, err
		}
		return []eventBusPolicyStatement{single}, nil
	}
	return nil, nil
}

type parsedPrincipal struct {
	IsWildcard  bool
	AWSAccounts []string
}

func parseEventBusPrincipal(raw json.RawMessage) parsedPrincipal {
	var result parsedPrincipal
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return result
	}

	var strVal string
	if err := json.Unmarshal(trimmed, &strVal); err == nil {
		if strVal == "*" {
			result.IsWildcard = true
		} else if acc := extractAccountID(strVal); acc != "" {
			result.AWSAccounts = append(result.AWSAccounts, acc)
		}
		return result
	}

	var mapVal map[string]interface{}
	if err := json.Unmarshal(trimmed, &mapVal); err == nil {
		if awsVal, ok := mapVal["AWS"]; ok {
			inspectAWSPrincipal(awsVal, &result)
		}
	}
	return result
}

func inspectAWSPrincipal(val interface{}, result *parsedPrincipal) {
	switch v := val.(type) {
	case string:
		if v == "*" {
			result.IsWildcard = true
		} else if acc := extractAccountID(v); acc != "" {
			result.AWSAccounts = append(result.AWSAccounts, acc)
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s == "*" {
					result.IsWildcard = true
				} else if acc := extractAccountID(s); acc != "" {
					result.AWSAccounts = append(result.AWSAccounts, acc)
				}
			}
		}
	}
}

func extractAccountID(principal string) string {
	principal = strings.TrimSpace(principal)
	if principal == "" || principal == "*" {
		return ""
	}
	if strings.HasPrefix(principal, "arn:") {
		parts := strings.Split(principal, ":")
		if len(parts) >= 5 && parts[4] != "" {
			return parts[4]
		}
		return ""
	}
	isDigits := true
	for _, ch := range principal {
		if ch < '0' || ch > '9' {
			isDigits = false
			break
		}
	}
	if isDigits && len(principal) >= 6 {
		return principal
	}
	return principal
}

func extractAccountFromArn(arnStr string) string {
	parts := strings.Split(arnStr, ":")
	if len(parts) >= 5 && parts[4] != "" {
		return parts[4]
	}
	return ""
}

func hasTrustedOrgOrAccountCondition(condition map[string]interface{}, busAccountID string) bool {
	if len(condition) == 0 {
		return false
	}
	for _, opVal := range condition {
		opMap, ok := opVal.(map[string]interface{})
		if !ok {
			continue
		}
		for key, val := range opMap {
			lowerKey := strings.ToLower(key)
			if lowerKey == "aws:principalorgid" || lowerKey == "aws:principalorgpaths" {
				return true
			}
			if busAccountID != "" && (lowerKey == "aws:principalaccount" || lowerKey == "aws:sourceaccount") {
				if matchAccountValue(val, busAccountID) {
					return true
				}
			}
		}
	}
	return false
}

func matchAccountValue(val interface{}, targetAccountID string) bool {
	switch v := val.(type) {
	case string:
		return v == targetAccountID
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == targetAccountID {
				return true
			}
		}
	}
	return false
}

// Meta returns rich scanner metadata for execution planning and pre-filtering.
func (s *EventBridgeScanner) Meta() scanner.ScannerMeta {
	return scanner.ScannerMeta{
		ID:            "eventbridge-scanner",
		Name:          s.Name(),
		Category:      graph.CategorySecOps,
		Scope:         graph.ScopeRegional,
		ExecutionCost: scanner.CostMedium,
		Service:       "eventbridge",
		CheckIDs:      []string{"eventbridge_bus_cross_account_access", "eventbridge_bus_exposed"},
	}
}
