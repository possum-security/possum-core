package custom

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/possum-security/possum-core/pkg/model"
	"gopkg.in/yaml.v3"
)

// Engine evaluates declarative policy rules against scan results and resource properties.
type Engine struct {
	rules []Rule
}

// NewEngine creates a new custom policy engine with optional initial rules.
func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// AddRule registers a declarative rule.
func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// Rules returns all currently registered rules.
func (e *Engine) Rules() []Rule {
	return e.rules
}

// LoadRule reads a single rule from an io.Reader.
func LoadRule(r io.Reader) (*Rule, error) {
	var rule Rule
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to parse custom rule yaml: %w", err)
	}
	if rule.ID == "" {
		return nil, fmt.Errorf("custom rule requires non-empty 'id'")
	}
	if rule.Severity == "" {
		rule.Severity = model.SeverityMedium
	}
	return &rule, nil
}

// LoadDirectory scans a directory recursively for .yaml / .yml rule definitions.
func (e *Engine) LoadDirectory(dir string) (int, error) {
	count := 0
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()

		rule, err := LoadRule(f)
		if err == nil && rule != nil {
			e.AddRule(*rule)
			count++
		}
		return nil
	})
	return count, err
}

// ResourceContext models the evaluation context for a resource under test.
type ResourceContext struct {
	ResourceID   string
	ResourceType string
	Region       string
	Tags         map[string]string
	Properties   map[string]interface{}
}

// EvaluateContext evaluates all registered rules against a given ResourceContext.
// Returns a slice of ScanResult findings for failed checks.
func (e *Engine) EvaluateContext(ctx ResourceContext) []model.ScanResult {
	var results []model.ScanResult

	for _, rule := range e.rules {
		// Filter by ResourceType if specified
		if rule.ResourceType != "" && !strings.EqualFold(rule.ResourceType, ctx.ResourceType) && rule.ResourceType != "*" {
			continue
		}

		passed, err := e.evaluateCondition(rule, ctx)
		if err != nil {
			// On evaluation error, consider failing or skipping
			continue
		}

		// By default (mode "assert"), condition must evaluate to true to pass.
		// If mode == "violate", condition true means a violation occurred.
		isViolation := false
		if strings.EqualFold(rule.Mode, "violate") {
			isViolation = passed
		} else {
			isViolation = !passed
		}

		if isViolation {
			finding := model.ScanResult{
				ResourceID:   ctx.ResourceID,
				ResourceType: ctx.ResourceType,
				Region:       ctx.Region,
				RuleID:       rule.ID,
				Title:        rule.Name,
				Description:  rule.Message,
				Remediation:  rule.Remediation,
				Severity:     rule.Severity,
				Status:       model.StatusFail,
				Category:     rule.Category,
				Compliance:   rule.Compliance,
				EvaluatedAt:  time.Now(),
				Metadata:     rule.Metadata,
			}
			if finding.Category == "" {
				finding.Category = model.CategorySecurity
			}
			if finding.Title == "" {
				finding.Title = rule.ID
			}
			results = append(results, finding)
		}
	}

	return results
}

func (e *Engine) evaluateCondition(rule Rule, ctx ResourceContext) (bool, error) {
	// 1. Structured Conditions
	if rule.Conditions != nil {
		return evaluateStructuredCondition(rule.Conditions, ctx)
	}

	// 2. String Expression condition: e.g. "tags.Environment in ['prod', 'stage']"
	if exprStr, ok := rule.Condition.(string); ok && exprStr != "" {
		return evaluateStringExpression(exprStr, ctx)
	}

	// 3. Map condition: e.g. { field: "tags.Environment", op: "==", value: "production" }
	if condMap, ok := rule.Condition.(map[string]interface{}); ok {
		field, _ := condMap["field"].(string)
		op, _ := condMap["op"].(string)
		val := condMap["value"]
		return evaluateOp(field, op, val, ctx)
	}

	return true, nil
}

func evaluateStructuredCondition(sc *StructuredCondition, ctx ResourceContext) (bool, error) {
	if sc == nil {
		return true, nil
	}

	// AND logic: all nodes must be true
	for _, node := range sc.And {
		res, err := evaluateNode(node, ctx)
		if err != nil || !res {
			return false, err
		}
	}

	// OR logic: at least one node must be true
	if len(sc.Or) > 0 {
		matchedOr := false
		for _, node := range sc.Or {
			res, err := evaluateNode(node, ctx)
			if err == nil && res {
				matchedOr = true
				break
			}
		}
		if !matchedOr {
			return false, nil
		}
	}

	// NOT logic
	if sc.Not != nil {
		res, err := evaluateNode(sc.Not, ctx)
		if err != nil {
			return false, err
		}
		return !res, nil
	}

	return true, nil
}

func evaluateNode(node *ConditionNode, ctx ResourceContext) (bool, error) {
	if node == nil {
		return true, nil
	}
	if node.Field != "" {
		return evaluateOp(node.Field, node.Op, node.Value, ctx)
	}
	if len(node.And) > 0 {
		for _, sub := range node.And {
			res, err := evaluateNode(sub, ctx)
			if err != nil || !res {
				return false, err
			}
		}
		return true, nil
	}
	if len(node.Or) > 0 {
		for _, sub := range node.Or {
			res, err := evaluateNode(sub, ctx)
			if err == nil && res {
				return true, nil
			}
		}
		return false, nil
	}
	if node.Not != nil {
		res, err := evaluateNode(node.Not, ctx)
		if err != nil {
			return false, err
		}
		return !res, nil
	}
	return true, nil
}

// evaluateStringExpression parses and evaluates expressions such as:
// "tags.Retention in ['30d', '90d', '365d']" or "tags.Env == 'prod'"
func evaluateStringExpression(expr string, ctx ResourceContext) (bool, error) {
	expr = strings.TrimSpace(expr)

	// Check for ' in ' or ' not in '
	if idx := strings.Index(expr, " not in "); idx != -1 {
		field := strings.TrimSpace(expr[:idx])
		valList := strings.TrimSpace(expr[idx+8:])
		return evaluateOp(field, "not_in", parseSlice(valList), ctx)
	}
	if idx := strings.Index(expr, " in "); idx != -1 {
		field := strings.TrimSpace(expr[:idx])
		valList := strings.TrimSpace(expr[idx+4:])
		return evaluateOp(field, "in", parseSlice(valList), ctx)
	}

	// Check for ==, !=, >=, <=, >, <
	ops := []string{"==", "!=", ">=", "<=", ">", "<"}
	for _, op := range ops {
		if idx := strings.Index(expr, " "+op+" "); idx != -1 {
			field := strings.TrimSpace(expr[:idx])
			val := strings.TrimSpace(expr[idx+len(op)+2:])
			return evaluateOp(field, op, trimQuotes(val), ctx)
		}
	}

	return false, fmt.Errorf("unrecognized expression syntax: %s", expr)
}

func parseSlice(raw string) []string {
	raw = strings.Trim(strings.TrimSpace(raw), "[]")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		res = append(res, trimQuotes(strings.TrimSpace(p)))
	}
	return res
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func getFieldValue(field string, ctx ResourceContext) interface{} {
	// Handle tags lookup: tags.Key or resource.tags['Key']
	if strings.HasPrefix(field, "tags.") {
		key := strings.TrimPrefix(field, "tags.")
		if ctx.Tags != nil {
			return ctx.Tags[key]
		}
		return ""
	}
	if strings.HasPrefix(field, "resource.tags[") {
		key := strings.Trim(strings.TrimPrefix(field, "resource.tags["), "']\"")
		if ctx.Tags != nil {
			return ctx.Tags[key]
		}
		return ""
	}

	switch strings.ToLower(field) {
	case "id", "resource_id", "resourceid":
		return ctx.ResourceID
	case "type", "resource_type", "resourcetype":
		return ctx.ResourceType
	case "region":
		return ctx.Region
	default:
		if ctx.Properties != nil {
			return ctx.Properties[field]
		}
		return nil
	}
}

func evaluateOp(field, op string, expectedVal interface{}, ctx ResourceContext) (bool, error) {
	actualVal := getFieldValue(field, ctx)

	switch strings.ToLower(op) {
	case "==", "eq", "equals":
		return fmt.Sprintf("%v", actualVal) == fmt.Sprintf("%v", expectedVal), nil
	case "!=", "neq", "not_equals":
		return fmt.Sprintf("%v", actualVal) != fmt.Sprintf("%v", expectedVal), nil
	case "in":
		return sliceContains(expectedVal, actualVal), nil
	case "not_in", "not in":
		return !sliceContains(expectedVal, actualVal), nil
	case "contains":
		actStr := fmt.Sprintf("%v", actualVal)
		expStr := fmt.Sprintf("%v", expectedVal)
		return strings.Contains(actStr, expStr), nil
	case "exists":
		return actualVal != nil && fmt.Sprintf("%v", actualVal) != "", nil
	case "empty":
		return actualVal == nil || fmt.Sprintf("%v", actualVal) == "", nil
	case ">", ">=", "<", "<=":
		return compareNumeric(actualVal, expectedVal, op)
	default:
		return false, fmt.Errorf("unknown operator: %s", op)
	}
}

func sliceContains(container, target interface{}) bool {
	tgtStr := fmt.Sprintf("%v", target)
	switch v := container.(type) {
	case []string:
		for _, item := range v {
			if strings.EqualFold(item, tgtStr) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if strings.EqualFold(fmt.Sprintf("%v", item), tgtStr) {
				return true
			}
		}
	}
	return false
}

func compareNumeric(actual, expected interface{}, op string) (bool, error) {
	actFloat, err1 := toFloat(actual)
	expFloat, err2 := toFloat(expected)
	if err1 != nil || err2 != nil {
		return false, fmt.Errorf("numeric comparison failed: %v %s %v", actual, op, expected)
	}

	switch op {
	case ">":
		return actFloat > expFloat, nil
	case ">=":
		return actFloat >= expFloat, nil
	case "<":
		return actFloat < expFloat, nil
	case "<=":
		return actFloat <= expFloat, nil
	default:
		return false, nil
	}
}

func toFloat(val interface{}) (float64, error) {
	if val == nil {
		return 0, fmt.Errorf("nil value")
	}
	switch v := val.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(v), 64)
	default:
		return 0, fmt.Errorf("unsupported type: %v", reflect.TypeOf(val))
	}
}
