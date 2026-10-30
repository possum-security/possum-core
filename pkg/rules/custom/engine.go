package custom

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/possum-security/possum-core/pkg/model"
	"gopkg.in/yaml.v3"
)

// Engine evaluates declarative policy rules against scan results and resource properties.
type Engine struct {
	rules      []Rule
	lastErrors []error
}

// NewEngine creates a new custom policy engine with optional initial rules.
func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: rules}
}

// AddRule registers a declarative rule.
func (e *Engine) AddRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

// RegisterRule validates and registers a declarative rule, returning any validation error.
func (e *Engine) RegisterRule(rule Rule) error {
	if err := ValidateRule(rule); err != nil {
		return err
	}
	e.rules = append(e.rules, rule)
	return nil
}

// Rules returns all currently registered rules.
func (e *Engine) Rules() []Rule {
	return e.rules
}

// LastErrors returns any evaluation errors encountered during the most recent EvaluateContext call.
func (e *Engine) LastErrors() []error {
	return e.lastErrors
}

// ValidateRule validates a custom rule's metadata, expressions, and structured conditions.
func ValidateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("custom rule requires non-empty 'id'")
	}
	if rule.Mode != "" && !strings.EqualFold(rule.Mode, "assert") && !strings.EqualFold(rule.Mode, "violate") {
		return fmt.Errorf("rule %s: invalid mode %q (expected 'assert' or 'violate')", rule.ID, rule.Mode)
	}
	if rule.Conditions != nil {
		if err := validateStructuredCondition(rule.Conditions); err != nil {
			return fmt.Errorf("rule %s: %w", rule.ID, err)
		}
	}
	if rule.Condition != nil {
		switch cond := rule.Condition.(type) {
		case string:
			if strings.TrimSpace(cond) == "" {
				return fmt.Errorf("rule %s: condition expression cannot be empty", rule.ID)
			}
			if _, err := compileExpression(cond); err != nil {
				return fmt.Errorf("rule %s: invalid condition expression %q: %w", rule.ID, cond, err)
			}
		case map[string]interface{}:
			field, _ := cond["field"].(string)
			op, _ := cond["op"].(string)
			if strings.TrimSpace(field) == "" {
				return fmt.Errorf("rule %s: map condition requires non-empty 'field'", rule.ID)
			}
			if !isValidOp(op) {
				return fmt.Errorf("rule %s: unknown operator %q", rule.ID, op)
			}
		default:
			return fmt.Errorf("rule %s: unsupported condition type %T", rule.ID, rule.Condition)
		}
	}
	return nil
}

func validateStructuredCondition(sc *StructuredCondition) error {
	if sc == nil {
		return nil
	}
	if len(sc.And) == 0 && len(sc.Or) == 0 && sc.Not == nil {
		return fmt.Errorf("structured conditions block cannot be empty")
	}
	for _, n := range sc.And {
		if err := validateConditionNode(n); err != nil {
			return err
		}
	}
	for _, n := range sc.Or {
		if err := validateConditionNode(n); err != nil {
			return err
		}
	}
	if sc.Not != nil {
		if err := validateConditionNode(sc.Not); err != nil {
			return err
		}
	}
	return nil
}

func validateConditionNode(node *ConditionNode) error {
	if node == nil {
		return fmt.Errorf("condition node cannot be nil")
	}
	if node.Field != "" {
		if _, err := parseFieldPath(node.Field); err != nil {
			return fmt.Errorf("invalid field path %q: %w", node.Field, err)
		}
		if !isValidOp(node.Op) {
			return fmt.Errorf("unknown operator %q for field %q", node.Op, node.Field)
		}
		return nil
	}
	if len(node.And) == 0 && len(node.Or) == 0 && node.Not == nil {
		return fmt.Errorf("condition node must specify 'field' or boolean combinators ('and', 'or', 'not')")
	}
	for _, sub := range node.And {
		if err := validateConditionNode(sub); err != nil {
			return err
		}
	}
	for _, sub := range node.Or {
		if err := validateConditionNode(sub); err != nil {
			return err
		}
	}
	if node.Not != nil {
		if err := validateConditionNode(node.Not); err != nil {
			return err
		}
	}
	return nil
}

func isValidOp(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "==", "eq", "equals",
		"!=", "neq", "not_equals",
		"in", "not_in", "not in",
		"contains", "startswith", "starts_with", "endswith", "ends_with",
		"exists", "empty",
		">", ">=", "<", "<=":
		return true
	default:
		return false
	}
}

// LoadRule reads and validates a single rule from an io.Reader.
func LoadRule(r io.Reader) (*Rule, error) {
	var rule Rule
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&rule); err != nil {
		return nil, fmt.Errorf("failed to parse custom rule yaml: %w", err)
	}
	if rule.Severity == "" {
		rule.Severity = model.SeverityMedium
	}
	if err := ValidateRule(rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// LoadDirectory scans a directory recursively for .yaml / .yml rule definitions.
// Returns an error if the directory cannot be read or any rule file is invalid.
func (e *Engine) LoadDirectory(dir string) (int, error) {
	if _, err := os.Stat(dir); err != nil {
		return 0, fmt.Errorf("failed to access rules directory %s: %w", dir, err)
	}

	count := 0
	var loadErrs []error

	err := filepath.Walk(dir, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			loadErrs = append(loadErrs, fmt.Errorf("%s: %w", p, walkErr))
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Errorf("failed to open %s: %w", p, err))
			return nil
		}
		defer f.Close()

		rule, err := LoadRule(f)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Errorf("%s: %w", p, err))
			return nil
		}
		e.AddRule(*rule)
		count++
		return nil
	})
	if err != nil {
		loadErrs = append(loadErrs, err)
	}
	if len(loadErrs) > 0 {
		return count, errors.Join(loadErrs...)
	}
	return count, nil
}

// ResourceContext models the evaluation context for a resource under test.
type ResourceContext struct {
	ResourceID   string
	ResourceType string
	Region       string
	Tags         map[string]string
	Properties   map[string]interface{}
}

// Evaluate evaluates all registered rules against a given ResourceContext and returns both findings and any errors.
func (e *Engine) Evaluate(ctx ResourceContext) ([]model.ScanResult, error) {
	var results []model.ScanResult
	var evalErrs []error

	for _, rule := range e.rules {
		if rule.ResourceType != "" && !strings.EqualFold(rule.ResourceType, ctx.ResourceType) && rule.ResourceType != "*" {
			continue
		}

		passed, err := e.evaluateCondition(rule, ctx)
		if err != nil {
			evalErrs = append(evalErrs, fmt.Errorf("rule %s: %w", rule.ID, err))
			continue
		}

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

	e.lastErrors = evalErrs
	if len(evalErrs) > 0 {
		return results, errors.Join(evalErrs...)
	}
	return results, nil
}

// EvaluateContext evaluates all registered rules against a given ResourceContext.
// Any evaluation errors are recorded in e.LastErrors().
func (e *Engine) EvaluateContext(ctx ResourceContext) []model.ScanResult {
	results, _ := e.Evaluate(ctx)
	return results
}

// EvaluateRule evaluates a single rule's condition against a ResourceContext and surfaces errors.
func (e *Engine) EvaluateRule(rule Rule, ctx ResourceContext) (bool, error) {
	if err := ValidateRule(rule); err != nil {
		return false, err
	}
	return e.evaluateCondition(rule, ctx)
}

func (e *Engine) evaluateCondition(rule Rule, ctx ResourceContext) (bool, error) {
	if rule.Conditions != nil {
		return evaluateStructuredCondition(rule.Conditions, ctx)
	}

	if exprStr, ok := rule.Condition.(string); ok {
		if strings.TrimSpace(exprStr) == "" {
			return false, fmt.Errorf("empty condition expression")
		}
		return evaluateStringExpression(exprStr, ctx)
	}

	if condMap, ok := rule.Condition.(map[string]interface{}); ok {
		field, _ := condMap["field"].(string)
		op, _ := condMap["op"].(string)
		val := condMap["value"]
		return evaluateOp(field, op, val, ctx)
	}

	if rule.Condition != nil {
		return false, fmt.Errorf("unsupported condition type %T", rule.Condition)
	}

	return true, nil
}

func evaluateStructuredCondition(sc *StructuredCondition, ctx ResourceContext) (bool, error) {
	if sc == nil {
		return true, nil
	}

	for _, node := range sc.And {
		res, err := evaluateNode(node, ctx)
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
	}

	if len(sc.Or) > 0 {
		matchedOr := false
		for _, node := range sc.Or {
			res, err := evaluateNode(node, ctx)
			if err != nil {
				return false, err
			}
			if res {
				matchedOr = true
				break
			}
		}
		if !matchedOr {
			return false, nil
		}
	}

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
			if err != nil {
				return false, err
			}
			if !res {
				return false, nil
			}
		}
		return true, nil
	}
	if len(node.Or) > 0 {
		for _, sub := range node.Or {
			res, err := evaluateNode(sub, ctx)
			if err != nil {
				return false, err
			}
			if res {
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
	return false, fmt.Errorf("empty condition node")
}

// ============================================================================
// Expression Lexer, Recursive-Descent Parser, and AST Evaluator
// ============================================================================

type tokenType int

const (
	tokEOF tokenType = iota
	tokIdent
	tokString
	tokNumber
	tokDot
	tokComma
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
	tokAnd // &&
	tokOr  // ||
	tokNot // !
	tokOp  // ==, !=, <, <=, >, >=
)

type token struct {
	typ tokenType
	val string
	pos int
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	n := len(input)
	i := 0

	for i < n {
		ch := input[i]
		if unicode.IsSpace(rune(ch)) {
			i++
			continue
		}

		switch ch {
		case '.':
			tokens = append(tokens, token{typ: tokDot, val: ".", pos: i})
			i++
		case ',':
			tokens = append(tokens, token{typ: tokComma, val: ",", pos: i})
			i++
		case '(':
			tokens = append(tokens, token{typ: tokLParen, val: "(", pos: i})
			i++
		case ')':
			tokens = append(tokens, token{typ: tokRParen, val: ")", pos: i})
			i++
		case '[':
			tokens = append(tokens, token{typ: tokLBracket, val: "[", pos: i})
			i++
		case ']':
			tokens = append(tokens, token{typ: tokRBracket, val: "]", pos: i})
			i++
		case '&':
			if i+1 < n && input[i+1] == '&' {
				tokens = append(tokens, token{typ: tokAnd, val: "&&", pos: i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '&' at position %d (use '&&' or 'and')", i)
			}
		case '|':
			if i+1 < n && input[i+1] == '|' {
				tokens = append(tokens, token{typ: tokOr, val: "||", pos: i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '|' at position %d (use '||' or 'or')", i)
			}
		case '!':
			if i+1 < n && input[i+1] == '=' {
				if i+2 < n && input[i+2] == '=' {
					return nil, fmt.Errorf("unsupported operator '!==' at position %d", i)
				}
				tokens = append(tokens, token{typ: tokOp, val: "!=", pos: i})
				i += 2
			} else {
				tokens = append(tokens, token{typ: tokNot, val: "!", pos: i})
				i++
			}
		case '=':
			if i+1 < n && input[i+1] == '=' {
				if i+2 < n && input[i+2] == '=' {
					return nil, fmt.Errorf("unsupported operator '===' at position %d", i)
				}
				tokens = append(tokens, token{typ: tokOp, val: "==", pos: i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '=' at position %d (use '==' for equality)", i)
			}
		case '<':
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, token{typ: tokOp, val: "<=", pos: i})
				i += 2
			} else {
				tokens = append(tokens, token{typ: tokOp, val: "<", pos: i})
				i++
			}
		case '>':
			if i+1 < n && input[i+1] == '=' {
				tokens = append(tokens, token{typ: tokOp, val: ">=", pos: i})
				i += 2
			} else {
				tokens = append(tokens, token{typ: tokOp, val: ">", pos: i})
				i++
			}
		case '\'', '"':
			quote := ch
			start := i
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				if input[i] == '\\' && i+1 < n {
					sb.WriteByte(input[i+1])
					i += 2
					continue
				}
				if input[i] == quote {
					closed = true
					i++
					break
				}
				sb.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unclosed string literal starting at position %d", start)
			}
			tokens = append(tokens, token{typ: tokString, val: sb.String(), pos: start})
		default:
			if unicode.IsDigit(rune(ch)) || (ch == '-' && i+1 < n && unicode.IsDigit(rune(input[i+1]))) {
				start := i
				if ch == '-' {
					i++
				}
				hasDot := false
				for i < n && (unicode.IsDigit(rune(input[i])) || (!hasDot && input[i] == '.')) {
					if input[i] == '.' {
						hasDot = true
					}
					i++
				}
				tokens = append(tokens, token{typ: tokNumber, val: input[start:i], pos: start})
			} else if isIdentStart(ch) {
				start := i
				for i < n && isIdentPart(input[i]) {
					i++
				}
				word := input[start:i]
				switch strings.ToLower(word) {
				case "and":
					tokens = append(tokens, token{typ: tokAnd, val: word, pos: start})
				case "or":
					tokens = append(tokens, token{typ: tokOr, val: word, pos: start})
				default:
					tokens = append(tokens, token{typ: tokIdent, val: word, pos: start})
				}
			} else {
				return nil, fmt.Errorf("unexpected character %q at position %d", ch, i)
			}
		}
	}

	tokens = append(tokens, token{typ: tokEOF, pos: n})
	return tokens, nil
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentPart(ch byte) bool {
	return isIdentStart(ch) || (ch >= '0' && ch <= '9') || ch == '-'
}

type exprNode interface {
	eval(ctx ResourceContext) (bool, error)
}

type binaryBoolExpr struct {
	op    string // "&&" or "||"
	left  exprNode
	right exprNode
}

func (b *binaryBoolExpr) eval(ctx ResourceContext) (bool, error) {
	lv, err := b.left.eval(ctx)
	if err != nil {
		return false, err
	}
	if b.op == "&&" {
		if !lv {
			return false, nil
		}
		return b.right.eval(ctx)
	}
	// "||"
	if lv {
		return true, nil
	}
	return b.right.eval(ctx)
}

type notBoolExpr struct {
	inner exprNode
}

func (n *notBoolExpr) eval(ctx ResourceContext) (bool, error) {
	v, err := n.inner.eval(ctx)
	if err != nil {
		return false, err
	}
	return !v, nil
}

type valueRef struct {
	isField  bool
	segments []string
	literal  interface{}
}

func (v valueRef) resolve(ctx ResourceContext) interface{} {
	if !v.isField {
		return v.literal
	}
	return resolveSegments(v.segments, ctx)
}

type comparisonExpr struct {
	left  valueRef
	op    string
	right valueRef
}

func (c *comparisonExpr) eval(ctx ResourceContext) (bool, error) {
	actual := c.left.resolve(ctx)
	expected := c.right.resolve(ctx)
	return evaluateValuesOp(actual, c.op, expected)
}

type methodCallExpr struct {
	target valueRef
	method string
	arg    interface{}
}

func (m *methodCallExpr) eval(ctx ResourceContext) (bool, error) {
	actual := m.target.resolve(ctx)
	switch strings.ToLower(m.method) {
	case "contains":
		if actual == nil {
			return false, nil
		}
		switch v := actual.(type) {
		case []string:
			return sliceContains(v, m.arg), nil
		case []interface{}:
			return sliceContains(v, m.arg), nil
		default:
			return strings.Contains(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", m.arg)), nil
		}
	case "startswith", "starts_with":
		if actual == nil {
			return false, nil
		}
		return strings.HasPrefix(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", m.arg)), nil
	case "endswith", "ends_with":
		if actual == nil {
			return false, nil
		}
		return strings.HasSuffix(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", m.arg)), nil
	case "exists":
		return actual != nil && fmt.Sprintf("%v", actual) != "", nil
	case "isempty", "empty":
		return actual == nil || fmt.Sprintf("%v", actual) == "", nil
	default:
		return false, fmt.Errorf("unknown method: %s", m.method)
	}
}

type truthyFieldExpr struct {
	ref valueRef
}

func (t *truthyFieldExpr) eval(ctx ResourceContext) (bool, error) {
	val := t.ref.resolve(ctx)
	if val == nil {
		return false, nil
	}
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		trimmed := strings.TrimSpace(v)
		if strings.EqualFold(trimmed, "true") {
			return true, nil
		}
		if strings.EqualFold(trimmed, "false") || trimmed == "" {
			return false, nil
		}
		return true, nil
	default:
		return true, nil
	}
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	tok := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return tok
}

func compileExpression(expr string) (exprNode, error) {
	tokens, err := tokenize(expr)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().typ != tokEOF {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.peek().val, p.peek().pos)
	}
	return node, nil
}

func (p *parser) parseOr() (exprNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokOr {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &binaryBoolExpr{op: "||", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (exprNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().typ == tokAnd {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &binaryBoolExpr{op: "&&", left: left, right: right}
	}
	return left, nil
}

func (p *parser) parseUnary() (exprNode, error) {
	tok := p.peek()
	if tok.typ == tokNot || (tok.typ == tokIdent && strings.EqualFold(tok.val, "not")) {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notBoolExpr{inner: inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (exprNode, error) {
	if p.peek().typ == tokLParen {
		openPos := p.next().pos
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().typ != tokRParen {
			return nil, fmt.Errorf("unclosed '(' starting at position %d", openPos)
		}
		p.next()
		return inner, nil
	}

	leftVal, methodNode, err := p.parseValueOrMethod()
	if err != nil {
		return nil, err
	}

	if methodNode != nil {
		// Allow optional `== true` or `== false` or `!= true` after a method call
		if p.peek().typ == tokOp && (p.peek().val == "==" || p.peek().val == "!=") {
			op := p.next().val
			rhs, _, err := p.parseValueOrMethod()
			if err != nil {
				return nil, err
			}
			rhsBool, ok := rhs.literal.(bool)
			if !ok {
				return nil, fmt.Errorf("method comparison requires boolean literal")
			}
			if (op == "==" && !rhsBool) || (op == "!=" && rhsBool) {
				return &notBoolExpr{inner: methodNode}, nil
			}
		}
		return methodNode, nil
	}

	// Check for comparison operators: ==, !=, <, <=, >, >=, in, not in
	nextTok := p.peek()
	if nextTok.typ == tokOp {
		op := p.next().val
		rightVal, rightMethod, err := p.parseValueOrMethod()
		if err != nil {
			return nil, err
		}
		if rightMethod != nil {
			return nil, fmt.Errorf("unexpected method call on right-hand side of %s", op)
		}
		return &comparisonExpr{left: leftVal, op: op, right: rightVal}, nil
	}

	if nextTok.typ == tokIdent && strings.EqualFold(nextTok.val, "in") {
		p.next()
		rightVal, err := p.parseListLiteralOrField()
		if err != nil {
			return nil, err
		}
		return &comparisonExpr{left: leftVal, op: "in", right: rightVal}, nil
	}

	if nextTok.typ == tokIdent && strings.EqualFold(nextTok.val, "not") {
		p.next()
		if p.peek().typ != tokIdent || !strings.EqualFold(p.peek().val, "in") {
			return nil, fmt.Errorf("expected 'in' after 'not' at position %d", p.peek().pos)
		}
		p.next()
		rightVal, err := p.parseListLiteralOrField()
		if err != nil {
			return nil, err
		}
		return &comparisonExpr{left: leftVal, op: "not_in", right: rightVal}, nil
	}

	// Standalone boolean literal or nested field reference (e.g. `properties.encrypted`)
	if !leftVal.isField {
		if _, isBool := leftVal.literal.(bool); isBool {
			return &truthyFieldExpr{ref: leftVal}, nil
		}
		return nil, fmt.Errorf("expected comparison operator after literal %v", leftVal.literal)
	}
	if len(leftVal.segments) < 2 {
		return nil, fmt.Errorf("incomplete expression: %q requires an operator or nested field", strings.Join(leftVal.segments, "."))
	}
	return &truthyFieldExpr{ref: leftVal}, nil
}

func (p *parser) parseValueOrMethod() (valueRef, exprNode, error) {
	tok := p.peek()
	switch tok.typ {
	case tokString:
		p.next()
		return valueRef{isField: false, literal: tok.val}, nil, nil
	case tokNumber:
		p.next()
		if fv, err := strconv.ParseFloat(tok.val, 64); err == nil {
			return valueRef{isField: false, literal: fv}, nil, nil
		}
		return valueRef{}, nil, fmt.Errorf("invalid number %q", tok.val)
	case tokLBracket:
		listRef, err := p.parseListLiteralOrField()
		return listRef, nil, err
	case tokIdent:
		lower := strings.ToLower(tok.val)
		if lower == "true" && p.peekAt(1).typ != tokDot && p.peekAt(1).typ != tokLBracket {
			p.next()
			return valueRef{isField: false, literal: true}, nil, nil
		}
		if lower == "false" && p.peekAt(1).typ != tokDot && p.peekAt(1).typ != tokLBracket {
			p.next()
			return valueRef{isField: false, literal: false}, nil, nil
		}
		if (lower == "null" || lower == "nil") && p.peekAt(1).typ != tokDot && p.peekAt(1).typ != tokLBracket {
			p.next()
			return valueRef{isField: false, literal: nil}, nil, nil
		}

		// Parse field path and optional trailing method call
		segments := []string{p.next().val}
		for {
			if p.peek().typ == tokDot {
				p.next()
				identTok := p.peek()
				if identTok.typ != tokIdent {
					return valueRef{}, nil, fmt.Errorf("expected identifier after '.' at position %d", identTok.pos)
				}
				p.next()
				// Check if this is a method call `.methodName(...)`
				if p.peek().typ == tokLParen {
					p.next() // consume '('
					methodName := identTok.val
					if !isValidMethodName(methodName) {
						return valueRef{}, nil, fmt.Errorf("unknown method %q", methodName)
					}
					var argVal interface{}
					if p.peek().typ != tokRParen {
						argRef, _, err := p.parseValueOrMethod()
						if err != nil {
							return valueRef{}, nil, err
						}
						argVal = argRef.literal
					}
					if p.peek().typ != tokRParen {
						return valueRef{}, nil, fmt.Errorf("expected ')' after arguments to %s", methodName)
					}
					p.next() // consume ')'
					targetRef := valueRef{isField: true, segments: segments}
					return targetRef, &methodCallExpr{
						target: targetRef,
						method: methodName,
						arg:    argVal,
					}, nil
				}
				segments = append(segments, identTok.val)
			} else if p.peek().typ == tokLBracket {
				openPos := p.next().pos // consume '['
				keyTok := p.peek()
				if keyTok.typ != tokString && keyTok.typ != tokNumber && keyTok.typ != tokIdent {
					return valueRef{}, nil, fmt.Errorf("expected key inside '[...]' at position %d", openPos)
				}
				p.next()
				if p.peek().typ != tokRBracket {
					return valueRef{}, nil, fmt.Errorf("unclosed '[' at position %d", openPos)
				}
				p.next() // consume ']'
				segments = append(segments, keyTok.val)
			} else {
				break
			}
		}
		return valueRef{isField: true, segments: segments}, nil, nil
	default:
		return valueRef{}, nil, fmt.Errorf("unexpected token %q at position %d", tok.val, tok.pos)
	}
}

func (p *parser) peekAt(offset int) token {
	idx := p.pos + offset
	if idx >= len(p.tokens) {
		return token{typ: tokEOF}
	}
	return p.tokens[idx]
}

func (p *parser) parseListLiteralOrField() (valueRef, error) {
	if p.peek().typ != tokLBracket {
		return valueRef{}, fmt.Errorf("expected '[' for list at position %d", p.peek().pos)
	}
	openPos := p.next().pos // consume '['
	var items []interface{}
	for p.peek().typ != tokRBracket {
		if p.peek().typ == tokEOF {
			return valueRef{}, fmt.Errorf("unclosed '[' starting at position %d", openPos)
		}
		elem, _, err := p.parseValueOrMethod()
		if err != nil {
			return valueRef{}, err
		}
		items = append(items, elem.literal)
		if p.peek().typ == tokComma {
			p.next()
		} else if p.peek().typ != tokRBracket {
			return valueRef{}, fmt.Errorf("expected ',' or ']' in list at position %d", p.peek().pos)
		}
	}
	p.next() // consume ']'
	return valueRef{isField: false, literal: items}, nil
}

func isValidMethodName(name string) bool {
	switch strings.ToLower(name) {
	case "contains", "startswith", "starts_with", "endswith", "ends_with", "exists", "isempty", "empty":
		return true
	default:
		return false
	}
}

func evaluateStringExpression(expr string, ctx ResourceContext) (bool, error) {
	ast, err := compileExpression(expr)
	if err != nil {
		return false, err
	}
	return ast.eval(ctx)
}

func parseFieldPath(field string) ([]string, error) {
	tokens, err := tokenize(field)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	ref, methodNode, err := p.parseValueOrMethod()
	if err != nil {
		return nil, err
	}
	if methodNode != nil || !ref.isField || p.peek().typ != tokEOF {
		return nil, fmt.Errorf("invalid field path %q", field)
	}
	return ref.segments, nil
}

func getFieldValue(field string, ctx ResourceContext) interface{} {
	segments, err := parseFieldPath(field)
	if err != nil {
		// Fallback for simple direct lookup
		if ctx.Properties != nil {
			if v, ok := ctx.Properties[field]; ok {
				return v
			}
		}
		return nil
	}
	return resolveSegments(segments, ctx)
}

func resolveSegments(segments []string, ctx ResourceContext) interface{} {
	if len(segments) == 0 {
		return nil
	}

	// Strip optional leading "resource" prefix: e.g. resource.tags['env'] -> tags['env']
	if len(segments) > 1 && strings.EqualFold(segments[0], "resource") {
		segments = segments[1:]
	}

	head := strings.ToLower(segments[0])

	if len(segments) == 1 {
		switch head {
		case "id", "resource_id", "resourceid":
			return ctx.ResourceID
		case "type", "resource_type", "resourcetype":
			return ctx.ResourceType
		case "region":
			return ctx.Region
		case "tags":
			return ctx.Tags
		case "properties":
			return ctx.Properties
		default:
			if v, found := lookupInMap(ctx.Properties, segments[0]); found {
				return v
			}
			if ctx.Tags != nil {
				if v, ok := ctx.Tags[segments[0]]; ok {
					return v
				}
			}
			return nil
		}
	}

	if head == "tags" {
		tagKey := segments[1]
		if len(segments) == 2 && ctx.Tags != nil {
			if v, ok := ctx.Tags[tagKey]; ok {
				return v
			}
		}
		if tagsProp, found := lookupInMap(ctx.Properties, "tags"); found {
			return traverseNested(tagsProp, segments[1:])
		}
		return ""
	}

	if head == "properties" {
		return traverseNested(ctx.Properties, segments[1:])
	}

	return traverseNested(ctx.Properties, segments)
}

func traverseNested(curr interface{}, segments []string) interface{} {
	for _, seg := range segments {
		if curr == nil {
			return nil
		}
		switch m := curr.(type) {
		case map[string]interface{}:
			val, found := lookupInMap(m, seg)
			if !found {
				return nil
			}
			curr = val
		case map[string]string:
			if val, ok := m[seg]; ok {
				curr = val
				continue
			}
			matched := false
			for k, v := range m {
				if strings.EqualFold(k, seg) {
					curr = v
					matched = true
					break
				}
			}
			if !matched {
				return nil
			}
		case map[interface{}]interface{}:
			if val, ok := m[seg]; ok {
				curr = val
			} else {
				return nil
			}
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(m) {
				return nil
			}
			curr = m[idx]
		case []string:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(m) {
				return nil
			}
			curr = m[idx]
		default:
			return nil
		}
	}
	return curr
}

func lookupInMap(m map[string]interface{}, key string) (interface{}, bool) {
	if m == nil {
		return nil, false
	}
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func evaluateOp(field, op string, expectedVal interface{}, ctx ResourceContext) (bool, error) {
	if _, err := parseFieldPath(field); err != nil {
		return false, err
	}
	actualVal := getFieldValue(field, ctx)
	return evaluateValuesOp(actualVal, op, expectedVal)
}

func evaluateValuesOp(actualVal interface{}, op string, expectedVal interface{}) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "==", "eq", "equals":
		return valuesEqual(actualVal, expectedVal), nil
	case "!=", "neq", "not_equals":
		return !valuesEqual(actualVal, expectedVal), nil
	case "in":
		return sliceContains(expectedVal, actualVal), nil
	case "not_in", "not in":
		return !sliceContains(expectedVal, actualVal), nil
	case "contains":
		if actualVal == nil {
			return false, nil
		}
		if sliceContains(actualVal, expectedVal) {
			return true, nil
		}
		actStr := fmt.Sprintf("%v", actualVal)
		expStr := fmt.Sprintf("%v", expectedVal)
		return strings.Contains(actStr, expStr), nil
	case "startswith", "starts_with":
		if actualVal == nil {
			return false, nil
		}
		return strings.HasPrefix(fmt.Sprintf("%v", actualVal), fmt.Sprintf("%v", expectedVal)), nil
	case "endswith", "ends_with":
		if actualVal == nil {
			return false, nil
		}
		return strings.HasSuffix(fmt.Sprintf("%v", actualVal), fmt.Sprintf("%v", expectedVal)), nil
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

func valuesEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil {
		return fmt.Sprintf("%v", b) == ""
	}
	if b == nil {
		return fmt.Sprintf("%v", a) == ""
	}
	if af, err1 := toFloat(a); err1 == nil {
		if bf, err2 := toFloat(b); err2 == nil {
			return af == bf
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func sliceContains(container, target interface{}) bool {
	if target == nil {
		return false
	}
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
			if valuesEqual(item, target) || strings.EqualFold(fmt.Sprintf("%v", item), tgtStr) {
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
