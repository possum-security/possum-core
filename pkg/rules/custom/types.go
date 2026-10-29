package custom

import (
	"github.com/amirmahdy/possum-core/pkg/model"
)

// ConditionNode represents a structured condition rule in declarative YAML policies.
type ConditionNode struct {
	Field string           `yaml:"field,omitempty" json:"field,omitempty"`
	Op    string           `yaml:"op,omitempty" json:"op,omitempty"`
	Value interface{}      `yaml:"value,omitempty" json:"value,omitempty"`
	And   []*ConditionNode `yaml:"and,omitempty" json:"and,omitempty"`
	Or    []*ConditionNode `yaml:"or,omitempty" json:"or,omitempty"`
	Not   *ConditionNode   `yaml:"not,omitempty" json:"not,omitempty"`
}

// StructuredCondition defines nested boolean logic for structured rule definitions.
type StructuredCondition struct {
	And []*ConditionNode `yaml:"and,omitempty" json:"and,omitempty"`
	Or  []*ConditionNode `yaml:"or,omitempty" json:"or,omitempty"`
	Not *ConditionNode   `yaml:"not,omitempty" json:"not,omitempty"`
}

// Rule defines a declarative policy check evaluated against cloud resources or scan results.
type Rule struct {
	ID           string                 `yaml:"id" json:"id"`
	Name         string                 `yaml:"name" json:"name"`
	Service      string                 `yaml:"service" json:"service"`
	Severity     model.Severity         `yaml:"severity" json:"severity"`
	Category     model.Category         `yaml:"category,omitempty" json:"category,omitempty"`
	ResourceType string                 `yaml:"resource_type" json:"resource_type"`
	Condition    interface{}            `yaml:"condition,omitempty" json:"condition,omitempty"`
	Conditions   *StructuredCondition   `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Mode         string                 `yaml:"mode,omitempty" json:"mode,omitempty"` // "assert" (default, must be true to pass) or "violate" (true indicates violation)
	Message      string                 `yaml:"message" json:"message"`
	Remediation  string                 `yaml:"remediation" json:"remediation"`
	Compliance   []string               `yaml:"compliance,omitempty" json:"compliance,omitempty"`
	Metadata     map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}
