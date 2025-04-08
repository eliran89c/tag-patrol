package types

// TagType represents the data type of a tag value
type TagType string

const (
	// TagTypeString represents a string tag value type
	TagTypeString TagType = "string"
	// TagTypeBool represents a boolean tag value type
	TagTypeBool TagType = "bool"
	// TagTypeInt represents an integer tag value type
	TagTypeInt TagType = "int"
)

// TagPolicy defines the rules for tag compliance including mandatory keys, validations, and rules
type TagPolicy struct {
	MandatoryKeys []string               `yaml:"mandatoryKeys" validate:"omitempty,dive,required"`
	Validations   map[string]*Validation `yaml:"validations" validate:"omitempty,dive"`
	Rules         []*Rule                `yaml:"rules" validate:"omitempty,dive"`
}

// Policy represents the top-level policy configuration for resource tagging
type Policy struct {
	Blueprints map[string]*Blueprint                 `yaml:"blueprints" validate:"omitempty,dive"`
	Resources  map[string]map[string]*ResourceConfig `yaml:"resources" validate:"required,min=1,dive,keys,required,endkeys,dive"`
}

// Blueprint defines a reusable tag policy template that can be extended by specific resources
type Blueprint struct {
	*TagPolicy `yaml:",inline" validate:"required"`
}

// ResourceConfig defines the tag policy configuration for a specific resource type
type ResourceConfig struct {
	*TagPolicy `yaml:",inline" validate:"omitempty"`
	Extends    []string `yaml:"extends,omitempty" validate:"omitempty,dive,extends_format"`
}

// Validation defines validation rules for a specific tag
type Validation struct {
	Type          TagType  `yaml:"type" validate:"required,oneof=bool string int"`
	AllowedValues []string `yaml:"allowedValues,omitempty" validate:"omitempty,dive,required"`
	Regex         string   `yaml:"regex,omitempty" validate:"omitempty,valid_regex"`
	MinValue      int      `yaml:"minValue,omitempty"`
	MaxValue      int      `yaml:"maxValue,omitempty" validate:"omitempty,gtecsfield=MinValue"`
}

// Rule defines a conditional rule for tag compliance
type Rule struct {
	When *Condition `yaml:"when" validate:"required"`
	Then *Action    `yaml:"then" validate:"required"`
}

// Condition defines a condition for a tag rule
type Condition struct {
	Exists      *ExistsCondition   `yaml:"exists,omitempty" validate:"omitempty"`
	Equals      *EqualsCondition   `yaml:"equals,omitempty" validate:"omitempty"`
	NotEquals   *EqualsCondition   `yaml:"notEquals,omitempty" validate:"omitempty"`
	Contains    *ContainsCondition `yaml:"contains,omitempty" validate:"omitempty"`
	GreaterThan *NumericCondition  `yaml:"greaterThan,omitempty" validate:"omitempty"`
	LessThan    *NumericCondition  `yaml:"lessThan,omitempty" validate:"omitempty"`
	And         []*Condition       `yaml:"and,omitempty" validate:"omitempty,min=1,dive"`
	Or          []*Condition       `yaml:"or,omitempty" validate:"omitempty,min=1,dive"`
}

// ExistsCondition checks if a tag key exists
type ExistsCondition struct {
	Key string `yaml:"key" validate:"required"`
}

// EqualsCondition checks if a tag value equals a specified value
type EqualsCondition struct {
	Key   string `yaml:"key" validate:"required"`
	Value any    `yaml:"value" validate:"required"`
}

// ContainsCondition checks if a tag value contains a specified substring
type ContainsCondition struct {
	Key   string `yaml:"key" validate:"required"`
	Value string `yaml:"value" validate:"required"`
}

// NumericCondition checks if a tag value satisfies a numeric condition
type NumericCondition struct {
	Key   string  `yaml:"key" validate:"required"`
	Value float64 `yaml:"value" validate:"required"`
}

// Action defines the actions to take when a condition is met
type Action struct {
	MustContainKeys   []string `yaml:"mustContainKeys,omitempty" validate:"omitempty,dive,required"`
	ShouldContainKeys []string `yaml:"shouldContainKeys,omitempty" validate:"omitempty,dive,required"`
	Warn              string   `yaml:"warn,omitempty"`
	Error             string   `yaml:"error,omitempty"`
}

// ResourceDefinition represents a fully processed resource type with its complete tag policy
type ResourceDefinition struct {
	Service      string
	ResourceType string
	*TagPolicy
}
