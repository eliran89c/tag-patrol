package ruler

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"slices"

	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
	ptypes "github.com/eliran89c/tag-patrol/pkg/policy/types"
)

// DefaultRuler implements the rule validation logic for resource tags
type DefaultRuler struct{}

// NewRuler creates a new DefaultRuler instance
func NewRuler() *DefaultRuler {
	return &DefaultRuler{}
}

// ValidateAll validates all resources against the provided tag policy and returns counts of compliant and non-compliant resources
func (r *DefaultRuler) ValidateAll(resources []cr.CloudResource, policy *ptypes.TagPolicy) (int, int) {
	compliant := 0
	nonCompliant := 0

	for _, resource := range resources {
		r.Validate(resource, policy)

		if resource.IsCompliant() {
			compliant++
		} else {
			nonCompliant++
		}
	}

	return compliant, nonCompliant
}

// Validate applies all tag policy rules to a single resource
func (r *DefaultRuler) Validate(resource cr.CloudResource, policy *ptypes.TagPolicy) {
	r.validateMandatoryKeys(resource, policy.MandatoryKeys)
	r.validateTagValues(resource, policy.Validations)
	r.applyRules(resource, policy.Rules)
}

func (r *DefaultRuler) validateMandatoryKeys(resource cr.CloudResource, keys []string) {
	for _, key := range keys {
		if _, exists := resource.Tags()[key]; !exists {
			resource.AddComplianceError(fmt.Sprintf("Missing mandatory tag: `%s`", key))
		}
	}
}

func (r *DefaultRuler) validateTagValues(resource cr.CloudResource, validations map[string]*ptypes.Validation) {
	for key, validation := range validations {
		value, exists := resource.Tags()[key]
		if !exists {
			continue
		}

		switch validation.Type {
		case ptypes.TagTypeString:
			r.validateString(resource, key, value, validation)
		case ptypes.TagTypeBool:
			r.validateBool(resource, key, value)
		case ptypes.TagTypeInt:
			r.validateInt(resource, key, value, validation)
		}
	}
}

func (r *DefaultRuler) validateString(resource cr.CloudResource, key, value string, validation *ptypes.Validation) {
	if len(validation.AllowedValues) > 0 {
		valid := slices.Contains(validation.AllowedValues, value)

		if !valid {
			resource.AddComplianceError(fmt.Sprintf("Tag `%s` has value `%s` which is not in allowed values: `%s`", key, value, strings.Join(validation.AllowedValues, ", ")))
		}
	}

	if validation.Regex != "" {
		regex, err := regexp.Compile(validation.Regex)
		if err == nil && !regex.MatchString(value) {
			resource.AddComplianceError(fmt.Sprintf("Tag `%s` with value `%s` does not match regex: `%s`", key, value, validation.Regex))
		}
	}
}

func (r *DefaultRuler) validateBool(resource cr.CloudResource, key, value string) {
	valid := slices.Contains([]string{"true", "false"}, value)

	if !valid {
		resource.AddComplianceError(fmt.Sprintf("Tag `%s` has value `%s` which is not a valid boolean", key, value))
	}
}

func (r *DefaultRuler) validateInt(resource cr.CloudResource, key, value string, validation *ptypes.Validation) {
	intVal, err := strconv.Atoi(value)
	if err != nil {
		resource.AddComplianceError(fmt.Sprintf("Tag `%s` has value `%s` which is not a valid integer", key, value))
		return
	}

	if validation.MinValue != 0 && intVal < validation.MinValue {
		resource.AddComplianceError(fmt.Sprintf("Tag `%s` has value `%d` which is less than minimum: %d", key, intVal, validation.MinValue))
	}

	if validation.MaxValue != 0 && intVal > validation.MaxValue {
		resource.AddComplianceError(fmt.Sprintf("Tag `%s` has value `%d` which is greater than maximum: %d", key, intVal, validation.MaxValue))
	}

	if len(validation.AllowedValues) > 0 {
		if !slices.Contains(validation.AllowedValues, value) {
			resource.AddComplianceError(fmt.Sprintf("Tag `%s` has value `%s` which is not in allowed values: `%s`", key, value, strings.Join(validation.AllowedValues, ", ")))
		}
	}
}

func (r *DefaultRuler) applyRules(resource cr.CloudResource, rules []*ptypes.Rule) {
	for _, rule := range rules {
		if r.evaluateCondition(resource, rule.When) {
			r.applyAction(resource, rule.Then)
		}
	}
}

func (r *DefaultRuler) evaluateCondition(resource cr.CloudResource, condition *ptypes.Condition) bool {
	if condition == nil {
		return false
	}

	if condition.Exists != nil {
		_, exists := resource.Tags()[condition.Exists.Key]
		return exists
	}

	if condition.Equals != nil {
		value, exists := resource.Tags()[condition.Equals.Key]
		if !exists {
			return false
		}
		strValue := fmt.Sprintf("%v", condition.Equals.Value)
		return value == strValue
	}

	if condition.NotEquals != nil {
		value, exists := resource.Tags()[condition.NotEquals.Key]
		if !exists {
			return true // If the key doesn't exist, it's not equal
		}
		strValue := fmt.Sprintf("%v", condition.NotEquals.Value)
		return value != strValue
	}

	if condition.Contains != nil {
		value, exists := resource.Tags()[condition.Contains.Key]
		if !exists {
			return false
		}
		return strings.Contains(value, condition.Contains.Value)
	}

	if condition.GreaterThan != nil {
		value, exists := resource.Tags()[condition.GreaterThan.Key]
		if !exists {
			return false
		}
		numValue, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}
		return numValue > condition.GreaterThan.Value
	}

	if condition.LessThan != nil {
		value, exists := resource.Tags()[condition.LessThan.Key]
		if !exists {
			return false
		}
		numValue, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}
		return numValue < condition.LessThan.Value
	}

	if condition.And != nil && len(condition.And) > 0 {
		for _, subCondition := range condition.And {
			if !r.evaluateCondition(resource, subCondition) {
				return false
			}
		}
		return true
	}

	if condition.Or != nil && len(condition.Or) > 0 {
		for _, subCondition := range condition.Or {
			if r.evaluateCondition(resource, subCondition) {
				return true
			}
		}
		return false
	}

	return false
}

func (r *DefaultRuler) applyAction(resource cr.CloudResource, action *ptypes.Action) {
	if action == nil {
		return
	}

	if action.MustContainKeys != nil {
		for _, key := range action.MustContainKeys {
			if _, exists := resource.Tags()[key]; !exists {
				resource.AddComplianceError(fmt.Sprintf("Missing required tag `%s` based on rule condition", key))
			}
		}
	}

	if action.ShouldContainKeys != nil {
		for _, key := range action.ShouldContainKeys {
			if _, exists := resource.Tags()[key]; !exists {
				resource.AddComplianceWarning(fmt.Sprintf("Missing recommended tag `%s` based on rule condition", key))
			}
		}
	}

	if action.Error != "" {
		resource.AddComplianceError(action.Error)
	}

	if action.Warn != "" {
		resource.AddComplianceWarning(action.Warn)
	}
}
