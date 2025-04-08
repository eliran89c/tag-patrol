package policy

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/eliran89c/tag-patrol/pkg/policy/types"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

var (
	validate *validator.Validate
	uni      *ut.UniversalTranslator
	trans    ut.Translator
)

// ParserErrors represents a collection of policy validation errors
type ParserErrors struct {
	Messages []string
}

func init() {
	validate = validator.New()

	enLocale := en.New()
	uni = ut.New(enLocale, enLocale)
	trans, _ = uni.GetTranslator("en")

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		yamlTag := fld.Tag.Get("yaml")

		if yamlTag == "" {
			return fld.Name
		}

		parts := strings.SplitN(yamlTag, ",", 2)
		name := parts[0]

		if name == "-" {
			return fld.Name
		}

		return name
	})

	en_translations.RegisterDefaultTranslations(validate, trans)

	validate.RegisterValidation("extends_format", validateExtendsFormat)
	validate.RegisterValidation("valid_regex", validateRegexCompilation)

	validate.RegisterStructValidation(ValidateValidationStruct, types.Validation{})
	validate.RegisterStructValidation(ValidateConditionStruct, types.Condition{})
	validate.RegisterStructValidation(ValidatePolicyStruct, types.Policy{})

	registerCustomTranslations(validate, trans)
}

func validateExtendsFormat(fl validator.FieldLevel) bool {
	extend := fl.Field().String()
	if extend == "" {
		return false
	}
	parts := strings.Split(extend, ".")
	if len(parts) != 2 {
		return false
	}
	return len(parts) == 2 && parts[0] == "blueprints" && parts[1] != ""
}

func validateRegexCompilation(fl validator.FieldLevel) bool {
	regex := fl.Field().String()
	if regex == "" {
		return true
	}
	_, err := regexp.Compile(regex)
	return err == nil
}

// ValidateValidationStruct validates the Validation struct for internal consistency
func ValidateValidationStruct(sl validator.StructLevel) {
	v := sl.Current().Interface().(types.Validation)
	if v.Type == types.TagTypeBool {
		if v.MinValue != 0 {
			sl.ReportError(v.MinValue, "MinValue", "minValue", "no_extras_for_bool", "")
		}
		if v.MaxValue != 0 {
			sl.ReportError(v.MaxValue, "MaxValue", "maxValue", "no_extras_for_bool", "")
		}
		if len(v.AllowedValues) > 0 {
			sl.ReportError(v.AllowedValues, "AllowedValues", "allowedValues", "no_extras_for_bool", "")
		}
		if v.Regex != "" {
			sl.ReportError(v.Regex, "Regex", "regex", "no_extras_for_bool", "")
		}
	}
	if v.Type != types.TagTypeInt {
		if v.MinValue != 0 {
			sl.ReportError(v.MinValue, "MinValue", "minValue", "only_int_supports_minmax", string(v.Type))
		}
		if v.MaxValue != 0 {
			sl.ReportError(v.MaxValue, "MaxValue", "maxValue", "only_int_supports_minmax", string(v.Type))
		}
	}
	if v.Type != types.TagTypeInt && v.Type != types.TagTypeString && len(v.AllowedValues) > 0 {
		sl.ReportError(v.AllowedValues, "AllowedValues", "allowedValues", "allowedvalues_for_int_or_str_only", string(v.Type))
	}
	if v.Type != types.TagTypeString && v.Regex != "" {
		sl.ReportError(v.Regex, "Regex", "regex", "regex_for_str_only", string(v.Type))
	}
	if v.Regex != "" && len(v.AllowedValues) > 0 {
		sl.ReportError(v.AllowedValues, "AllowedValues", "allowedValues", "regex_xor_allowedvalues", "")
	}
}

// ValidateConditionStruct validates the Condition struct to ensure exactly one condition type is specified
func ValidateConditionStruct(sl validator.StructLevel) {
	condition := sl.Current().Interface().(types.Condition)
	count := 0
	if condition.Exists != nil {
		count++
	}
	if condition.Equals != nil {
		count++
	}
	if condition.NotEquals != nil {
		count++
	}
	if condition.Contains != nil {
		count++
	}
	if condition.GreaterThan != nil {
		count++
	}
	if condition.LessThan != nil {
		count++
	}
	if len(condition.And) > 0 {
		count++
	}
	if len(condition.Or) > 0 {
		count++
	}
	if count != 1 {
		sl.ReportError(condition, "Condition", "condition", "exactly_one_condition_type", "")
	}
}

// ValidatePolicyStruct validates the overall Policy struct for correctness
func ValidatePolicyStruct(sl validator.StructLevel) {
	policy := sl.Current().Interface().(types.Policy)
	if policy.Resources == nil {
		sl.ReportError(policy.Resources, "Resources", "resources", "required", "")
	}

	for sname, serviceResources := range policy.Resources {
		if serviceResources != nil {
			for rname, resourceConfig := range serviceResources {
				if resourceConfig != nil && len(resourceConfig.Extends) > 0 {
					for i, extendName := range resourceConfig.Extends {
						if extendName == "" {
							continue
						}

						parts := strings.Split(extendName, ".")
						if len(parts) != 2 {
							// will be caught by the extends_format validation
							continue
						}

						name := parts[1]

						blueprintExists := false
						if policy.Blueprints != nil {
							_, blueprintExists = policy.Blueprints[name]
						}

						if !blueprintExists {
							sl.ReportError(resourceConfig.Extends[i], name, "extends", "blueprint_exists", fmt.Sprintf("%v.%v", sname, rname))
						}
					}
				}
			}
		} else {
			sl.ReportError(serviceResources, "ResourceType", "resources", "required", "")
		}
	}
}

// ValidatePolicy validates a Policy instance and returns any validation errors
func ValidatePolicy(policy *types.Policy) error {
	err := validate.Struct(policy)
	if err == nil {
		return nil
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return fmt.Errorf("unexpected error during validation: %w", err)
	}

	translatedErrors := make([]string, 0, len(validationErrors))
	for _, e := range validationErrors {
		translatedErrors = append(translatedErrors, e.Translate(trans))
	}

	if len(translatedErrors) > 0 {
		return &ParserErrors{Messages: translatedErrors}
	}

	return nil
}

// Error returns a formatted string of all validation errors
func (e *ParserErrors) Error() string {
	return fmt.Sprintf("%d validation error(s) occurred:\n- %s",
		len(e.Messages),
		strings.Join(e.Messages, "\n- "))
}
