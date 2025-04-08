package policy

import (
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

func registerCustomTranslations(validate *validator.Validate, t ut.Translator) {
	validate.RegisterTranslation("extends_format", t,
		func(ut ut.Translator) error {
			return ut.Add("extends_format", "'{0}' must be in the format 'blueprints.name'.", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("extends_format", fe.Value().(string))
			return t
		},
	)

	validate.RegisterTranslation("valid_regex", t,
		func(ut ut.Translator) error {
			return ut.Add("valid_regex", "Field '{0}' must contain a valid Go regular expression.", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("valid_regex", fe.Field())
			return t
		},
	)

	validate.RegisterTranslation("no_extras_for_bool", t,
		func(ut ut.Translator) error {
			return ut.Add("no_extras_for_bool", "Field '{0}' is not applicable when Type is 'bool'.", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("no_extras_for_bool", fe.Field())
			return t
		},
	)

	validate.RegisterTranslation("only_int_supports_minmax", t,
		func(ut ut.Translator) error {
			return ut.Add("only_int_supports_minmax", "Field '{0}' is only applicable when Type is 'int' (current type: '{1}').", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("only_int_supports_minmax", fe.Field(), fe.Param())
			return t
		},
	)

	validate.RegisterTranslation("allowedvalues_for_int_or_str_only", t,
		func(ut ut.Translator) error {
			return ut.Add("allowedvalues_for_int_or_str_only", "Field '{0}' is only applicable when Type is 'int' or 'string' (current type: '{1}').", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("allowedvalues_for_int_or_str_only", fe.Field(), fe.Param())
			return t
		},
	)

	validate.RegisterTranslation("regex_for_str_only", t,
		func(ut ut.Translator) error {
			return ut.Add("regex_for_str_only", "Field '{0}' is only applicable when Type is 'string' (current type: '{1}').", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("regex_for_str_only", fe.Field(), fe.Param())
			return t
		},
	)

	validate.RegisterTranslation("regex_xor_allowedvalues", t,
		func(ut ut.Translator) error {
			return ut.Add("regex_xor_allowedvalues", "Cannot specify both Regex and AllowedValues.", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("regex_xor_allowedvalues")
			return t
		},
	)

	validate.RegisterTranslation("exactly_one_condition_type", t,
		func(ut ut.Translator) error {
			return ut.Add("exactly_one_condition_type", "A Condition must specify exactly one operator (e.g., exists, equals, and, or).", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("exactly_one_condition_type")
			return t
		},
	)

	validate.RegisterTranslation("blueprint_exists", t,
		func(ut ut.Translator) error {
			return ut.Add("blueprint_exists", "Blueprint '{0}' referenced in '{1}' does not exist in the 'blueprints' section.", true)
		},
		func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("blueprint_exists", fe.Field(), fe.Param())
			return t
		},
	)
}
