package ruler

import (
	"testing"

	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
	"github.com/eliran89c/tag-patrol/pkg/policy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockResource struct {
	id           string
	resourceType string
	service      string
	provider     string
	region       string
	ownerID      string
	tags         map[string]string
	errors       []*cr.ComplianceError
	warnings     []*cr.ComplianceWarning
}

func NewMockResource(id, resourceType, service, provider, region, ownerID string, tags map[string]string) *MockResource {
	return &MockResource{
		id:           id,
		resourceType: resourceType,
		service:      service,
		provider:     provider,
		region:       region,
		ownerID:      ownerID,
		tags:         tags,
		errors:       make([]*cr.ComplianceError, 0),
		warnings:     make([]*cr.ComplianceWarning, 0),
	}
}

func (m *MockResource) ID() string {
	return m.id
}

func (m *MockResource) Type() string {
	return m.resourceType
}

func (m *MockResource) Service() string {
	return m.service
}

func (m *MockResource) Provider() string {
	return m.provider
}

func (m *MockResource) Region() string {
	return m.region
}

func (m *MockResource) OwnerID() string {
	return m.ownerID
}

func (m *MockResource) Tags() map[string]string {
	return m.tags
}

func (m *MockResource) IsCompliant() bool {
	return len(m.errors) == 0
}

func (m *MockResource) AddComplianceError(msg string) {
	m.errors = append(m.errors, &cr.ComplianceError{Message: msg})
}

func (m *MockResource) AddComplianceWarning(msg string) {
	m.warnings = append(m.warnings, &cr.ComplianceWarning{Message: msg})
}

func (m *MockResource) ComplianceErrors() []*cr.ComplianceError {
	return m.errors
}

func (m *MockResource) ComplianceWarnings() []*cr.ComplianceWarning {
	return m.warnings
}

func TestNewRuler(t *testing.T) {
	ruler := NewRuler()
	require.NotNil(t, ruler)
}

func TestValidateMandatoryKeys(t *testing.T) {
	ruler := NewRuler()

	t.Run("All Mandatory Keys Present", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
				"owner":       "team@example.com",
				"cost-center": "CC123",
			},
		)

		mandatoryKeys := []string{"environment", "owner"}

		ruler.validateMandatoryKeys(resource, mandatoryKeys)

		assert.True(t, resource.IsCompliant())
		assert.Empty(t, resource.ComplianceErrors())
	})

	t.Run("Missing Mandatory Keys", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
			},
		)

		mandatoryKeys := []string{"environment", "owner", "cost-center"}

		ruler.validateMandatoryKeys(resource, mandatoryKeys)

		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 2)

		errors := resource.ComplianceErrors()
		errorMessages := []string{errors[0].Message, errors[1].Message}
		assert.Contains(t, errorMessages, "Missing mandatory tag: `owner`")
		assert.Contains(t, errorMessages, "Missing mandatory tag: `cost-center`")
	})

	t.Run("Empty Mandatory Keys", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{},
		)

		var mandatoryKeys []string

		ruler.validateMandatoryKeys(resource, mandatoryKeys)

		assert.True(t, resource.IsCompliant())
		assert.Empty(t, resource.ComplianceErrors())
	})
}

func TestValidateTagValues(t *testing.T) {
	ruler := NewRuler()

	t.Run("String Tag with Allowed Values", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
			},
		)

		validations := map[string]*types.Validation{
			"environment": {
				Type:          types.TagTypeString,
				AllowedValues: []string{"dev", "staging", "prod"},
			},
		}

		ruler.validateTagValues(resource, validations)

		assert.True(t, resource.IsCompliant())
		assert.Empty(t, resource.ComplianceErrors())
	})

	t.Run("String Tag with Invalid Value", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "production", // Not in allowed values
			},
		)

		validations := map[string]*types.Validation{
			"environment": {
				Type:          types.TagTypeString,
				AllowedValues: []string{"dev", "staging", "prod"},
			},
		}

		ruler.validateTagValues(resource, validations)

		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 1)
		assert.Contains(t, resource.ComplianceErrors()[0].Message, "not in allowed values")
	})

	t.Run("String Tag with Regex", func(t *testing.T) {
		// Valid regex case
		validResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"email": "user@example.com",
			},
		)

		// Invalid regex case
		invalidResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"email": "invalid-email",
			},
		)

		validations := map[string]*types.Validation{
			"email": {
				Type:  types.TagTypeString,
				Regex: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
			},
		}

		// Test valid case
		ruler.validateTagValues(validResource, validations)
		assert.True(t, validResource.IsCompliant())

		// Test invalid case
		ruler.validateTagValues(invalidResource, validations)
		assert.False(t, invalidResource.IsCompliant())
		assert.Contains(t, invalidResource.ComplianceErrors()[0].Message, "does not match regex")
	})

	t.Run("Boolean Tag", func(t *testing.T) {
		// Valid boolean cases
		validResource1 := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"enabled": "true",
			},
		)

		validResource2 := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"enabled": "false",
			},
		)

		// Invalid boolean case
		invalidResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"enabled": "yes", // Not a valid boolean
			},
		)

		validations := map[string]*types.Validation{
			"enabled": {
				Type: types.TagTypeBool,
			},
		}

		ruler.validateTagValues(validResource1, validations)
		assert.True(t, validResource1.IsCompliant())

		ruler.validateTagValues(validResource2, validations)
		assert.True(t, validResource2.IsCompliant())

		ruler.validateTagValues(invalidResource, validations)
		assert.False(t, invalidResource.IsCompliant())
		assert.Contains(t, invalidResource.ComplianceErrors()[0].Message, "not a valid boolean")
	})

	t.Run("Integer Tag", func(t *testing.T) {
		// Valid integer
		validResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"ttl": "30",
			},
		)

		// Invalid integer
		invalidResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"ttl": "thirty",
			},
		)

		// Outside range
		outOfRangeResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"ttl": "150",
			},
		)

		validations := map[string]*types.Validation{
			"ttl": {
				Type:     types.TagTypeInt,
				MinValue: 1,
				MaxValue: 90,
			},
		}

		ruler.validateTagValues(validResource, validations)
		assert.True(t, validResource.IsCompliant())

		ruler.validateTagValues(invalidResource, validations)
		assert.False(t, invalidResource.IsCompliant())
		assert.Contains(t, invalidResource.ComplianceErrors()[0].Message, "not a valid integer")

		ruler.validateTagValues(outOfRangeResource, validations)
		assert.False(t, outOfRangeResource.IsCompliant())
		assert.Contains(t, outOfRangeResource.ComplianceErrors()[0].Message, "greater than maximum")
	})

	t.Run("Integer with Allowed Values", func(t *testing.T) {
		// Valid integer from allowed list
		validResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"priority": "10",
			},
		)

		// Valid integer but not in allowed list
		invalidResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"priority": "15",
			},
		)

		validations := map[string]*types.Validation{
			"priority": {
				Type:          types.TagTypeInt,
				AllowedValues: []string{"1", "5", "10"},
			},
		}

		ruler := NewRuler()

		ruler.validateTagValues(validResource, validations)
		assert.True(t, validResource.IsCompliant())

		ruler.validateTagValues(invalidResource, validations)

		assert.False(t, invalidResource.IsCompliant(), "Resource with invalid integer value should be non-compliant")
		errors := invalidResource.ComplianceErrors()
		if assert.NotEmpty(t, errors, "Resource should have compliance errors") {
			assert.Contains(t, errors[0].Message, "not in allowed values")
		}
	})

	t.Run("Missing Tag", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{},
		)

		validations := map[string]*types.Validation{
			"environment": {
				Type:          types.TagTypeString,
				AllowedValues: []string{"dev", "staging", "prod"},
			},
		}

		ruler.validateTagValues(resource, validations)

		assert.True(t, resource.IsCompliant())
		assert.Empty(t, resource.ComplianceErrors())
	})
}

func TestApplyRules(t *testing.T) {
	ruler := NewRuler()

	t.Run("Equals Condition", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					Equals: &types.EqualsCondition{
						Key:   "environment",
						Value: "prod",
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"cost-center", "owner"}},
			},
		}

		ruler.applyRules(resource, rules)

		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 2) // two from the missing keys
	})

	t.Run("Exists Condition", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"temporary": "yes",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					Exists: &types.ExistsCondition{
						Key: "temporary",
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"ttl"},
				},
			},
		}

		ruler.applyRules(resource, rules)

		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 1) // one from the missing key
	})

	t.Run("NotEquals Condition", func(t *testing.T) {
		// Should match (environment != prod)
		matchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "dev",
			},
		)

		// Should not match (environment = prod)
		noMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					NotEquals: &types.EqualsCondition{
						Key:   "environment",
						Value: "prod",
					},
				},
				Then: &types.Action{
					ShouldContainKeys: []string{"owner"},
					Warn:              "Non-production resources should have an owner tag",
				},
			},
		}

		ruler.applyRules(matchResource, rules)
		assert.True(t, matchResource.IsCompliant())          // Warning doesn't affect compliance
		assert.Len(t, matchResource.ComplianceWarnings(), 2) // One from the warning message, one from should contain

		ruler.applyRules(noMatchResource, rules)
		assert.True(t, noMatchResource.IsCompliant())
		assert.Empty(t, noMatchResource.ComplianceWarnings())
	})

	t.Run("Contains Condition", func(t *testing.T) {
		// Should match (description contains "test")
		matchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"description": "This is a test resource",
			},
		)

		// Should not match (description does not contain "test")
		noMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"description": "Production server",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					Contains: &types.ContainsCondition{
						Key:   "description",
						Value: "test",
					},
				},
				Then: &types.Action{
					Warn: "Test resources should be cleaned up regularly",
				},
			},
		}

		ruler.applyRules(matchResource, rules)
		assert.True(t, matchResource.IsCompliant())
		assert.Len(t, matchResource.ComplianceWarnings(), 1)
		assert.Contains(t, matchResource.ComplianceWarnings()[0].Message, "Test resources should be cleaned up regularly")

		ruler.applyRules(noMatchResource, rules)
		assert.True(t, noMatchResource.IsCompliant())
		assert.Empty(t, noMatchResource.ComplianceWarnings())
	})

	t.Run("Numeric Conditions", func(t *testing.T) {
		// GreaterThan match
		gtMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"count": "15",
			},
		)

		// GreaterThan no match
		gtNoMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"count": "5",
			},
		)

		// LessThan match
		ltMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"count": "5",
			},
		)

		// LessThan no match
		ltNoMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"count": "15",
			},
		)

		gtRules := []*types.Rule{
			{
				When: &types.Condition{
					GreaterThan: &types.NumericCondition{
						Key:   "count",
						Value: 10.0,
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"high-count-approval"},
					Error:           "Resources with count > 10 require approval",
				},
			},
		}

		ltRules := []*types.Rule{
			{
				When: &types.Condition{
					LessThan: &types.NumericCondition{
						Key:   "count",
						Value: 10.0,
					},
				},
				Then: &types.Action{
					Warn: "Count is low, consider increasing for better performance",
				},
			},
		}

		ruler.applyRules(gtMatchResource, gtRules)
		assert.False(t, gtMatchResource.IsCompliant())
		assert.Len(t, gtMatchResource.ComplianceErrors(), 2)

		ruler.applyRules(gtNoMatchResource, gtRules)
		assert.True(t, gtNoMatchResource.IsCompliant())
		assert.Empty(t, gtNoMatchResource.ComplianceErrors())

		ruler.applyRules(ltMatchResource, ltRules)
		assert.True(t, ltMatchResource.IsCompliant())
		assert.Len(t, ltMatchResource.ComplianceWarnings(), 1)

		ruler.applyRules(ltNoMatchResource, ltRules)
		assert.True(t, ltNoMatchResource.IsCompliant())
		assert.Empty(t, ltNoMatchResource.ComplianceWarnings())
	})

	t.Run("And Condition", func(t *testing.T) {
		// Both conditions match
		bothMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
				"critical":    "true",
			},
		)

		// Only one condition matches
		oneMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					And: []*types.Condition{
						{
							Equals: &types.EqualsCondition{
								Key:   "environment",
								Value: "prod",
							},
						},
						{
							Exists: &types.ExistsCondition{
								Key: "critical",
							},
						},
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"dr-policy", "backup-policy"},
					Error:           "Critical production resources need DR and backup policies",
				},
			},
		}

		ruler.applyRules(bothMatchResource, rules)
		assert.False(t, bothMatchResource.IsCompliant())
		assert.Len(t, bothMatchResource.ComplianceErrors(), 3)

		ruler.applyRules(oneMatchResource, rules)
		assert.True(t, oneMatchResource.IsCompliant())
		assert.Empty(t, oneMatchResource.ComplianceErrors())
	})

	t.Run("Or Condition", func(t *testing.T) {
		// First condition matches
		firstMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
			},
		)

		// Second condition matches
		secondMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "staging",
			},
		)

		// Neither condition matches
		noMatchResource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "dev",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					Or: []*types.Condition{
						{
							Equals: &types.EqualsCondition{
								Key:   "environment",
								Value: "prod",
							},
						},
						{
							Equals: &types.EqualsCondition{
								Key:   "environment",
								Value: "staging",
							},
						},
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"owner", "cost-center"},
					Error:           "Prod and staging environments require owner and cost-center tags",
				},
			},
		}

		ruler.applyRules(firstMatchResource, rules)
		assert.False(t, firstMatchResource.IsCompliant())
		assert.Len(t, firstMatchResource.ComplianceErrors(), 3)

		ruler.applyRules(secondMatchResource, rules)
		assert.False(t, secondMatchResource.IsCompliant())
		assert.Len(t, secondMatchResource.ComplianceErrors(), 3)

		ruler.applyRules(noMatchResource, rules)
		assert.True(t, noMatchResource.IsCompliant())
		assert.Empty(t, noMatchResource.ComplianceErrors())
	})

	t.Run("Multiple Rules", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
				"temporary":   "yes",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					Equals: &types.EqualsCondition{
						Key:   "environment",
						Value: "prod",
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"cost-center"},
					Error:           "Production resources must have cost-center",
				},
			},
			{
				When: &types.Condition{
					Exists: &types.ExistsCondition{
						Key: "temporary",
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"ttl"},
					Error:           "Temporary resources must have TTL",
				},
			},
		}

		ruler.applyRules(resource, rules)

		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 4) // 2 errors + 2 missing keys
	})

	t.Run("Action with Error and Warning", func(t *testing.T) {
		resource := NewMockResource(
			"test-id",
			"test-type",
			"test-service",
			"test-provider",
			"test-region",
			"test-owner",
			map[string]string{
				"environment": "prod",
				"owner":       "team@example.com",
			},
		)

		rules := []*types.Rule{
			{
				When: &types.Condition{
					Equals: &types.EqualsCondition{
						Key:   "environment",
						Value: "prod",
					},
				},
				Then: &types.Action{
					MustContainKeys:   []string{"cost-center"},
					ShouldContainKeys: []string{"project"},
					Error:             "Production resources must have cost-center",
					Warn:              "Production resources should have project tag",
				},
			},
		}

		ruler.applyRules(resource, rules)

		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 2)
		assert.Len(t, resource.ComplianceWarnings(), 2)
	})
}

func TestValidate(t *testing.T) {
	ruler := NewRuler()

	resource := NewMockResource(
		"test-id",
		"test-type",
		"test-service",
		"test-provider",
		"test-region",
		"test-owner",
		map[string]string{
			"environment": "prod",
		},
	)

	policy := &types.TagPolicy{
		MandatoryKeys: []string{"environment", "owner", "cost-center"},
		Validations: map[string]*types.Validation{
			"environment": {
				Type:          types.TagTypeString,
				AllowedValues: []string{"dev", "staging", "prod"},
			},
		},
		Rules: []*types.Rule{
			{
				When: &types.Condition{
					Equals: &types.EqualsCondition{
						Key:   "environment",
						Value: "prod",
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"backup-policy"},
					Error:           "Production resources need backup policy",
				},
			},
		},
	}

	ruler.Validate(resource, policy)

	assert.False(t, resource.IsCompliant())

	// Should have errors for:
	// 1. Missing mandatory tag: owner
	// 2. Missing mandatory tag: cost-center
	// 3. "Production resources need backup policy" error message
	// 4. Missing required tag backup-policy based on rule condition
	assert.Len(t, resource.ComplianceErrors(), 4)

	errorMessages := make(map[string]bool)
	for _, err := range resource.ComplianceErrors() {
		errorMessages[err.Message] = true
	}

	assert.True(t, errorMessages["Missing mandatory tag: `owner`"])
	assert.True(t, errorMessages["Missing mandatory tag: `cost-center`"])
	assert.True(t, errorMessages["Production resources need backup policy"])
	assert.True(t, errorMessages["Missing required tag `backup-policy` based on rule condition"])
}

func TestValidateAll(t *testing.T) {
	ruler := NewRuler()

	// Compliant resource
	compliantResource := NewMockResource(
		"compliant-id",
		"test-type",
		"test-service",
		"test-provider",
		"test-region",
		"test-owner",
		map[string]string{
			"environment": "dev",
			"owner":       "team@example.com",
		},
	)

	// Non-compliant resource
	nonCompliantResource := NewMockResource(
		"non-compliant-id",
		"test-type",
		"test-service",
		"test-provider",
		"test-region",
		"test-owner",
		map[string]string{
			"environment": "prod",
		},
	)

	resources := []cr.CloudResource{compliantResource, nonCompliantResource}

	policy := &types.TagPolicy{
		MandatoryKeys: []string{"environment", "owner"},
		Validations: map[string]*types.Validation{
			"environment": {
				Type:          types.TagTypeString,
				AllowedValues: []string{"dev", "staging", "prod"},
			},
		},
		Rules: []*types.Rule{
			{
				When: &types.Condition{
					Equals: &types.EqualsCondition{
						Key:   "environment",
						Value: "prod",
					},
				},
				Then: &types.Action{
					MustContainKeys: []string{"cost-center"},
					Error:           "Production resources must have cost-center",
				},
			},
		},
	}

	compliant, nonCompliant := ruler.ValidateAll(resources, policy)

	assert.Equal(t, 1, compliant)
	assert.Equal(t, 1, nonCompliant)

	assert.True(t, compliantResource.IsCompliant())

	assert.False(t, nonCompliantResource.IsCompliant())
	assert.Len(t, nonCompliantResource.ComplianceErrors(), 3)
}
