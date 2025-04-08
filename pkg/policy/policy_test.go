package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/eliran89c/tag-patrol/pkg/policy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBytes(t *testing.T) {
	parser := NewParser()

	minimalPolicy := `
resources:
  ec2:
    instance:
      mandatoryKeys:
        - name
        - environment
`

	definitions, err := parser.ParseBytes([]byte(minimalPolicy))
	assert.NoError(t, err)
	assert.Len(t, definitions, 1)
	assert.Equal(t, "ec2", definitions[0].Service)
	assert.Equal(t, "instance", definitions[0].ResourceType)
	assert.Len(t, definitions[0].MandatoryKeys, 2)
	assert.Contains(t, definitions[0].MandatoryKeys, "name")
	assert.Contains(t, definitions[0].MandatoryKeys, "environment")
}

func TestParseReader(t *testing.T) {
	parser := NewParser()

	policyWithValidations := `
resources:
  ec2:
    instance:
      mandatoryKeys:
        - name
        - environment
      validations:
        environment:
          type: string
          allowedValues:
            - prod
            - staging
            - dev
`

	reader := strings.NewReader(policyWithValidations)
	definitions, err := parser.ParseReader(reader)
	assert.NoError(t, err)
	assert.Len(t, definitions, 1)

	def := definitions[0]
	assert.Equal(t, "ec2", def.Service)
	assert.Equal(t, "instance", def.ResourceType)
	assert.Len(t, def.Validations, 1)
	assert.Contains(t, def.Validations, "environment")
	assert.Equal(t, types.TagTypeString, def.Validations["environment"].Type)
	assert.Len(t, def.Validations["environment"].AllowedValues, 3)
}

func TestParseFile(t *testing.T) {
	policyContent := `
resources:
  ec2:
    instance:
      mandatoryKeys:
        - name
      validations:
        name:
          type: string
          regex: "^[a-z0-9-]+$"
`

	tempFile, err := os.CreateTemp("", "policy-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	_, err = tempFile.WriteString(policyContent)
	require.NoError(t, err)
	require.NoError(t, tempFile.Close())

	parser := NewParser()
	definitions, err := parser.ParseFile(tempFile.Name())
	assert.NoError(t, err)
	assert.Len(t, definitions, 1)

	def := definitions[0]
	assert.Equal(t, "ec2", def.Service)
	assert.Equal(t, "instance", def.ResourceType)
	assert.Len(t, def.MandatoryKeys, 1)
	assert.Contains(t, def.MandatoryKeys, "name")
	assert.Len(t, def.Validations, 1)
	assert.Equal(t, "^[a-z0-9-]+$", def.Validations["name"].Regex)
}

func TestProcessPolicy(t *testing.T) {
	t.Run("Basic Policy", func(t *testing.T) {
		parser := NewParser()

		policy := &types.Policy{
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"name", "environment"},
						},
					},
				},
			},
		}

		definitions, err := parser.ProcessPolicy(policy)

		assert.NoError(t, err)
		assert.Len(t, definitions, 1)
		assert.Equal(t, "ec2", definitions[0].Service)
		assert.Equal(t, "instance", definitions[0].ResourceType)
		assert.Len(t, definitions[0].MandatoryKeys, 2)
	})

	t.Run("Policy with Blueprint Extension", func(t *testing.T) {
		parser := NewParser()

		policy := &types.Policy{
			Blueprints: map[string]*types.Blueprint{
				"base": {
					TagPolicy: &types.TagPolicy{
						MandatoryKeys: []string{"environment", "owner"},
						Validations: map[string]*types.Validation{
							"environment": {
								Type:          types.TagTypeString,
								AllowedValues: []string{"prod", "staging", "dev"},
							},
						},
					},
				},
			},
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"name"},
						},
						Extends: []string{"blueprints.base"},
					},
				},
			},
		}

		definitions, err := parser.ProcessPolicy(policy)

		assert.NoError(t, err)
		assert.Len(t, definitions, 1)

		def := definitions[0]
		assert.Equal(t, "ec2", def.Service)
		assert.Equal(t, "instance", def.ResourceType)

		assert.Len(t, def.MandatoryKeys, 3)
		assert.Contains(t, def.MandatoryKeys, "name")
		assert.Contains(t, def.MandatoryKeys, "environment")
		assert.Contains(t, def.MandatoryKeys, "owner")

		assert.Len(t, def.Validations, 1)
		assert.Contains(t, def.Validations, "environment")
	})

	t.Run("Multiple Resources", func(t *testing.T) {
		parser := NewParser()

		policy := &types.Policy{
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"name"},
						},
					},
					"volume": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"attached-to"},
						},
					},
				},
				"s3": {
					"bucket": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"purpose"},
						},
					},
				},
			},
		}

		definitions, err := parser.ProcessPolicy(policy)

		assert.NoError(t, err)
		assert.Len(t, definitions, 3)

		serviceTypes := make(map[string]bool)
		for _, def := range definitions {
			key := def.Service + "." + def.ResourceType
			serviceTypes[key] = true
		}

		assert.True(t, serviceTypes["ec2.instance"])
		assert.True(t, serviceTypes["ec2.volume"])
		assert.True(t, serviceTypes["s3.bucket"])
	})

	t.Run("Empty Resource Config", func(t *testing.T) {
		parser := NewParser()

		policy := &types.Policy{
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": nil,
				},
			},
		}

		definitions, err := parser.ProcessPolicy(policy)

		assert.NoError(t, err)
		assert.Len(t, definitions, 1)

		def := definitions[0]
		assert.Equal(t, "ec2", def.Service)
		assert.Equal(t, "instance", def.ResourceType)
		assert.Empty(t, def.MandatoryKeys)
		assert.Empty(t, def.Validations)
		assert.Empty(t, def.Rules)
	})
}

func TestParsePolicyWithBlueprints(t *testing.T) {
	policy := `
blueprints:
  base:
    mandatoryKeys:
      - environment
    validations:
      environment:
        type: string
        allowedValues:
          - prod
          - staging
          - dev
          
  production:
    mandatoryKeys:
      - cost-center
    validations:
      cost-center:
        type: string
        regex: "^CC-[0-9]{4}$"
    rules:
      - when:
          equals:
            key: environment
            value: prod
        then:
          mustContainKeys:
            - backup-policy
          
resources:
  ec2:
    instance:
      extends:
        - blueprints.base
        - blueprints.production
      mandatoryKeys:
        - name
      validations:
        name:
          type: string
          regex: "^[a-z0-9-]+$"
`

	parser := NewParser()
	definitions, err := parser.ParseBytes([]byte(policy))

	assert.NoError(t, err)
	assert.Len(t, definitions, 1)

	def := definitions[0]

	assert.Len(t, def.MandatoryKeys, 3)
	assert.Contains(t, def.MandatoryKeys, "environment")
	assert.Contains(t, def.MandatoryKeys, "cost-center")
	assert.Contains(t, def.MandatoryKeys, "name")

	assert.Len(t, def.Validations, 3)
	assert.Contains(t, def.Validations, "environment")
	assert.Contains(t, def.Validations, "cost-center")
	assert.Contains(t, def.Validations, "name")

	assert.Len(t, def.Rules, 1)
}

func TestInvalidPolicies(t *testing.T) {
	testCases := []struct {
		name        string
		policyYAML  string
		errorSubstr string
	}{
		{
			name: "Missing Resources",
			policyYAML: `
blueprints:
  base:
    mandatoryKeys:
      - environment
`,
			errorSubstr: "required",
		},
		{
			name: "Invalid Condition",
			policyYAML: `
resources:
  ec2:
    instance:
      rules:
        - when:
            invalidCondition:
              key: test
          then:
            error: "Invalid"
`,
			errorSubstr: "specify exactly one operator",
		},
		{
			name: "Invalid Validation Type",
			policyYAML: `
resources:
  ec2:
    instance:
      validations:
        test:
          type: invalid
`,
			errorSubstr: "must be one of",
		},
		{
			name: "Invalid Regex",
			policyYAML: `
resources:
  ec2:
    instance:
      validations:
        test:
          type: string
          regex: "["
`,
			errorSubstr: "valid",
		},
		{
			name: "Both Regex and AllowedValues",
			policyYAML: `
resources:
  ec2:
    instance:
      validations:
        test:
          type: string
          regex: "^test$"
          allowedValues:
            - test
`,
			errorSubstr: "Cannot specify both Regex and AllowedValues",
		},
		{
			name: "Min/Max Value for non-int",
			policyYAML: `
resources:
  ec2:
    instance:
      validations:
        test:
          type: string
          minValue: 1
          maxValue: 10
`,
			errorSubstr: "only applicable when Type is 'int'",
		},
		{
			name: "MinValue > MaxValue",
			policyYAML: `
resources:
  ec2:
    instance:
      validations:
        test:
          type: int
          minValue: 100
          maxValue: 10
`,
			errorSubstr: "greater than or equal",
		},
		{
			name: "Invalid Blueprint Reference",
			policyYAML: `
resources:
  ec2:
    instance:
      extends:
        - blueprints.nonexistent
`,
			errorSubstr: "does not exist",
		},
		{
			name: "Invalid YAML",
			policyYAML: `
resources:
  - this is not valid YAML
    nested:
      - items with missing colons
`,
			errorSubstr: "decode",
		},
	}

	parser := NewParser()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parser.ParseBytes([]byte(tc.policyYAML))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorSubstr)
		})
	}
}

func TestValidationErrors(t *testing.T) {
	errors := &ParserErrors{
		Messages: []string{
			"Error 1",
			"Error 2",
			"Error 3",
		},
	}

	errorStr := errors.Error()
	assert.Contains(t, errorStr, "3 validation error(s) occurred")
	assert.Contains(t, errorStr, "Error 1")
	assert.Contains(t, errorStr, "Error 2")
	assert.Contains(t, errorStr, "Error 3")
}

func TestValidatePolicy(t *testing.T) {
	t.Run("Valid Policy", func(t *testing.T) {
		policy := &types.Policy{
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"name"},
						},
					},
				},
			},
		}

		err := ValidatePolicy(policy)
		assert.NoError(t, err)
	})

	t.Run("Valid Complex Policy", func(t *testing.T) {
		policy := &types.Policy{
			Blueprints: map[string]*types.Blueprint{
				"base": {
					TagPolicy: &types.TagPolicy{
						MandatoryKeys: []string{"environment"},
						Validations: map[string]*types.Validation{
							"environment": {
								Type:          types.TagTypeString,
								AllowedValues: []string{"prod", "staging", "dev"},
							},
							"ttl": {
								Type:     types.TagTypeInt,
								MinValue: 1,
								MaxValue: 90,
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
								},
							},
						},
					},
				},
			},
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": {
						TagPolicy: &types.TagPolicy{
							MandatoryKeys: []string{"name"},
						},
						Extends: []string{"blueprints.base"},
					},
				},
			},
		}

		err := ValidatePolicy(policy)
		assert.NoError(t, err)
	})
}

func TestValidateConditionStruct(t *testing.T) {
	validConditions := []*types.Condition{
		{
			Exists: &types.ExistsCondition{
				Key: "tag-key",
			},
		},
		{
			Equals: &types.EqualsCondition{
				Key:   "environment",
				Value: "prod",
			},
		},
		{
			NotEquals: &types.EqualsCondition{
				Key:   "environment",
				Value: "dev",
			},
		},
		{
			Contains: &types.ContainsCondition{
				Key:   "description",
				Value: "test",
			},
		},
		{
			GreaterThan: &types.NumericCondition{
				Key:   "count",
				Value: 10.0,
			},
		},
		{
			LessThan: &types.NumericCondition{
				Key:   "count",
				Value: 5.0,
			},
		},
		{
			And: []*types.Condition{
				{
					Exists: &types.ExistsCondition{
						Key: "tag1",
					},
				},
				{
					Exists: &types.ExistsCondition{
						Key: "tag2",
					},
				},
			},
		},
		{
			Or: []*types.Condition{
				{
					Exists: &types.ExistsCondition{
						Key: "tag1",
					},
				},
				{
					Exists: &types.ExistsCondition{
						Key: "tag2",
					},
				},
			},
		},
	}

	policy := &types.Policy{
		Resources: map[string]map[string]*types.ResourceConfig{
			"ec2": {
				"instance": {
					TagPolicy: &types.TagPolicy{
						Rules: make([]*types.Rule, len(validConditions)),
					},
				},
			},
		},
	}

	for i, cond := range validConditions {
		policy.Resources["ec2"]["instance"].TagPolicy.Rules[i] = &types.Rule{
			When: cond,
			Then: &types.Action{
				Error: "Test action",
			},
		}
	}

	err := ValidatePolicy(policy)
	assert.NoError(t, err, "Valid conditions should pass validation")

	invalidConditions := []*types.Condition{
		{}, // Empty condition
		{ // Multiple condition types
			Exists: &types.ExistsCondition{
				Key: "tag1",
			},
			Equals: &types.EqualsCondition{
				Key:   "tag1",
				Value: "value",
			},
		},
	}

	for _, cond := range invalidConditions {
		invalidPolicy := &types.Policy{
			Resources: map[string]map[string]*types.ResourceConfig{
				"ec2": {
					"instance": {
						TagPolicy: &types.TagPolicy{
							Rules: []*types.Rule{
								{
									When: cond,
									Then: &types.Action{
										Error: "Test action",
									},
								},
							},
						},
					},
				},
			},
		}

		err := ValidatePolicy(invalidPolicy)
		assert.Error(t, err, "Invalid condition should fail validation")
		assert.Contains(t, err.Error(), "must specify exactly one operator",
			"Error should mention the need for exactly one operator")
	}
}

func TestParsePolicyRules(t *testing.T) {
	policyWithRules := `
resources:
  ec2:
    instance:
      rules:
        - when:
            equals:
              key: environment
              value: prod
          then:
            mustContainKeys:
              - cost-center
              - backup-policy
            error: "Production instances must have cost-center and backup-policy tags"
            
        - when:
            exists:
              key: temporary
          then:
            mustContainKeys:
              - ttl
            error: "Temporary resources must have a TTL"
            
        - when:
            and:
              - equals:
                  key: environment
                  value: prod
              - exists:
                  key: critical
          then:
            mustContainKeys:
              - dr-policy
            error: "Critical production resources need a DR policy"
            
        - when:
            or:
              - equals:
                  key: environment
                  value: prod
              - equals:
                  key: environment
                  value: staging
          then:
            shouldContainKeys:
              - owner
            warn: "Production and staging resources should have an owner"
`

	parser := NewParser()
	definitions, err := parser.ParseBytes([]byte(policyWithRules))

	assert.NoError(t, err)
	assert.Len(t, definitions, 1)

	def := definitions[0]
	assert.Len(t, def.Rules, 4)

	assert.NotNil(t, def.Rules[0].When.Equals)
	assert.Equal(t, "environment", def.Rules[0].When.Equals.Key)
	assert.Equal(t, "prod", def.Rules[0].When.Equals.Value)
	assert.Len(t, def.Rules[0].Then.MustContainKeys, 2)
	assert.Equal(t, "Production instances must have cost-center and backup-policy tags", def.Rules[0].Then.Error)

	assert.NotNil(t, def.Rules[1].When.Exists)
	assert.Equal(t, "temporary", def.Rules[1].When.Exists.Key)
	assert.Len(t, def.Rules[1].Then.MustContainKeys, 1)
	assert.Equal(t, "ttl", def.Rules[1].Then.MustContainKeys[0])

	assert.Len(t, def.Rules[2].When.And, 2)
	assert.NotNil(t, def.Rules[2].When.And[0].Equals)
	assert.NotNil(t, def.Rules[2].When.And[1].Exists)

	assert.Len(t, def.Rules[3].When.Or, 2)
	assert.NotNil(t, def.Rules[3].When.Or[0].Equals)
	assert.NotNil(t, def.Rules[3].When.Or[1].Equals)
	assert.Len(t, def.Rules[3].Then.ShouldContainKeys, 1)
	assert.Equal(t, "owner", def.Rules[3].Then.ShouldContainKeys[0])
	assert.Equal(t, "Production and staging resources should have an owner", def.Rules[3].Then.Warn)
}

func TestProcessEmptyResources(t *testing.T) {
	parser := NewParser()

	policy := &types.Policy{
		Resources: map[string]map[string]*types.ResourceConfig{},
	}

	definitions, err := parser.ProcessPolicy(policy)
	assert.NoError(t, err)
	assert.Empty(t, definitions)

	nilPolicy := &types.Policy{
		Resources: nil,
	}

	err = ValidatePolicy(nilPolicy)
	assert.Error(t, err, "Nil resources should cause a validation error")
	assert.Contains(t, err.Error(), "required")
}
