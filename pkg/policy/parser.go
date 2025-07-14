package policy

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"

	"github.com/eliran89c/tag-patrol/pkg/policy/types"
	ptypes "github.com/eliran89c/tag-patrol/pkg/policy/types"
	"gopkg.in/yaml.v3"
)

// DefaultParser implements the standard policy parser for tag policies
type DefaultParser struct{}

// NewParser creates a new DefaultParser instance
func NewParser() *DefaultParser {
	return &DefaultParser{}
}

// ParseFile parses a policy file from the specified path
func (p *DefaultParser) ParseFile(path string) ([]*types.ResourceDefinition, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return p.ParseReader(file)
}

// ParseBytes parses a policy from a byte slice
func (p *DefaultParser) ParseBytes(data []byte) ([]*types.ResourceDefinition, error) {
	return p.ParseReader(bytes.NewReader(data))
}

// ParseReader parses a policy from an io.Reader
func (p *DefaultParser) ParseReader(reader io.Reader) ([]*types.ResourceDefinition, error) {
	var policy types.Policy

	decoder := yaml.NewDecoder(reader)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %w", err)
	}

	return p.ParsePolicy(&policy)

}

// ParsePolicy validates and processes a Policy into ResourceDefinitions
func (p *DefaultParser) ParsePolicy(policy *ptypes.Policy) ([]*ptypes.ResourceDefinition, error) {
	if err := ValidatePolicy(policy); err != nil {
		return nil, fmt.Errorf("failed to validate policy: %w", err)
	}

	return p.ProcessPolicy(policy)
}

// ProcessPolicy converts a Policy into a list of ResourceDefinitions
func (p *DefaultParser) ProcessPolicy(config *ptypes.Policy) ([]*ptypes.ResourceDefinition, error) {
	var definitions []*ptypes.ResourceDefinition

	for service, resource := range config.Resources {
		for resourceType, resourceConfig := range resource {
			definition, err := p.processResource(config, service, resourceType, resourceConfig)
			if err != nil {
				return nil, fmt.Errorf("failed to process resource configuration %s.%s: %w", service, resourceType, err)
			}
			definitions = append(definitions, definition)
		}
	}

	return definitions, nil
}

func (p *DefaultParser) processResource(config *ptypes.Policy, service, resourceType string, resourceConfig *ptypes.ResourceConfig) (*ptypes.ResourceDefinition, error) {
	definition := &ptypes.ResourceDefinition{
		Service:      service,
		ResourceType: resourceType,
		TagPolicy: &ptypes.TagPolicy{
			MandatoryKeys: make([]string, 0),
			Validations:   make(map[string]*ptypes.Validation),
			Rules:         make([]*ptypes.Rule, 0),
		},
	}

	if resourceConfig == nil {
		return definition, nil
	}

	if resourceConfig.TagPolicy == nil {
		resourceConfig.TagPolicy = &ptypes.TagPolicy{
			MandatoryKeys: make([]string, 0),
			Validations:   make(map[string]*ptypes.Validation),
			Rules:         make([]*ptypes.Rule, 0),
		}
	}

	resourceKeys := make(map[string]bool)

	if resourceConfig.MandatoryKeys != nil {
		for _, key := range resourceConfig.MandatoryKeys {
			resourceKeys[key] = true
		}
	}

	if len(resourceConfig.Extends) > 0 && config.Blueprints != nil {
		for _, extendPath := range resourceConfig.Extends {
			parts := strings.Split(strings.TrimSpace(extendPath), ".")

			name := parts[1]
			blueprint := config.Blueprints[name]

			if blueprint.MandatoryKeys != nil {
				for _, key := range blueprint.MandatoryKeys {
					if !resourceKeys[key] {
						resourceKeys[key] = true
					}
				}
			}

			if blueprint.Validations != nil {
				for key, validation := range blueprint.Validations {
					if resourceConfig.Validations == nil {
						definition.Validations[key] = validation
						continue
					}

					if _, hasValidation := resourceConfig.Validations[key]; !hasValidation {
						definition.Validations[key] = validation
					}
				}
			}

			if blueprint.Rules != nil {
				definition.Rules = append(definition.Rules, blueprint.Rules...)
			}
		}
	}

	for key := range resourceKeys {
		definition.MandatoryKeys = append(definition.MandatoryKeys, key)
	}

	if resourceConfig.Validations != nil {
		if definition.Validations == nil {
			definition.Validations = make(map[string]*ptypes.Validation)
		}
		maps.Copy(definition.Validations, resourceConfig.Validations)
	}

	if resourceConfig.Rules != nil {
		definition.Rules = append(definition.Rules, resourceConfig.Rules...)
	}

	return definition, nil
}
