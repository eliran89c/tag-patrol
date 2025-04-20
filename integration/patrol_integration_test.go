//go:build integration

package integration_test

import (
	"context"
	"testing"

	"io/ioutil"
	"path/filepath"

	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
	patrolpkg "github.com/eliran89c/tag-patrol/pkg/patrol"
	types "github.com/eliran89c/tag-patrol/pkg/policy/types"
	"github.com/stretchr/testify/assert"
)

// inMemoryResource implements cr.CloudResource for integration testing
// (copied and simplified from patrol_test.go)
type inMemoryResource struct {
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

func (m *inMemoryResource) ID() string              { return m.id }
func (m *inMemoryResource) Type() string            { return m.resourceType }
func (m *inMemoryResource) Service() string         { return m.service }
func (m *inMemoryResource) Provider() string        { return m.provider }
func (m *inMemoryResource) Region() string          { return m.region }
func (m *inMemoryResource) OwnerID() string         { return m.ownerID }
func (m *inMemoryResource) Tags() map[string]string { return m.tags }
func (m *inMemoryResource) IsCompliant() bool       { return len(m.errors) == 0 }
func (m *inMemoryResource) AddComplianceError(msg string) {
	m.errors = append(m.errors, &cr.ComplianceError{Message: msg})
}
func (m *inMemoryResource) AddComplianceWarning(msg string) {
	m.warnings = append(m.warnings, &cr.ComplianceWarning{Message: msg})
}
func (m *inMemoryResource) ComplianceErrors() []*cr.ComplianceError     { return m.errors }
func (m *inMemoryResource) ComplianceWarnings() []*cr.ComplianceWarning { return m.warnings }

// inMemoryFinder implements patrolpkg.Finder
// Returns a static set of resources for the test

type inMemoryFinder struct {
	resources []cr.CloudResource
}

func (f *inMemoryFinder) FindResources(ctx context.Context, service, resourceType string) ([]cr.CloudResource, error) {
	return f.resources, nil
}

func TestPatrolIntegration_BasicEndToEnd(t *testing.T) {
	ctx := context.Background()
	// Define a simple tag policy: require tag "env"
	policy := &types.ResourceDefinition{
		Service:      "ec2",
		ResourceType: "instance",
		TagPolicy: &types.TagPolicy{
			MandatoryKeys: []string{"env"},
		},
	}
	// One compliant, one non-compliant resource
	resources := []cr.CloudResource{
		&inMemoryResource{
			id:           "i-1",
			resourceType: "instance",
			service:      "ec2",
			provider:     "aws",
			region:       "us-east-1",
			ownerID:      "123",
			tags:         map[string]string{"env": "prod"},
		},
		&inMemoryResource{
			id:           "i-2",
			resourceType: "instance",
			service:      "ec2",
			provider:     "aws",
			region:       "us-east-1",
			ownerID:      "123",
			tags:         map[string]string{"Name": "bad"},
		},
	}
	finder := &inMemoryFinder{resources: resources}
	patrol := patrolpkg.New(finder, nil)
	results, err := patrol.Run(ctx, []*types.ResourceDefinition{policy})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	result := results[0]
	assert.Equal(t, 1, result.CompliantCount)
	assert.Equal(t, 1, result.NonCompliantCount)
	assert.Len(t, result.Resources, 2)
	// Check that the non-compliant resource has the expected error
	var foundNonCompliant bool
	for _, r := range result.Resources {
		if !r.IsCompliant() {
			errs := r.ComplianceErrors()
			assert.NotEmpty(t, errs)
			assert.Contains(t, errs[0].Message, "Missing mandatory tag: `env`")
			foundNonCompliant = true
		}
	}
	assert.True(t, foundNonCompliant, "Should find a non-compliant resource")
}

func TestPatrolIntegration_WithRealPolicyFile(t *testing.T) {
	ctx := context.Background()

	// Write a real policy YAML to a temp file
	policyYAML := `
resources:
  ec2:
    instance:
      mandatoryKeys:
        - env
      validations:
        env:
          type: string
          allowedValues: ["prod", "dev"]
`
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	err := ioutil.WriteFile(policyPath, []byte(policyYAML), 0644)
	assert.NoError(t, err)

	// One compliant, one non-compliant resource
	resources := []cr.CloudResource{
		&inMemoryResource{
			id:           "i-1",
			resourceType: "instance",
			service:      "ec2",
			provider:     "aws",
			region:       "us-east-1",
			ownerID:      "123",
			tags:         map[string]string{"env": "prod"},
		},
		&inMemoryResource{
			id:           "i-2",
			resourceType: "instance",
			service:      "ec2",
			provider:     "aws",
			region:       "us-east-1",
			ownerID:      "123",
			tags:         map[string]string{"Name": "bad"},
		},
	}
	finder := &inMemoryFinder{resources: resources}
	patrol := patrolpkg.New(finder, nil)

	// Use the real parser and RunFromFile
	results, err := patrol.RunFromFile(ctx, policyPath)
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	result := results[0]
	assert.Equal(t, 1, result.CompliantCount)
	assert.Equal(t, 1, result.NonCompliantCount)
	assert.Len(t, result.Resources, 2)
	var foundNonCompliant bool
	for _, r := range result.Resources {
		if !r.IsCompliant() {
			errs := r.ComplianceErrors()
			assert.NotEmpty(t, errs)
			assert.Contains(t, errs[0].Message, "Missing mandatory tag: `env`")
			foundNonCompliant = true
		}
	}
	assert.True(t, foundNonCompliant, "Should find a non-compliant resource")
}

func TestPatrolIntegration_BlueprintsExtends(t *testing.T) {
	ctx := context.Background()
	policyYAML := `
blueprints:
  common:
    mandatoryKeys: [env, owner]
    validations:
      env:
        type: string
        allowedValues: [prod, dev, staging]
resources:
  ec2:
    instance:
      extends: [blueprints.common]
      mandatoryKeys: [Name]
`
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	err := ioutil.WriteFile(policyPath, []byte(policyYAML), 0644)
	assert.NoError(t, err)

	resources := []cr.CloudResource{
		&inMemoryResource{
			id:           "i-1",
			resourceType: "instance",
			service:      "ec2",
			provider:     "aws",
			region:       "us-east-1",
			ownerID:      "123",
			tags:         map[string]string{"env": "prod", "owner": "alice", "Name": "web"},
		},
		&inMemoryResource{
			id:           "i-2",
			resourceType: "instance",
			service:      "ec2",
			provider:     "aws",
			region:       "us-east-1",
			ownerID:      "123",
			tags:         map[string]string{"env": "qa", "Name": "bad"}, // missing owner, env not allowed
		},
	}
	finder := &inMemoryFinder{resources: resources}
	patrol := patrolpkg.New(finder, nil)
	results, err := patrol.RunFromFile(ctx, policyPath)
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	result := results[0]
	assert.Equal(t, 1, result.CompliantCount)
	assert.Equal(t, 1, result.NonCompliantCount)
	assert.Len(t, result.Resources, 2)
	var foundNonCompliant bool
	for _, r := range result.Resources {
		if !r.IsCompliant() {
			errs := r.ComplianceErrors()
			assert.NotEmpty(t, errs)
			msgs := []string{errs[0].Message}
			for _, e := range errs[1:] {
				msgs = append(msgs, e.Message)
			}
			assert.True(t,
				containsAny(msgs, []string{
					"Missing mandatory tag: `owner`",
					"Tag `env` has value `qa` which is not in allowed values",
				}),
				"Should have blueprint-inherited errors",
			)
			foundNonCompliant = true
		}
	}
	assert.True(t, foundNonCompliant, "Should find a non-compliant resource")
}

func containsAny(msgs []string, subs []string) bool {
	for _, m := range msgs {
		for _, s := range subs {
			if contains(m, s) {
				return true
			}
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && (len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))))
}
