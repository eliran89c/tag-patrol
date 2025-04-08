package patrol

import (
	"context"
	"errors"
	"testing"

	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
	"github.com/eliran89c/tag-patrol/pkg/policy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

type MockFinder struct {
	mock.Mock
}

func (m *MockFinder) FindResources(ctx context.Context, service, resourceType string) ([]cr.CloudResource, error) {
	args := m.Called(ctx, service, resourceType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]cr.CloudResource), args.Error(1)
}

type MockParser struct {
	mock.Mock
}

func (m *MockParser) ParseFile(path string) ([]*types.ResourceDefinition, error) {
	args := m.Called(path)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*types.ResourceDefinition), args.Error(1)
}

func (m *MockParser) ParseBytes(data []byte) ([]*types.ResourceDefinition, error) {
	args := m.Called(data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*types.ResourceDefinition), args.Error(1)
}

type MockRuler struct {
	mock.Mock
}

func (m *MockRuler) Validate(resource cr.CloudResource, policy *types.TagPolicy) {
	m.Called(resource, policy)
}

func (m *MockRuler) ValidateAll(resources []cr.CloudResource, policy *types.TagPolicy) (int, int) {
	args := m.Called(resources, policy)
	return args.Int(0), args.Int(1)
}

func TestNew(t *testing.T) {
	mockFinder := new(MockFinder)

	t.Run("With Default Options", func(t *testing.T) {
		patrol := New(mockFinder, nil)

		assert.NotNil(t, patrol)
		assert.NotNil(t, patrol.Parser)
		assert.NotNil(t, patrol.Ruler)
		assert.Equal(t, mockFinder, patrol.ResourceFinder)
		assert.NotNil(t, patrol.Options)
		assert.Equal(t, 10, patrol.Options.ConcurrentWorkers) // Default value
		assert.False(t, patrol.Options.StopOnError)           // Default value
	})

	t.Run("With Custom Options", func(t *testing.T) {
		options := &Options{
			ConcurrentWorkers: 5,
			StopOnError:       true,
		}

		patrol := New(mockFinder, options)

		assert.NotNil(t, patrol)
		assert.Equal(t, mockFinder, patrol.ResourceFinder)
		assert.Equal(t, options, patrol.Options)
		assert.Equal(t, 5, patrol.Options.ConcurrentWorkers)
		assert.True(t, patrol.Options.StopOnError)
	})
}

func TestDefaultOptions(t *testing.T) {
	options := DefaultOptions()

	assert.NotNil(t, options)
	assert.Equal(t, 10, options.ConcurrentWorkers)
	assert.False(t, options.StopOnError)
}

func TestRunFromFile(t *testing.T) {
	ctx := context.Background()
	mockParser := new(MockParser)
	mockFinder := new(MockFinder)
	mockRuler := new(MockRuler)

	patrol := &Patrol{
		Parser:         mockParser,
		ResourceFinder: mockFinder,
		Ruler:          mockRuler,
		Options:        DefaultOptions(),
	}

	resourceDef := &types.ResourceDefinition{
		Service:      "ec2",
		ResourceType: "instance",
		TagPolicy: &types.TagPolicy{
			MandatoryKeys: []string{"name", "environment"},
		},
	}

	resource1 := NewMockResource(
		"res-1",
		"instance",
		"ec2",
		"aws",
		"us-west-2",
		"123456789012",
		map[string]string{"name": "test1", "environment": "prod"},
	)

	resource2 := NewMockResource(
		"res-2",
		"instance",
		"ec2",
		"aws",
		"us-west-2",
		"123456789012",
		map[string]string{"name": "test2"},
	)

	resource2.AddComplianceError("Missing mandatory tag: `environment`")

	resources := []cr.CloudResource{resource1, resource2}

	mockParser.On("ParseFile", "test-policy.yaml").Return([]*types.ResourceDefinition{resourceDef}, nil)
	mockFinder.On("FindResources", ctx, "ec2", "instance").Return(resources, nil)
	mockRuler.On("ValidateAll", resources, resourceDef.TagPolicy).Return(1, 1)

	results, err := patrol.RunFromFile(ctx, "test-policy.yaml")

	assert.NoError(t, err)
	assert.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, resourceDef, result.Definition)
	assert.Equal(t, resources, result.Resources)
	assert.Equal(t, 1, result.CompliantCount)
	assert.Equal(t, 1, result.NonCompliantCount)
	assert.Nil(t, result.Error)

	mockParser.AssertExpectations(t)
	mockFinder.AssertExpectations(t)
	mockRuler.AssertExpectations(t)
}

func TestRunFromBytes(t *testing.T) {
	ctx := context.Background()
	mockParser := new(MockParser)
	mockFinder := new(MockFinder)
	mockRuler := new(MockRuler)

	patrol := &Patrol{
		Parser:         mockParser,
		ResourceFinder: mockFinder,
		Ruler:          mockRuler,
		Options:        DefaultOptions(),
	}

	resourceDef := &types.ResourceDefinition{
		Service:      "s3",
		ResourceType: "bucket",
		TagPolicy: &types.TagPolicy{
			MandatoryKeys: []string{"purpose"},
		},
	}

	resource := NewMockResource(
		"test-bucket",
		"bucket",
		"s3",
		"aws",
		"us-east-1",
		"123456789012",
		map[string]string{"purpose": "logs"},
	)

	resources := []cr.CloudResource{resource}
	policyBytes := []byte("test policy content")

	mockParser.On("ParseBytes", policyBytes).Return([]*types.ResourceDefinition{resourceDef}, nil)
	mockFinder.On("FindResources", ctx, "s3", "bucket").Return(resources, nil)
	mockRuler.On("ValidateAll", resources, resourceDef.TagPolicy).Return(1, 0)

	results, err := patrol.RunFromBytes(ctx, policyBytes)

	assert.NoError(t, err)
	assert.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, resourceDef, result.Definition)
	assert.Equal(t, resources, result.Resources)
	assert.Equal(t, 1, result.CompliantCount)
	assert.Equal(t, 0, result.NonCompliantCount)
	assert.Nil(t, result.Error)

	mockParser.AssertExpectations(t)
	mockFinder.AssertExpectations(t)
	mockRuler.AssertExpectations(t)
}

func TestRunWithSingleDefinition(t *testing.T) {
	ctx := context.Background()
	mockFinder := new(MockFinder)
	mockRuler := new(MockRuler)

	patrol := &Patrol{
		ResourceFinder: mockFinder,
		Ruler:          mockRuler,
		Options:        DefaultOptions(),
	}

	resourceDef := &types.ResourceDefinition{
		Service:      "ec2",
		ResourceType: "instance",
		TagPolicy: &types.TagPolicy{
			MandatoryKeys: []string{"name"},
		},
	}

	resource := NewMockResource(
		"i-123456",
		"instance",
		"ec2",
		"aws",
		"us-west-2",
		"123456789012",
		map[string]string{"name": "test-instance"},
	)

	mockFinder.On("FindResources", ctx, "ec2", "instance").Return([]cr.CloudResource{resource}, nil)
	mockRuler.On("ValidateAll", []cr.CloudResource{resource}, resourceDef.TagPolicy).Return(1, 0)

	results, err := patrol.Run(ctx, []*types.ResourceDefinition{resourceDef})

	assert.NoError(t, err)
	assert.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, resourceDef, result.Definition)
	assert.Equal(t, []cr.CloudResource{resource}, result.Resources)
	assert.Equal(t, 1, result.CompliantCount)
	assert.Equal(t, 0, result.NonCompliantCount)

	mockFinder.AssertExpectations(t)
	mockRuler.AssertExpectations(t)
}

func TestRunWithFindResourcesError(t *testing.T) {
	ctx := context.Background()
	mockFinder := new(MockFinder)
	mockRuler := new(MockRuler)

	patrol := &Patrol{
		ResourceFinder: mockFinder,
		Ruler:          mockRuler,
		Options:        DefaultOptions(),
	}

	resourceDef := &types.ResourceDefinition{
		Service:      "ec2",
		ResourceType: "instance",
		TagPolicy:    &types.TagPolicy{},
	}

	expectedErr := errors.New("resource finder error")
	mockFinder.On("FindResources", ctx, "ec2", "instance").Return(nil, expectedErr)

	results, err := patrol.Run(ctx, []*types.ResourceDefinition{resourceDef})

	assert.NoError(t, err)
	assert.Len(t, results, 1)

	result := results[0]
	assert.Equal(t, resourceDef, result.Definition)
	assert.Nil(t, result.Resources)
	assert.Equal(t, 0, result.CompliantCount)
	assert.Equal(t, 0, result.NonCompliantCount)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), expectedErr.Error())

	mockFinder.AssertExpectations(t)
}

func TestRunWithContextCancelled(t *testing.T) {
	mockFinder := new(MockFinder)
	mockRuler := new(MockRuler)

	patrol := &Patrol{
		ResourceFinder: mockFinder,
		Ruler:          mockRuler,
		Options:        DefaultOptions(),
	}

	resourceDef := &types.ResourceDefinition{
		Service:      "ec2",
		ResourceType: "instance",
		TagPolicy:    &types.TagPolicy{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := patrol.Run(ctx, []*types.ResourceDefinition{resourceDef})

	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.Empty(t, results)
}

func TestSummary(t *testing.T) {
	patrol := &Patrol{
		Options: DefaultOptions(),
	}

	compliantResult := Result{
		Definition: &types.ResourceDefinition{
			Service:      "ec2",
			ResourceType: "instance",
		},
		Resources:         make([]cr.CloudResource, 5),
		CompliantCount:    5,
		NonCompliantCount: 0,
	}

	nonCompliantResult := Result{
		Definition: &types.ResourceDefinition{
			Service:      "s3",
			ResourceType: "bucket",
		},
		Resources:         make([]cr.CloudResource, 3),
		CompliantCount:    1,
		NonCompliantCount: 2,
	}

	errorResult := Result{
		Definition: &types.ResourceDefinition{
			Service:      "rds",
			ResourceType: "instance",
		},
		Error: errors.New("test error"),
	}

	results := []Result{compliantResult, nonCompliantResult, errorResult}
	summary := patrol.Summary(results)

	assert.Contains(t, summary, "Processed 3 resource definitions")
	assert.Contains(t, summary, "Found 8 resources")
	assert.Contains(t, summary, "Compliant: 6 resources")
	assert.Contains(t, summary, "Non-compliant: 2 resources")
	assert.Contains(t, summary, "Errors: 1 resource definitions had errors")
}
