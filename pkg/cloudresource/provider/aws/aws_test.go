package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/types"
	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type MockResourceExplorerClient struct {
	mock.Mock
}

func (m *MockResourceExplorerClient) Search(ctx context.Context, params *resourceexplorer2.SearchInput, optFns ...func(*resourceexplorer2.Options)) (*resourceexplorer2.SearchOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*resourceexplorer2.SearchOutput), args.Error(1)
}

func TestAWSResource(t *testing.T) {
	t.Run("Basic Properties", func(t *testing.T) {
		resource := &AWSResource{
			ResourceARN:    "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
			ResourceType:   "AWS::EC2::Instance",
			ServiceName:    "ec2",
			AccountID:      "123456789012",
			ResourceRegion: "us-west-2",
			ResourceTags:   map[string]string{"Name": "test-instance", "Environment": "dev"},
		}

		assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0", resource.ID())
		assert.Equal(t, "AWS::EC2::Instance", resource.Type())
		assert.Equal(t, "ec2", resource.Service())
		assert.Equal(t, "aws", resource.Provider())
		assert.Equal(t, "us-west-2", resource.Region())
		assert.Equal(t, "123456789012", resource.OwnerID())

		tags := resource.Tags()
		assert.Equal(t, 2, len(tags))
		assert.Equal(t, "test-instance", tags["Name"])
		assert.Equal(t, "dev", tags["Environment"])
	})

	t.Run("Empty Properties", func(t *testing.T) {
		resource := &AWSResource{}

		assert.Empty(t, resource.ID())
		assert.Empty(t, resource.Type())
		assert.Empty(t, resource.Service())
		assert.Equal(t, "aws", resource.Provider())
		assert.Empty(t, resource.Region())
		assert.Empty(t, resource.OwnerID())

		if tags := resource.Tags(); tags != nil {
			assert.Empty(t, tags)
		}
	})

	t.Run("Compliance Status", func(t *testing.T) {
		resource := &AWSResource{
			ResourceARN:  "arn:aws:ec2:us-west-2:123456789012:instance/i-test",
			ResourceTags: map[string]string{},
		}

		assert.True(t, resource.IsCompliant())
		assert.Empty(t, resource.ComplianceErrors())
		assert.Empty(t, resource.ComplianceWarnings())

		resource.AddComplianceError("Error 1")
		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceErrors(), 1)
		assert.Equal(t, "Error 1", resource.ComplianceErrors()[0].Message)

		resource.AddComplianceError("Error 2")
		resource.AddComplianceError("Error 3")
		assert.Len(t, resource.ComplianceErrors(), 3)
		assert.Equal(t, "Error 3", resource.ComplianceErrors()[2].Message)

		resource.AddComplianceWarning("Warning 1")
		resource.AddComplianceWarning("Warning 2")
		assert.False(t, resource.IsCompliant())
		assert.Len(t, resource.ComplianceWarnings(), 2)
		assert.Equal(t, "Warning 1", resource.ComplianceWarnings()[0].Message)
		assert.Equal(t, "Warning 2", resource.ComplianceWarnings()[1].Message)

		resource = &AWSResource{
			ResourceARN:  "arn:aws:ec2:us-west-2:123456789012:instance/i-test",
			ResourceTags: map[string]string{},
		}
		resource.AddComplianceWarning("Warning Only")
		assert.True(t, resource.IsCompliant()) // Still compliant with warnings
	})
}

func TestProviderOptions(t *testing.T) {
	tests := []struct {
		name    string
		options []Option
		profile string
		region  string
		viewARN string
	}{
		{
			name:    "No options",
			options: []Option{},
		},
		{
			name:    "With profile",
			options: []Option{WithProfile("test-profile")},
			profile: "test-profile",
		},
		{
			name:    "With region",
			options: []Option{WithRegion("us-east-1")},
			region:  "us-east-1",
		},
		{
			name:    "With viewARN",
			options: []Option{WithViewARN("arn:aws:resource-explorer-2:us-east-1:123456789012:view/test-view/1234567890")},
			viewARN: "arn:aws:resource-explorer-2:us-east-1:123456789012:view/test-view/1234567890",
		},
		{
			name: "With all options",
			options: []Option{
				WithProfile("test-profile"),
				WithRegion("us-east-1"),
				WithViewARN("arn:aws:resource-explorer-2:us-east-1:123456789012:view/test-view/1234567890"),
			},
			profile: "test-profile",
			region:  "us-east-1",
			viewARN: "arn:aws:resource-explorer-2:us-east-1:123456789012:view/test-view/1234567890",
		},
		{
			name: "Empty values",
			options: []Option{
				WithProfile(""),
				WithRegion(""),
				WithViewARN(""),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &providerConfig{}

			for _, opt := range tc.options {
				opt(cfg)
			}

			assert.Equal(t, tc.profile, cfg.profile)
			assert.Equal(t, tc.region, cfg.region)
			assert.Equal(t, tc.viewARN, cfg.viewARN)
		})
	}
}

func TestFindResources(t *testing.T) {
	t.Run("Single Resource", func(t *testing.T) {
		ctx := context.Background()
		mockClient := new(MockResourceExplorerClient)

		provider := &Provider{
			client:  mockClient,
			viewARN: "test-view-arn",
		}

		expectedQueryString := "resourcetype:ec2:instance"
		expectedInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   nil,
		}

		mockClient.On("Search", ctx, expectedInput).Return(&resourceexplorer2.SearchOutput{
			Resources: []types.Resource{
				{
					Arn:             aws.String("arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0"),
					ResourceType:    aws.String("AWS::EC2::Instance"),
					Service:         aws.String("ec2"),
					OwningAccountId: aws.String("123456789012"),
					Region:          aws.String("us-west-2"),
					Properties:      []types.ResourceProperty{}, // No properties means no tags
				},
			},
			NextToken: nil,
		}, nil)

		resources, err := provider.FindResources(ctx, "ec2", "instance")

		assert.NoError(t, err)
		assert.Equal(t, 1, len(resources))

		resource := resources[0]
		assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0", resource.ID())
		assert.Equal(t, "AWS::EC2::Instance", resource.Type())
		assert.Equal(t, "ec2", resource.Service())
		assert.Equal(t, "aws", resource.Provider())
		assert.Equal(t, "us-west-2", resource.Region())
		assert.Equal(t, "123456789012", resource.OwnerID())

		assert.Empty(t, resource.Tags())

		mockClient.AssertExpectations(t)
	})

	t.Run("Pagination", func(t *testing.T) {
		ctx := context.Background()
		mockClient := new(MockResourceExplorerClient)

		provider := &Provider{
			client:  mockClient,
			viewARN: "test-view-arn",
		}

		expectedQueryString := "resourcetype:ec2:instance"
		firstPageInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   nil,
		}

		secondPageInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   aws.String("next-page-token"),
		}

		mockClient.On("Search", ctx, firstPageInput).Return(&resourceexplorer2.SearchOutput{
			Resources: []types.Resource{
				{
					Arn:             aws.String("arn:aws:ec2:us-west-2:123456789012:instance/i-1"),
					ResourceType:    aws.String("AWS::EC2::Instance"),
					Service:         aws.String("ec2"),
					OwningAccountId: aws.String("123456789012"),
					Region:          aws.String("us-west-2"),
					Properties:      []types.ResourceProperty{},
				},
			},
			NextToken: aws.String("next-page-token"),
		}, nil)

		mockClient.On("Search", ctx, secondPageInput).Return(&resourceexplorer2.SearchOutput{
			Resources: []types.Resource{
				{
					Arn:             aws.String("arn:aws:ec2:us-west-2:123456789012:instance/i-2"),
					ResourceType:    aws.String("AWS::EC2::Instance"),
					Service:         aws.String("ec2"),
					OwningAccountId: aws.String("123456789012"),
					Region:          aws.String("us-west-2"),
					Properties:      []types.ResourceProperty{},
				},
			},
			NextToken: nil, // No more pages
		}, nil)

		resources, err := provider.FindResources(ctx, "ec2", "instance")

		assert.NoError(t, err)
		assert.Equal(t, 2, len(resources))

		assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:instance/i-1", resources[0].ID())
		assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:instance/i-2", resources[1].ID())

		mockClient.AssertExpectations(t)
	})

	t.Run("Empty Results", func(t *testing.T) {
		ctx := context.Background()
		mockClient := new(MockResourceExplorerClient)

		provider := &Provider{
			client:  mockClient,
			viewARN: "test-view-arn",
		}

		expectedQueryString := "resourcetype:ec2:instance"
		expectedInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   nil,
		}

		mockClient.On("Search", ctx, expectedInput).Return(&resourceexplorer2.SearchOutput{
			Resources: []types.Resource{},
			NextToken: nil,
		}, nil)

		resources, err := provider.FindResources(ctx, "ec2", "instance")

		assert.NoError(t, err)
		assert.Empty(t, resources)

		mockClient.AssertExpectations(t)
	})

	t.Run("Error Response", func(t *testing.T) {
		ctx := context.Background()
		mockClient := new(MockResourceExplorerClient)

		provider := &Provider{
			client:  mockClient,
			viewARN: "test-view-arn",
		}

		expectedQueryString := "resourcetype:ec2:instance"
		expectedInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   nil,
		}

		mockError := errors.New("AWS API error")
		mockClient.On("Search", ctx, expectedInput).Return(&resourceexplorer2.SearchOutput{}, mockError)

		resources, err := provider.FindResources(ctx, "ec2", "instance")

		assert.Error(t, err)
		assert.Nil(t, resources)
		assert.Equal(t, mockError, err)

		mockClient.AssertExpectations(t)
	})

	t.Run("Pagination with Error", func(t *testing.T) {
		ctx := context.Background()
		mockClient := new(MockResourceExplorerClient)

		provider := &Provider{
			client:  mockClient,
			viewARN: "test-view-arn",
		}

		expectedQueryString := "resourcetype:ec2:instance"
		firstPageInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   nil,
		}

		secondPageInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     aws.String("test-view-arn"),
			NextToken:   aws.String("next-page-token"),
		}

		mockClient.On("Search", ctx, firstPageInput).Return(&resourceexplorer2.SearchOutput{
			Resources: []types.Resource{
				{
					Arn:             aws.String("arn:aws:ec2:us-west-2:123456789012:instance/i-1"),
					ResourceType:    aws.String("AWS::EC2::Instance"),
					Service:         aws.String("ec2"),
					OwningAccountId: aws.String("123456789012"),
					Region:          aws.String("us-west-2"),
					Properties:      []types.ResourceProperty{},
				},
			},
			NextToken: aws.String("next-page-token"),
		}, nil)

		// Second page fails
		mockError := errors.New("AWS API pagination error")
		mockClient.On("Search", ctx, secondPageInput).Return(&resourceexplorer2.SearchOutput{}, mockError)

		resources, err := provider.FindResources(ctx, "ec2", "instance")

		assert.Error(t, err)
		assert.Nil(t, resources)

		mockClient.AssertExpectations(t)
	})

	t.Run("No ViewARN", func(t *testing.T) {
		ctx := context.Background()
		mockClient := new(MockResourceExplorerClient)

		// Provider with no ViewARN set
		provider := &Provider{
			client: mockClient,
		}

		expectedQueryString := "resourcetype:ec2:instance"
		expectedInput := &resourceexplorer2.SearchInput{
			QueryString: aws.String(expectedQueryString),
			ViewArn:     nil, // ViewArn should be nil when not set
			NextToken:   nil,
		}

		mockClient.On("Search", ctx, expectedInput).Return(&resourceexplorer2.SearchOutput{
			Resources: []types.Resource{
				{
					Arn:             aws.String("arn:aws:ec2:us-west-2:123456789012:instance/i-test"),
					ResourceType:    aws.String("AWS::EC2::Instance"),
					Service:         aws.String("ec2"),
					OwningAccountId: aws.String("123456789012"),
					Region:          aws.String("us-west-2"),
					Properties:      []types.ResourceProperty{},
				},
			},
			NextToken: nil,
		}, nil)

		resources, err := provider.FindResources(ctx, "ec2", "instance")

		assert.NoError(t, err)
		assert.Len(t, resources, 1)
		assert.Equal(t, "arn:aws:ec2:us-west-2:123456789012:instance/i-test", resources[0].ID())

		mockClient.AssertExpectations(t)
	})
}

func TestAWSResourceImplementsCloudResource(t *testing.T) {
	var resource cr.CloudResource = &AWSResource{}

	require.NotNil(t, resource.ID)
	require.NotNil(t, resource.Type)
	require.NotNil(t, resource.Service)
	require.NotNil(t, resource.Provider)
	require.NotNil(t, resource.Region)
	require.NotNil(t, resource.OwnerID)
	require.NotNil(t, resource.Tags)
	require.NotNil(t, resource.IsCompliant)
	require.NotNil(t, resource.AddComplianceError)
	require.NotNil(t, resource.AddComplianceWarning)
	require.NotNil(t, resource.ComplianceErrors)
	require.NotNil(t, resource.ComplianceWarnings)
}
