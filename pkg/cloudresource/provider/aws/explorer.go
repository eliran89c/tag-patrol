package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/document"
	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
)

// Provider implements the CloudResource Finder interface for AWS
type Provider struct {
	client  ResourceExplorerClient
	viewARN string
}

type providerConfig struct {
	profile string
	region  string
	viewARN string
}

// Option is a function that configures the AWS provider
type Option func(*providerConfig)

// WithProfile sets the AWS profile to use for authentication
func WithProfile(profile string) Option {
	return func(c *providerConfig) {
		c.profile = profile
	}
}

// WithRegion sets the AWS region to use for API calls
func WithRegion(region string) Option {
	return func(c *providerConfig) {
		c.region = region
	}
}

// WithViewARN sets the Resource Explorer view ARN to use for resource searches
func WithViewARN(arn string) Option {
	return func(c *providerConfig) {
		c.viewARN = arn
	}
}

// ResourceExplorerClient defines the interface for AWS Resource Explorer API interactions
type ResourceExplorerClient interface {
	Search(ctx context.Context, params *resourceexplorer2.SearchInput, optFns ...func(*resourceexplorer2.Options)) (*resourceexplorer2.SearchOutput, error)
}

// NewProvider creates a new AWS provider with the specified options
func NewProvider(ctx context.Context, opts ...Option) (*Provider, error) {
	cfg := &providerConfig{}

	for _, opt := range opts {
		opt(cfg)
	}

	var awsLoadOpts []func(*config.LoadOptions) error
	if cfg.profile != "" {
		awsLoadOpts = append(awsLoadOpts, config.WithSharedConfigProfile(cfg.profile))
	}
	if cfg.region != "" {
		awsLoadOpts = append(awsLoadOpts, config.WithRegion(cfg.region))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, awsLoadOpts...)
	if err != nil {
		return nil, fmt.Errorf("error loading AWS config: %w", err)
	}

	return &Provider{
		client:  resourceexplorer2.NewFromConfig(awsCfg),
		viewARN: cfg.viewARN,
	}, nil
}

// FindResources searches for AWS resources of the specified service and resource type
func (p *Provider) FindResources(ctx context.Context, serviceName, resourceName string) ([]cr.CloudResource, error) {
	var resources []cr.CloudResource
	var nextToken, view *string

	if p.viewARN != "" {
		view = awssdk.String(p.viewARN)
	}

	for {
		resp, err := p.client.Search(ctx, &resourceexplorer2.SearchInput{
			QueryString: awssdk.String(fmt.Sprintf("resourcetype:%s:%s", serviceName, resourceName)),
			ViewArn:     view,
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, r := range resp.Resources {
			awsResource := &AWSResource{
				ResourceARN:    *r.Arn,
				ResourceType:   *r.ResourceType,
				ServiceName:    *r.Service,
				AccountID:      *r.OwningAccountId,
				ResourceRegion: *r.Region,
				ResourceTags:   make(map[string]string),
			}

			for _, prop := range r.Properties {
				if *prop.Name != "tags" {
					continue
				}
				awsResource.ResourceTags = p.unmarshalTags(prop.Data)
			}

			resources = append(resources, awsResource)
		}

		if resp.NextToken != nil {
			nextToken = resp.NextToken
		} else {
			break
		}
	}

	return resources, nil
}

func (p *Provider) unmarshalTags(d document.Interface) map[string]string {
	type Tag struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	}

	var tags []*Tag
	var tagMap = make(map[string]string)

	if err := d.UnmarshalSmithyDocument(&tags); err == nil {
		for _, tag := range tags {
			tagMap[tag.Key] = tag.Value
		}
	}

	return tagMap
}
