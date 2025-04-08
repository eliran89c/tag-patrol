package cmd

import (
	"context"
	"fmt"

	"github.com/eliran89c/tag-patrol/pkg/cloudresource/provider/aws"
	"github.com/eliran89c/tag-patrol/pkg/patrol"
	"github.com/spf13/cobra"
)

var (
	viewARN string
	profile string
	region  string
)

var (
	awsCmd = &cobra.Command{
		Use:   "aws",
		Short: "Scan AWS resources",
		Long:  "Scan AWS resources using Resource Explorer and validate their tags against a defined policy.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			var providerOpts []aws.Option
			if profile != "" {
				providerOpts = append(providerOpts, aws.WithProfile(profile))
			}
			if region != "" {
				providerOpts = append(providerOpts, aws.WithRegion(region))
			}
			if viewARN != "" {
				providerOpts = append(providerOpts, aws.WithViewARN(viewARN))
			}
			provider, err := aws.NewProvider(ctx, providerOpts...)
			if err != nil {
				return fmt.Errorf("error creating AWS provider: %w", err)
			}

			p := patrol.New(provider, &patrol.Options{StopOnError: true, ConcurrentWorkers: 10})
			results, err := p.RunFromFile(ctx, policyPath)
			if err != nil {
				return fmt.Errorf("error executing patrol: %w", err)
			}

			// TODO: create a `reporter` package to handle different output formats
			fmt.Println(p.Summary(results))

			for _, result := range results {
				if result.Error != nil {
					fmt.Printf("Error processing %s.%s: %v\n",
						result.Definition.Service,
						result.Definition.ResourceType,
						result.Error)
					continue
				}

				if result.NonCompliantCount > 0 {
					fmt.Printf("\nResource: %s.%s - Compliant: %d, Non-compliant: %d\n",
						result.Definition.Service,
						result.Definition.ResourceType,
						result.CompliantCount,
						result.NonCompliantCount)

					for _, resource := range result.Resources {
						if !resource.IsCompliant() {
							fmt.Printf("  Non-compliant resource: %s\n", resource.ID())

							for _, e := range resource.ComplianceErrors() {
								fmt.Printf("    Error: %s\n", e.Message)
							}

							for _, w := range resource.ComplianceWarnings() {
								fmt.Printf("    Warning: %s\n", w.Message)
							}
						}
					}
				}
			}
			return nil
		},
	}
)

func init() {
	awsCmd.PersistentFlags().StringVar(&viewARN, "view-arn", "", "The ARN of the Resource Explorer view to use.")
	awsCmd.PersistentFlags().StringVar(&profile, "profile", "", "The AWS profile to use.")
	awsCmd.PersistentFlags().StringVar(&region, "region", "", "The AWS region to use.")
}
