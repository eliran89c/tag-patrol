package patrol

import (
	"context"
	"fmt"
	"sync"

	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
	"github.com/eliran89c/tag-patrol/pkg/policy"
	ptypes "github.com/eliran89c/tag-patrol/pkg/policy/types"
	"github.com/eliran89c/tag-patrol/pkg/ruler"
)

// Result represents the outcome of validating a resource type against a policy
type Result struct {
	Definition        *ptypes.ResourceDefinition
	Resources         []cr.CloudResource
	CompliantCount    int
	NonCompliantCount int
	Error             error
}

// Options configures the behavior of the Patrol
type Options struct {
	ConcurrentWorkers int
	StopOnError       bool
}

// DefaultOptions returns the default Patrol options
func DefaultOptions() *Options {
	return &Options{
		ConcurrentWorkers: 10,
		StopOnError:       false,
	}
}

// Patrol is the main orchestrator for resource compliance checking
type Patrol struct {
	Parser         Parser
	Options        *Options
	ResourceFinder Finder
	Ruler          Ruler
}

// Ruler defines the interface for validating resources against tag policies
type Ruler interface {
	Validate(resource cr.CloudResource, policy *ptypes.TagPolicy)
	ValidateAll(resources []cr.CloudResource, policy *ptypes.TagPolicy) (int, int)
}

// Parser defines the interface for parsing tag policies
type Parser interface {
	ParseFile(path string) ([]*ptypes.ResourceDefinition, error)
	ParseBytes(data []byte) ([]*ptypes.ResourceDefinition, error)
	ParsePolicy(policy *ptypes.Policy) ([]*ptypes.ResourceDefinition, error)
}

// Finder defines the interface for finding cloud resources
type Finder interface {
	FindResources(ctx context.Context, service, resourceType string) ([]cr.CloudResource, error)
}

// New creates a new Patrol with the specified resource finder and options
func New(resourceFinder Finder, options *Options) *Patrol {
	if options == nil {
		options = DefaultOptions()
	}

	return &Patrol{
		Parser:         policy.NewParser(),
		ResourceFinder: resourceFinder,
		Ruler:          ruler.NewRuler(),
		Options:        options,
	}
}

// RunFromFile loads a policy from a file and runs the patrol
func (p *Patrol) RunFromFile(ctx context.Context, policyPath string) ([]Result, error) {
	rdefs, err := p.Parser.ParseFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("error parsing policy file: %w", err)
	}

	return p.Run(ctx, rdefs)
}

// RunFromBytes loads a policy from a byte slice and runs the patrol
func (p *Patrol) RunFromBytes(ctx context.Context, policyContent []byte) ([]Result, error) {
	rdefs, err := p.Parser.ParseBytes(policyContent)
	if err != nil {
		return nil, fmt.Errorf("error parsing policy content: %w", err)
	}

	return p.Run(ctx, rdefs)
}

// RunFromPolicy loads a policy from a Policy object and runs the patrol
func (p *Patrol) RunFromPolicy(ctx context.Context, policy *ptypes.Policy) ([]Result, error) {
	rdefs, err := p.Parser.ParsePolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("error parsing policy: %w", err)
	}
	return p.Run(ctx, rdefs)
}

// Run executes the patrol with the given resource definitions
func (p *Patrol) Run(ctx context.Context, definitions []*ptypes.ResourceDefinition) ([]Result, error) {
	var (
		wg           sync.WaitGroup
		resultsMutex sync.Mutex
		results      = make([]Result, 0, len(definitions))
		semaphore    = make(chan struct{}, p.Options.ConcurrentWorkers)
		errorCh      = make(chan error, 1)
		done         = make(chan struct{})
	)

	go func() {
		wg.Wait()
		close(done)
	}()

	for _, definition := range definitions {
		select {
		case err := <-errorCh:
			if p.Options.StopOnError {
				return results, err
			}
		default:
		}

		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		wg.Add(1)
		semaphore <- struct{}{}

		go func(def *ptypes.ResourceDefinition) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result := Result{
				Definition: def,
			}

			resources, err := p.ResourceFinder.FindResources(ctx, def.Service, def.ResourceType)
			if err != nil {
				result.Error = fmt.Errorf("error finding resources for %s.%s: %w", def.Service, def.ResourceType, err)

				resultsMutex.Lock()
				results = append(results, result)
				resultsMutex.Unlock()

				if p.Options.StopOnError {
					select {
					case errorCh <- result.Error:
					default:
					}
				}
				return
			}

			compliant, nonCompliant := p.Ruler.ValidateAll(resources, def.TagPolicy)

			result.Resources = resources
			result.CompliantCount = compliant
			result.NonCompliantCount = nonCompliant

			resultsMutex.Lock()
			results = append(results, result)
			resultsMutex.Unlock()
		}(definition)
	}

	select {
	case <-done:
	case <-ctx.Done():
		return results, ctx.Err()
	case err := <-errorCh:
		return results, err
	}

	return results, nil
}

// Summary generates a summary report of the patrol results
func (p *Patrol) Summary(results []Result) string {
	var (
		totalResources        int
		totalCompliant        int
		totalNonCompliant     int
		definitionsWithErrors int
	)

	for _, result := range results {
		if result.Error != nil {
			definitionsWithErrors++
			continue
		}

		totalResources += len(result.Resources)
		totalCompliant += result.CompliantCount
		totalNonCompliant += result.NonCompliantCount
	}

	return fmt.Sprintf(
		"Summary:\n"+
			"  Processed %d resource definitions\n"+
			"  Found %d resources\n"+
			"  Compliant: %d resources (%.1f%%)\n"+
			"  Non-compliant: %d resources (%.1f%%)\n"+
			"  Errors: %d resource definitions had errors\n",
		len(results),
		totalResources,
		totalCompliant,
		percentage(totalCompliant, totalResources),
		totalNonCompliant,
		percentage(totalNonCompliant, totalResources),
		definitionsWithErrors,
	)
}

func percentage(a, b int) float64 {
	if b == 0 {
		return 0.0
	}
	return float64(a) * 100.0 / float64(b)
}
