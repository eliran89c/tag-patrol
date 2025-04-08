package aws

import (
	cr "github.com/eliran89c/tag-patrol/pkg/cloudresource"
)

// AWSResource represents an AWS resource with its metadata and compliance status
type AWSResource struct {
	ResourceARN    string
	ResourceType   string
	ServiceName    string
	AccountID      string
	ResourceRegion string
	ResourceTags   map[string]string
	Errors         []*cr.ComplianceError
	Warnings       []*cr.ComplianceWarning
}

// ID returns the AWS ARN of the resource
func (r *AWSResource) ID() string {
	return r.ResourceARN
}

// Type returns the AWS resource type
func (r *AWSResource) Type() string {
	return r.ResourceType
}

// Service returns the AWS service name
func (r *AWSResource) Service() string {
	return r.ServiceName
}

// Provider returns the cloud provider name as "aws"
func (r *AWSResource) Provider() string {
	return "aws"
}

// Region returns the AWS region where the resource is located
func (r *AWSResource) Region() string {
	return r.ResourceRegion
}

// OwnerID returns the AWS account ID that owns the resource
func (r *AWSResource) OwnerID() string {
	return r.AccountID
}

// Tags returns the resource tags as a map of key-value pairs
func (r *AWSResource) Tags() map[string]string {
	return r.ResourceTags
}

// IsCompliant returns true if the resource has no compliance errors
func (r *AWSResource) IsCompliant() bool {
	return len(r.Errors) == 0
}

// AddComplianceError adds a new compliance error with the given message
func (r *AWSResource) AddComplianceError(msg string) {
	r.Errors = append(r.Errors, &cr.ComplianceError{Message: msg})
}

// AddComplianceWarning adds a new compliance warning with the given message
func (r *AWSResource) AddComplianceWarning(msg string) {
	r.Warnings = append(r.Warnings, &cr.ComplianceWarning{Message: msg})
}

// ComplianceErrors returns all compliance errors for this resource
func (r *AWSResource) ComplianceErrors() []*cr.ComplianceError {
	return r.Errors
}

// ComplianceWarnings returns all compliance warnings for this resource
func (r *AWSResource) ComplianceWarnings() []*cr.ComplianceWarning {
	return r.Warnings
}
