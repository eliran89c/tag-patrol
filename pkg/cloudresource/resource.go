package cloudresource

// CloudResource represents a generic cloud resource with tags
type CloudResource interface {
	// ID returns the unique identifier for the resource
	ID() string

	// Type returns the resource type
	Type() string

	// Service returns the service name (e.g. EC2, S3, etc.)
	Service() string

	// Provider returns the cloud provider name
	Provider() string

	// Region returns the region where the resource is located
	Region() string

	// OwnerID returns the owner(e.g. account/project/subscription, etc.) ID that owns the resource
	OwnerID() string

	// Tags returns the resource tags
	Tags() map[string]string

	// IsCompliant returns whether the resource is compliant
	IsCompliant() bool

	// AddComplianceError adds a compliance error to the resource
	AddComplianceError(msg string)

	// AddComplianceWarning adds a compliance warning to the resource
	AddComplianceWarning(msg string)

	// ComplianceError returns compliance validation errors
	ComplianceErrors() []*ComplianceError

	// ComplianceWarning returns compliance validation warnings
	ComplianceWarnings() []*ComplianceWarning
}

// ComplianceError represents a warning encountered during tag validation.
type ComplianceError struct {
	Message string
}

// ComplianceWarning represents a warning encountered during tag validation.
type ComplianceWarning struct {
	Message string
}
