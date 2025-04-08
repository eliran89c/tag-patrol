# TagPatrol

TagPatrol is a Go application that scans cloud resources and validates their tags against defined policies. It helps maintain governance and consistency in resource tagging across your cloud environments.

[![GitHub Release](https://img.shields.io/github/v/release/eliran89c/tag-patrol)](https://github.com/eliran89c/tag-patrol/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/eliran89c/tag-patrol)](https://goreportcard.com/report/github.com/eliran89c/tag-patrol)
[![License](https://img.shields.io/github/license/eliran89c/tag-patrol)](https://github.com/eliran89c/tag-patrol/blob/main/LICENSE)

## Features

- **Tag Policy Enforcement**: Define comprehensive tag policies for your cloud resources
- **Validation Rules**: Enforce mandatory tags, validate tag values (by type, regex, allowed values, numeric ranges)
- **Conditional Rules**: Apply rules based on conditions (e.g., if `environment=prod`, then `owner` tag must exist)
- **Multi-account Support**: Scan resources across your entire AWS organization
- **Extensible Design**: Currently supports AWS with more cloud providers coming soon

## Prerequisites

- **AWS Environment**: Currently, TagPatrol only works with AWS resources
- **AWS Resource Explorer**: TagPatrol requires AWS Resource Explorer to be enabled in your AWS environment
- **For multi-account setups**: AWS Organizations and properly configured Resource Explorer (see the [CFN setup](#multi-account-setup))

## Installation

### Homebrew

```bash
brew install eliran89c/tap/tagpatrol
```

### Download Binary

Download the latest release from the [GitHub releases page](https://github.com/eliran89c/tag-patrol/releases).

```bash
# Example for Linux amd64
curl -L https://github.com/eliran89c/tag-patrol/releases/latest/download/tagpatrol-linux-amd64 -o tagpatrol
chmod +x tagpatrol
sudo mv tagpatrol /usr/local/bin/
```

### Go Install

```bash
go install github.com/eliran89c/tag-patrol@latest
```

### Build from Source

```bash
git clone https://github.com/eliran89c/tag-patrol.git
cd tag-patrol
go build -o tagpatrol
```

## Usage

TagPatrol requires a policy file in YAML format that defines the tag requirements for your resources.

### Basic Usage

```bash
# Scan AWS resources in your default profile and region
tagpatrol aws --policy policy.yaml

# Specify a region
tagpatrol aws --policy policy.yaml --region us-west-2

# Use a specific AWS profile
tagpatrol aws --policy policy.yaml --profile prod-account

# Use a specific Resource Explorer view ARN (for organization-wide scanning)
tagpatrol aws --policy policy.yaml --view-arn arn:aws:resource-explorer-2:us-west-2:123456789012:view/OrganizationView
```

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `--policy` | Path to the policy file (YAML format). **Required** |
| `--region` | AWS region to use |
| `--profile` | AWS profile to use |
| `--view-arn` | ARN of the Resource Explorer view to use (useful for org-wide scanning) |

### Policy File Format

The policy file is the core of TagPatrol, defining what tags are required and how they should be validated. Here's the structure:

```yaml
# Optional blueprint definitions (reusable tag policies)
blueprints:
  base:
    mandatoryKeys:
      - environment
      - owner
    validations:
      environment:
        type: string
        allowedValues:
          - prod
          - staging
          - dev

# Resource definitions (required)
resources:
  # AWS service name
  ec2:
    # Resource type 
    instance:
      # Extend from blueprints (optional)
      extends:
        - blueprints.base
      # Additional mandatory keys
      mandatoryKeys:
        - name
      # Tag validations
      validations:
        name:
          type: string
          regex: "^[a-z0-9-]+$"
      # Conditional rules
      rules:
        - when:
            equals:
              key: environment
              value: prod
          then:
            mustContainKeys:
              - cost-center
```

### Example Policy

Here's a complete policy example covering various validation types:

```yaml
blueprints:
  base:
    mandatoryKeys:
      - environment
      - owner
    validations:
      environment:
        type: string
        allowedValues:
          - prod
          - staging
          - dev
      owner:
        type: string
        regex: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"

  production:
    rules:
      - when:
          equals:
            key: environment
            value: prod
          then:
            mustContainKeys:
              - cost-center
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
        ttl:
          type: int
          minValue: 1
          maxValue: 90

    volume:
      extends:
        - blueprints.base
      mandatoryKeys:
        - attached-to
      
  s3:
    bucket:
      extends:
        - blueprints.base
      mandatoryKeys:
        - purpose
      validations:
        public:
          type: bool
      rules:
        - when:
            equals:
              key: public
              value: "true"
          then:
            mustContainKeys:
              - security-exception
```

### Validation Types

TagPatrol supports the following validation types:

| Type | Description | Additional Validations |
|------|-------------|------------------------|
| `string` | Validates string values | `regex`, `allowedValues` |
| `int` | Validates integer values | `minValue`, `maxValue`, `allowedValues` |
| `bool` | Validates boolean values (`true`/`false`) | None |

### Rule Conditions and Actions

TagPatrol rules consist of a `when` condition and a `then` action. Here's a comprehensive overview:

#### When Conditions

| Condition | Description | Example |
|-----------|-------------|---------|
| `equals` | Checks if tag value equals a specific value | `environment` equals `prod` |
| `notEquals` | Checks if tag value doesn't equal a specific value | `environment` not equals `dev` |
| `exists` | Checks if the tag exists | `temporary` tag exists |
| `contains` | Checks if tag value contains a substring | `description` contains `test` |
| `greaterThan` | Checks if numeric tag value is greater than a value | `count` greater than `10` |
| `lessThan` | Checks if numeric tag value is less than a value | `count` less than `5` |
| `and` | Combines multiple conditions with AND logic | Both `environment=prod` AND `critical` exists |
| `or` | Combines multiple conditions with OR logic | Either `environment=prod` OR `environment=staging` |

#### Then Actions

| Action | Description | Effect on Compliance | Example |
|--------|-------------|----------------------|---------|
| `mustContainKeys` | Specifies tags that must exist if the condition is met | Non-compliant if any required tag is missing | Prod resources must have `cost-center` |
| `shouldContainKeys` | Specifies tags that should exist if the condition is met | Warning only (still compliant) | Dev resources should have `owner` |
| `error` | Custom error message to display | Resource marked as non-compliant | "backup=true is not allowed when env=dev" |
| `warn` | Custom warning message to display | Warning only (still compliant) | "Consider adding backup-policy tag" |

#### Example Rule Patterns

| Use Case | When | Then | Effect |
|----------|------|------|--------|
| Production resources need cost tracking | `when: equals: {key: environment, value: prod}` | `then: mustContainKeys: [cost-center]` | Non-compliant if cost-center missing on prod resources |
| Temporary resources need an expiration | `when: exists: {key: temporary}` | `then: mustContainKeys: [ttl]` | Non-compliant if ttl missing on temporary resources |
| Critical prod resources need backup policy | `when: and: [{equals: {key: environment, value: prod}}, {exists: {key: critical}}]` | `then: mustContainKeys: [backup-policy]` | Non-compliant if backup-policy missing on critical prod resources |
| Prod or staging resources should have owner | `when: or: [{equals: {key: environment, value: prod}}, {equals: {key: environment, value: staging}}]` | `then: shouldContainKeys: [owner]` | Warning only (still compliant) |

## Multi-Account Setup

For scanning resources across multiple AWS accounts, you need to set up AWS Resource Explorer properly:

1. Use the CloudFormation templates in the [cfn directory](./cfn/) to deploy Resource Explorer across your AWS organization
2. See the [cfn README](./cfn/README.md) for detailed setup instructions

After setup, you can run TagPatrol with the organization view:

```bash
tagpatrol aws --policy policy.yaml --view-arn arn:aws:resource-explorer-2:region:account-id:view/OrganizationView
```