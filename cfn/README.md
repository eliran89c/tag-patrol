# AWS Resource Explorer Setup for TagPatrol

This directory contains CloudFormation templates to set up AWS Resource Explorer for use with TagPatrol in a multi-account environment.

## Overview

The `stackset.yaml` template deploys AWS Resource Explorer across your organization using CloudFormation StackSets. This enables TagPatrol to scan resources across all your AWS accounts and regions.

## How it Works

The CloudFormation template:

1. Creates a Resource Explorer index in each account and region in your organization
2. Creates an aggregator index in your main region
3. Sets up views that can be used by TagPatrol to query resources
4. Configures organization-level views when deployed to a delegated admin account

## Deployment

### Prerequisites

- AWS Organizations set up
- CloudFormation StackSets permission configured
- Administrative access to the management account or delegated admin account

### Parameters

| Parameter | Description |
|-----------|-------------|
| `MainRegion` | The region where the aggregator index will be created |
| `OrgDelegatedAdminAccount` | The AWS account ID that is the delegated admin for Resource Explorer |
| `OrgID` | Your AWS Organization ID |
| `ManagementAccountID` | Your AWS Management Account ID |

### Deployment Steps

1. Log in to the AWS Management Console in your management account or delegated admin account
2. Navigate to CloudFormation > StackSets
3. Create a new StackSet using the `stackset.yaml` template
4. Provide the required parameters
5. Select deployment targets (accounts and regions)
6. Deploy the StackSet

## Using with TagPatrol

After deployment, you can use TagPatrol with the created Resource Explorer views:

1. For account-specific scanning:
   
```bash
tagpatrol aws --policy policy.yaml --region your-main-region
```

2. For organization-wide scanning (from delegated admin account):
   
```bash
tagpatrol aws --policy policy.yaml --view-arn ORGANIZATION_VIEW_ARN
```

> **Note:** The organization-level view ARN is provided as an output from the CloudFormation stack. You can find it in the Outputs tab of the deployed stack in the delegated admin account. Use this ARN with the `--view-arn` flag for organization-wide scanning.

## Resources Created

- **Index**: A Resource Explorer index in each account/region
- **MainView**: A view in the main region for account-specific scanning
- **OrganizationView**: A view in the delegated admin account for organization-wide scanning (when conditions are met)
- **DefaultViewAssociation**: Associates the main view as the default

## Troubleshooting

- Ensure the service-linked role for Resource Explorer exists in each account
- Verify that the delegated admin account has the necessary permissions
- Check CloudTrail logs for any permission issues during deployment
- If indexes fail to create, check for existing indexes that might conflict