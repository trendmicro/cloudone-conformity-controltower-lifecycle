# Cloud One Conformity Control Tower lifecycle implementation guide

[Cloud One Conformity] helps you to continuously improve your security and compliance posture for AWS infrastructure 
through automated checks and clear remediation steps.

[Cloud One Conformity]: https://cloudconformity.com

This guide provides details on how to integrate provisioning of Cloud One Conformity with [AWS Control Tower] to ensure 
that every account added through Control Tower Account Factory is automatically provisioned in Cloud One Conformity, 
providing centralized visibility to potential mis-configurations before any services have been provisioned.

[AWS Control Tower]: https://aws.amazon.com/controltower/

## Overview

The Lifecycle Hook solution provides a cloudformation template which, when launched in the Control Tower Master Account, 
deploys AWS infrastructure to ensure Conformity monitors each Account Factory AWS account automatically. The solution 
consists of 2 lambda functions; one to manage our role and access Conformity and another to manage the lifecycle of the 
first lambda. AWS Secrets Manager is leveraged to store the API key for Conformity in the Master account, and 
a CloudWatch Events rule is configured to trigger the customization lambda when a Control Tower account is successfully 
deployed.

### Usage

You will first need to [generate an API key for Conformity] and note the [region endpoint] for your Conformity 
Organization. Once you've recorded these items, log into the Control Tower master AWS account and [launch the 
lifecycle template]. Select the AWS region for your Control Tower deployment before entering the Conformity ApiKey 
and selecting your Conformity endpoint region then continue to complete launching the stack. On the last page of the 
wizard, be sure to select the checkbox to acknowledge that this template may create IAM resources.

[generate an API key for Conformity]:https://aws.amazon.com/controltower/
[region endpoint]:https://github.com/cloudconformity/documentation-api#endpoints
[launch the lifecycle template]:https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://s3.amazonaws.com/trend-micro-cloud-one-conformity-controltower-lifecycle/Trend-Micro-Conformity-LifeCycle.yaml&stackName=ConformityLifeCycleHook

### Implementation

Once the stack is launched, a cloudwatch event rule will trigger the lifecycle lambda for each successful Control Tower
Successful CreateManagedAccount event. The lifecycle lambda function will retrieve the Conformity ApiKey from AWS
Secrets Manager, then get the External ID for your organization from the Conformity API. Next the lambda function will
assume the ControlTowerExecution role in the target Managed Account in order to create the necessary cross account 
role and associated policy. Finally, a call will be made to the Conformity API to add this Managed Account to your  
Conformity Organization.

### Upgrade

As new rules are added to Conformity, it may be necessary on occasion to update the permissions for the application's 
cross account role. To update the role deployed by the lifecycle hook, update the conformity stack with the latest 
template which can be found at its original url. The parameter values should not be modified from their original values 
unless directed by Trend Micro Support.

[original url]:https://s3.amazonaws.com/trend-micro-cloud-one-conformity-controltower-lifecycle/Trend-Micro-Conformity-LifeCycle.yaml

### Removal

To remove the lifecycle hook, identify and delete the cloudformation stack. Protection for Managed Accounts which  
have already been added will remain in place. For details on removing an account subscription for conformity see 
the help documentation.


[removing an account subscriptio]:https://www.cloudconformity.com/help/organisation/subscriptions.html
