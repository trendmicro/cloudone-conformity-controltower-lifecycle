import c1cconnectorapi
import boto3
from botocore.exceptions import ClientError
import base64
import logging
import json
import os

logger = logging.getLogger()

APIKEY_SECRET_ID = "TrendMicro/CloudOne/ConformityApiKey"
ControlTowerRoleName = "AWSControlTowerExecution"
CloudOneConformityAccountId = "717210094962"
IamRoleName = "CloudOneConformityConnectorRole"
IamPolicyName = "CloudOneConformityConnectorPolicy"


class ConformityPolicyDoc:
    def __init__(self):
        self.part1 = ""
        self.part2 = ""
        self.load_policy_parts()

    def load_policy_parts(self):
        s3_client = boto3.client('s3')
        s3_request = s3_client.get_object(Bucket=os.environ['ConformityPolicyBucket'],
                                          Key='iam-policies.json')
        list_of_policies = json.loads(s3_request['Body'].read().decode('utf-8'))
        self.part1 = json.dumps(list_of_policies[0].get("document"))
        self.part2 = json.dumps(list_of_policies[1].get("document"))

    def part1(self):
        return self.part1

    def part2(self):
        return self.part2


def get_api_key():
    client = boto3.client('secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=APIKEY_SECRET_ID
        )
    except ClientError as e:
        logger.info('Failed to retrieve secret')
        logger.info(e)
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = json.loads(get_secret_value_response['SecretString'])['ApiKey']
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            logger.info("password binary:" + decoded_binary_secret)
            password = decoded_binary_secret.password
            return password


def get_assume_role_policy_document(c1c_connector):
    assume_role_policy_document = {
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {
                    "AWS": CloudOneConformityAccountId
                },
                "Condition": {
                    "StringEquals": {
                        "sts:ExternalId": c1c_connector.get_external_id()
                    }
                },
                "Sid": ""
            }
        ],
        "Version": "2012-10-17"
    }
    return json.dumps(assume_role_policy_document)


static_policy_document_part1 = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "acm:DescribeCertificate",
                "acm:ListCertificates",
                "acm:ListTagsForCertificate",
                "apigateway:GET",
                "autoscaling:DescribeAccountLimits",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeLoadBalancerTargetGroups",
                "autoscaling:DescribeLoadBalancers",
                "autoscaling:DescribeNotificationConfigurations",
                "autoscaling:DescribeTags",
                "aws-portal:ViewBilling",
                "aws-portal:ViewUsage",
                "budgets:ViewBudget",
                "cloudformation:DescribeAccountLimits",
                "cloudformation:DescribeStackDriftDetectionStatus",
                "cloudformation:DescribeStacks",
                "cloudformation:DetectStackDrift",
                "cloudformation:GetStackPolicy",
                "cloudformation:ListStacks",
                "cloudfront:GetDistribution",
                "cloudfront:ListDistributions",
                "cloudfront:ListTagsForResource",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors",
                "cloudtrail:ListTags",
                "cloudwatch:DescribeAlarms",
                "cloudwatch:DescribeAlarmsForMetric",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:ListMetrics",
                "config:DescribeComplianceByConfigRule",
                "config:DescribeConfigRules",
                "config:DescribeConfigurationRecorderStatus",
                "config:DescribeConfigurationRecorders",
                "config:DescribeDeliveryChannelStatus",
                "config:DescribeDeliveryChannels",
                "config:GetComplianceDetailsByConfigRule",
                "config:GetResourceConfigHistory",
                "config:GetResources",
                "config:GetTagKeys",
                "dynamodb:DescribeContinuousBackups",
                "dynamodb:DescribeLimits",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables",
                "dynamodb:ListTagsOfResource",
                "ec2:DescribeAccountAttributes",
                "ec2:DescribeAddresses",
                "ec2:DescribeEgressOnlyInternetGateways",
                "ec2:DescribeFlowLogs",
                "ec2:DescribeImages",
                "ec2:DescribeInstanceAttribute",
                "ec2:DescribeInstanceStatus",
                "ec2:DescribeInstances",
                "ec2:DescribeInternetGateways",
                "ec2:DescribeKeyPairs",
                "ec2:DescribeNatGateways",
                "ec2:DescribeNetworkAcls",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeReservedInstances",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroupReferences",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSnapshots",
                "ec2:DescribeSnapshotAttribute",
                "ec2:DescribeSubnets",
                "ec2:DescribeTags",
                "ec2:DescribeVolumes",
                "ec2:DescribeVpcAttribute",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeVpcPeeringConnections",
                "ec2:DescribeVpcs",
                "ec2:DescribeVpnConnections",
                "ec2:DescribeVpnGateways",
                "elasticfilesystem:DescribeFileSystems",
                "elasticfilesystem:DescribeTags",
                "elasticmapreduce:DescribeCluster",
                "elasticmapreduce:ListClusters",
                "elasticmapreduce:ListInstances",
                "es:DescribeElasticsearchDomain",
                "es:DescribeElasticsearchDomainConfig",
                "es:DescribeElasticsearchDomains",
                "es:DescribeElasticsearchInstanceTypeLimits",
                "es:DescribeReservedElasticsearchInstanceOfferings",
                "es:DescribeReservedElasticsearchInstances",
                "es:ListDomainNames",
                "es:ListElasticsearchInstanceTypes",
                "es:ListElasticsearchVersions",
                "es:ListTags",
                "elasticache:DescribeCacheClusters",
                "elasticache:DescribeReplicationGroups",
                "elasticache:DescribeReservedCacheNodes",
                "elasticache:ListTagsForResource",
                "elasticloadbalancing:DescribeListeners",
                "elasticloadbalancing:DescribeLoadBalancerAttributes",
                "elasticloadbalancing:DescribeLoadBalancerPolicies",
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTags",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth",
                "iam:GenerateCredentialReport",
                "iam:GetAccessKeyLastUsed",
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:GetCredentialReport",
                "iam:GetGroup",
                "iam:GetGroupPolicy",
                "iam:GetLoginProfile",
                "iam:GetOpenIDConnectProvider",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:GetSAMLProvider",
                "iam:GetServerCertificate",
                "iam:GetUser",
                "iam:GetUserPolicy",
                "iam:ListAccessKeys",
                "iam:ListAccountAliases",
                "iam:ListAttachedGroupPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListEntitiesForPolicy",
                "iam:ListGroupPolicies",
                "iam:ListGroups",
                "iam:ListInstanceProfiles",
                "iam:ListInstanceProfilesForRole",
                "iam:ListMFADevices",
                "iam:ListOpenIDConnectProviders",
                "iam:ListPolicies",
                "iam:ListPolicyVersions",
                "iam:ListRolePolicies",
                "iam:ListRoleTags",
                "iam:ListRoles",
                "iam:ListSAMLProviders",
                "iam:ListSSHPublicKeys",
                "iam:ListServerCertificates",
                "iam:ListUserPolicies",
                "iam:ListUserTags",
                "iam:ListUsers",
                "iam:ListVirtualMFADevices",
                "kms:DescribeKey",
                "kms:GetKeyPolicy",
                "kms:GetKeyRotationStatus",
                "kms:ListAliases",
                "kms:ListGrants",
                "kms:ListKeyPolicies",
                "kms:ListKeys",
                "kms:ListResourceTags",
                "lambda:GetAccountSettings",
                "lambda:GetFunctionConfiguration",
                "lambda:GetPolicy",
                "lambda:ListEventSourceMappings",
                "lambda:ListFunctions",
                "lambda:ListTags",
                "logs:DescribeLogGroups",
                "logs:DescribeMetricFilters",
                "rds:DescribeAccountAttributes",
                "rds:DescribeDBClusters",
                "rds:DescribeDBInstances",
                "rds:DescribeDBSecurityGroups",
                "rds:DescribeDBSnapshotAttributes",
                "rds:DescribeDBSnapshots",
                "rds:DescribeEvents",
                "rds:DescribeEventSubscriptions",
                "rds:DescribeReservedDBInstances",
                "rds:ListTagsForResource",
                "redshift:DescribeClusterParameterGroups",
                "redshift:DescribeClusterParameters",
                "redshift:DescribeClusters",
                "redshift:DescribeLoggingStatus",
                "redshift:DescribeReservedNodes",
                "redshift:DescribeTags",
                "route53:GetGeoLocation",
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "route53:ListTagsForResource",
                "route53domains:ListDomains",
                "route53domains:ListTagsForDomain",
                "ses:GetIdentityDkimAttributes",
                "ses:GetIdentityPolicies",
                "ses:GetIdentityVerificationAttributes",
                "ses:ListIdentities",
                "ses:ListIdentityPolicies",
                "sns:GetTopicAttributes",
                "sns:ListTopics",
                "sns:ListSubscriptionsByTopic",
                "sns:ListTagsForResource",
                "sqs:GetQueueAttributes",
                "sqs:ListQueues",
                "sqs:ListQueueTags",
                "tag:GetResources",
                "tag:GetTagKeys",
                "tag:GetTagValues"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}

static_policy_document_part2 = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "application-autoscaling:DescribeScalableTargets",
                "application-autoscaling:DescribeScalingActivities",
                "application-autoscaling:DescribeScalingPolicies",
                "application-autoscaling:DescribeScheduledActions",
                "athena:GetQueryExecution",
                "athena:ListQueryExecutions",
                "athena:ListTagsForResource",
                "backup:DescribeBackupVault",
                "backup:ListBackupVaults",
                "dax:DescribeClusters",
                "dax:ListTags",
                "dms:DescribeReplicationInstances",
                "dms:ListTagsForResource",
                "ds:DescribeDirectories",
                "ds:ListTagsForResource",
                "elasticbeanstalk:DescribeConfigurationSettings",
                "elasticbeanstalk:DescribeEnvironments",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "eks:DescribeCluster",
                "eks:ListClusters",
                "events:DescribeEventBus",
                "events:ListRules",
                "firehose:DescribeDeliveryStream",
                "firehose:ListDeliveryStreams",
                "kafka:DescribeCluster",
                "kafka:ListClusters",
                "kafka:ListNodes",
                "mq:DescribeBroker",
                "mq:ListBrokers",
                "glue:GetDataCatalogEncryptionSettings",
                "glue:GetSecurityConfiguration",
                "glue:GetSecurityConfigurations",
                "guardduty:GetDetector",
                "guardduty:GetFindings",
                "guardduty:ListDetectors",
                "guardduty:ListFindings",
                "health:DescribeAffectedEntities",
                "health:DescribeEventDetails",
                "health:DescribeEvents",
                "inspector:DescribeFindings",
                "inspector:DescribeAssessmentRuns",
                "inspector:ListFindings",
                "inspector:ListAssessmentRuns",
                "kinesis:ListStreams",
                "kinesis:DescribeStream",
                "kinesis:ListTagsForStream",
                "organizations:DescribeAccount",
                "organizations:DescribeCreateAccountStatus",
                "organizations:DescribeHandshake",
                "organizations:DescribeOrganization",
                "organizations:DescribeOrganizationalUnit",
                "organizations:DescribePolicy",
                "organizations:ListAWSServiceAccessForOrganization",
                "organizations:ListAccounts",
                "organizations:ListAccountsForParent",
                "organizations:ListChildren",
                "organizations:ListCreateAccountStatus",
                "organizations:ListHandshakesForAccount",
                "organizations:ListHandshakesForOrganization",
                "organizations:ListOrganizationalUnitsForParent",
                "organizations:ListParents",
                "organizations:ListPolicies",
                "organizations:ListPoliciesForTarget",
                "organizations:ListRoots",
                "organizations:ListTargetsForPolicy",
                "route53domains:GetDomainDetail",
                "s3:GetAccelerateConfiguration",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation",
                "s3:GetBucketLogging",
                "s3:GetBucketObjectLockConfiguration",
                "s3:GetBucketPolicy",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketTagging",
                "s3:GetBucketVersioning",
                "s3:GetBucketWebsite",
                "s3:GetEncryptionConfiguration",
                "s3:GetLifecycleConfiguration",
                "s3:ListBucket",
                "s3:ListAllMyBuckets",
                "securityhub:GetEnabledStandards",
                "securityhub:GetFindings",
                "securityhub:GetInsightResults",
                "securityhub:GetInsights",
                "securityhub:GetMasterAccount",
                "securityhub:GetMembers",
                "securityhub:ListEnabledProductsForImport",
                "securityhub:ListInvitations",
                "securityhub:ListMembers",
                "servicequotas:ListServiceQuotas",
                "sagemaker:DescribeNotebookInstance",
                "sagemaker:ListNotebookInstances",
                "sagemaker:ListTags",
                "secretsmanager:DescribeSecret",
                "secretsmanager:ListSecrets",
                "shield:DescribeSubscription",
                "ssm:DescribeParameters",
                "storagegateway:DescribeNFSFileShares",
                "storagegateway:DescribeSMBFileShares",
                "storagegateway:DescribeTapes",
                "storagegateway:ListFileShares",
                "storagegateway:ListTagsForResource",
                "storagegateway:ListTapes",
                "transfer:DescribeServer",
                "transfer:ListServers",
                "xray:GetEncryptionConfig",
                "waf:GetWebACL",
                "waf:ListWebACLs",
                "workspaces:DescribeTags",
                "workspaces:DescribeWorkspaces",
                "workspaces:DescribeWorkspacesConnectionStatus",
                "support:DescribeSeverityLevels",
                "support:DescribeTrustedAdvisorChecks",
                "support:DescribeTrustedAdvisorCheckResult",
                "support:DescribeTrustedAdvisorCheckRefreshStatuses",
                "support:RefreshTrustedAdvisorCheck"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*",
                "s3:List*"
            ],
            "Resource": "arn:aws:s3:::elasticbeanstalk*"
        }
    ]
}
