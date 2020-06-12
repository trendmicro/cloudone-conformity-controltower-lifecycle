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
