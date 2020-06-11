import time
import boto3
import json
import c1cconnectorapi
import ctlifecycleevent
import logging
import c1cresources
import cfnhelper

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_org_id():
    client = boto3.client('organizations')
    return client.list_roots()["Roots"][0]['ARN'].rsplit(':')[4]


def create_cross_account_role(aws_account_id, c1c_connector):
    sts_session = assume_role(aws_account_id, c1cresources.ControlTowerRoleName)
    client = sts_session.client('iam')
    logger.info(
        f'Creating role {c1cresources.IamRoleName} and policy {c1cresources.IamPolicyName} in account {aws_account_id}')
    path = "/"
    try:
        logger.info('Creating role...')
        client.create_role(Path=path, RoleName=c1cresources.IamRoleName,
                           AssumeRolePolicyDocument=c1cresources.get_assume_role_policy_document(c1c_connector),
                           Description='CloudOne Conformity Connector Role created by Control Tower Master'
                           )
    except Exception as e:
        logger.info('Failed to create role')
        logger.info(e)
        raise
    try:
        logger.info('Creating policy...')
        c1c_policy_document = c1cresources.ConformityPolicyDoc()
        client.create_policy(PolicyName=f'{c1cresources.IamPolicyName}1',
                             PolicyDocument=c1c_policy_document.part1
                             )
        client.create_policy(PolicyName=f'{c1cresources.IamPolicyName}2',
                             PolicyDocument=c1c_policy_document.part2
                             )
    except Exception as e:
        logger.info('Failed to create policy')
        logger.info(e)
        raise
    try:
        logger.info('Attaching policy...')
        client.attach_role_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}1',
                                  RoleName=c1cresources.IamRoleName
                                  )
        client.attach_role_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}2',
                                  RoleName=c1cresources.IamRoleName
                                  )
    except Exception as e:
        logger.info('Failed to attach policy')
        logger.info(e)
        raise
    else:
        return True


def delete_cross_account_role(aws_account_id):
    sts_session = assume_role(aws_account_id, c1cresources.ControlTowerRoleName)
    client = sts_session.client('iam')
    logger.info(f'Account is {boto3.client("sts").get_caller_identity()["Account"]}')
    try:
        client.detach_role_policy(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}1',
            RoleName=c1cresources.IamRoleName
        )
        client.detach_role_policy(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}2',
            RoleName=c1cresources.IamRoleName
        )
        logger.info('Detached policy')
    except Exception as e:
        logger.info(
            f'Failed to detach policy {c1cresources.IamPolicyName} from role {c1cresources.IamRoleName} \
                in account {aws_account_id}')
        logger.info(e)
    try:
        client.delete_role(RoleName=c1cresources.IamRoleName)
        logger.info('Deleted role')
    except Exception as e:
        logger.info(f'Failed to delete role {c1cresources.IamRoleName} in account {aws_account_id}')
        logger.info(e)
    try:
        client.delete_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}1')
        client.delete_policy(PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}2')
        logger.info('Deleted policy')
    except Exception as e:
        logger.info(
            "Failed to delete policy: {arn}".format(
                arn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName} 1 and/or 2'))
        logger.info(e)
    return


def assume_role(aws_account_number, role_name) -> boto3.Session:
    try:
        sts_client = boto3.client('sts')
        logger.info(f'Retrieving session for operation')
        logger.info(f'currently executing in '
                    f'{sts_client.get_caller_identity()["Account"]};'
                    f' called account is {aws_account_number}')
        if sts_client.get_caller_identity()["Account"] == aws_account_number:
            logger.info(f'Target account is Control Tower Master; returning local credentials session')
            return boto3.session.Session()
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]

        assume_role_response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                partition, aws_account_number, role_name),
            RoleSessionName=str(aws_account_number + '-' + role_name)
        )
        sts_session = boto3.Session(
            aws_access_key_id=assume_role_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=assume_role_response['Credentials']['SecretAccessKey'],
            aws_session_token=assume_role_response['Credentials']['SessionToken']
        )
        logger.info(f"Assumed session for {aws_account_number} - {role_name}.")
        return sts_session
    except Exception as e:
        logger.info(f"Could not assume role : {e}")
        raise e


def get_accounts():
    account_ids = []
    client = boto3.client('organizations')
    paginator = client.get_paginator('list_accounts')
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for account in page.get('Accounts'):
            account_ids.append(account.get('Id'))
    return account_ids


def fresh_deploy(function_name):
    client = boto3.client('lambda')
    logger.info(f'Received function name {function_name} from context')
    count = 0
    for account_id in get_accounts():
        client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps({'InvokeAction': 'configure_account', 'account_id': account_id})
        )
        count += 1
    print(f'Launched configure_account for {count} accounts')
    return None


def remove_all(function_name):
    client = boto3.client('lambda')
    logger.info(f'Received function name {function_name} from context')
    count = 0
    for account_id in get_accounts():
        client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps({'InvokeAction': 'remove_account_config', 'account_id': account_id})
        )
        count += 1
    print(f'Launched remove_account_config for {count} accounts')
    return None


def update_accounts(function_name):
    client = boto3.client('lambda')
    logger.info(f'Received function name {function_name} from context')
    count = 0
    for account_id in get_accounts():
        client.invoke(
            FunctionName=function_name,
            InvocationType='Event',
            Payload=json.dumps({'InvokeAction': 'update_account', 'account_id': account_id})
        )
        count += 1
    print(f'Launched update_accounts for {count} accounts')
    return None


def configure_account(aws_account_id):
    c1c_connector = c1cconnectorapi.CloudOneConformityConnector(c1cresources.get_api_key())
    iam_client = boto3.client('iam')
    try:
        logger.info('Create Connector Object')
        logger.info('Create role in target account')
        create_cross_account_role(aws_account_id, c1c_connector)
        time.sleep(20)
        logger.info('Add account to Cloud One Conformity')
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        update_policy(aws_account_id)
    except Exception as e:
        logger.info(f'Failed to configure account {aws_account_id} with exception: {e}')
    try:
        return c1c_connector.add_account(f'arn:aws:iam::{aws_account_id}:role/{c1cresources.IamRoleName}')
    except Exception as e:
        logger.info(f'Failed to add conformity connector with exception {e}')


def update_policy(aws_account_id):
    logger.info(f'Updating account {aws_account_id}')
    c1c_policy_document = c1cresources.ConformityPolicyDoc()
    sts_session = assume_role(aws_account_id, c1cresources.ControlTowerRoleName)
    client = sts_session.client('iam')
    policy_resource = sts_session.resource('iam')
    logger.info(f'Updating policy in account {aws_account_id}')
    try:
        client.get_role(RoleName=c1cresources.IamRoleName)
    except client.exceptions.NoSuchEntityException:
        logger.info(f'Policy not found; configuring account')
        configure_account(aws_account_id)
        return
    try:
        policy_part1 = policy_resource.Policy(f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}1')
        part1_version = policy_part1.default_version
        p1_new_version_response = client.create_policy_version(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}1',
            PolicyDocument=c1c_policy_document.part1,
            SetAsDefault=True
        )
        p1_delete_old_version_response = client.delete_policy_version(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}1',
            VersionId=part1_version.version_id
        )
        policy_part2 = policy_resource.Policy(f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}2')
        part2_version = policy_part2.default_version
        p2_new_version_response = client.create_policy_version(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}2',
            PolicyDocument=c1c_policy_document.part2,
            SetAsDefault=True
        )
        p2_delete_old_version_response = client.delete_policy_version(
            PolicyArn=f'arn:aws:iam::{aws_account_id}:policy/{c1cresources.IamPolicyName}2',
            VersionId=part2_version.version_id
        )
    except Exception as e:
        logger.info(f'Failed to update policy {e}')
        raise


def remove_account_config(aws_account_id):
    try:
        c1c_connector = c1cconnectorapi.CloudOneConformityConnector(c1cresources.get_api_key())
        logger.info(f'Removing account from conformity')
        c1c_connector.remove_account(aws_account_id)
        logger.info('Removing role from target account')
        delete_cross_account_role(aws_account_id)
    except Exception as e:
        logger.info(f'Failed to remove account {aws_account_id} config with exception: {e}')


def lambda_handler(event, context):
    logger.info(f"Event received by handler: {event}")
    logger.info(f'function name: {context.function_name}\n'
                f'invoked arn: {context.invoked_function_arn}\n')
    if 'RequestType' in event:
        logger.info(f'Handling cloudformation Request')
        if event['RequestType'] == 'Create':
            logger.info(f"Received CFN create")
            response = cfnhelper.cfnResponse(event, context)
            try:
                fresh_deploy(context.function_name)
            except Exception as e:
                logger.info(f'Failed to handle create event with exception: {e}')
                response.send(cfnhelper.responseCode.FAILED)
            response.send(cfnhelper.responseCode.SUCCESS)
        elif event['RequestType'] == 'Update':
            logger.info(f"Received CFN update")
            response = cfnhelper.cfnResponse(event, context)
            try:
                update_accounts(context.function_name)
            except Exception as e:
                logger.info(f'Failed to handle update event with exception: {e}')
                response.send(cfnhelper.responseCode.FAILED)
            response.send(cfnhelper.responseCode.SUCCESS)
        else:
            logger.info(f"Ignoring unhandled cfn request type: {event['RequestType']}")
            response = cfnhelper.cfnResponse(event, context)
            response.send(cfnhelper.responseCode.FAILED)
    elif 'InvokeAction' in event:
        if event['InvokeAction'] == 'configure_account':
            configure_account(event['account_id'])
        elif event['InvokeAction'] == 'update_account':
            update_policy(event['account_id'])
        elif event['InvokeAction'] == 'remove_account_config':
            remove_account_config(event['account_id'])
        elif event['InvokeAction'] == 'remove_all':
            remove_all(context.function_name)
    else:
        try:
            life_cycle_event = ctlifecycleevent.LifeCycleEvent(event)
        except Exception as e:
            logger.info(f'Did not find a supported event')
            return
        if life_cycle_event.create_account:
            configure_account(life_cycle_event.child_account_id)
        elif life_cycle_event.event_name == 'RemoveAccount':
            remove_account_config(life_cycle_event.child_account_id)
        else:
            logger.info(f'This is not an event handled by the integration. SKIPPING: {event}')
            response = cfnhelper.cfnResponse(event, context)
            response.send(cfnhelper.responseCode.FAILED)
        return False
