import logging

logger = logging.getLogger()


class LifeCycleEvent:
    def __init__(self, event):
        self.event = event
        self.org_master_acct = event['account']
        self.event_details = event['detail']
        self.region_name = event['detail']['awsRegion']
        self.event_name = event['detail']['eventName']
        self.create_status = event['detail']['serviceEventDetails']['createManagedAccountStatus']['state']
        self.child_account_id = event['detail']['serviceEventDetails']['createManagedAccountStatus']\
            ['account']['accountId']
        # accName = srvEventDetails['createManagedAccountStatus']['account']['accountName']
        # srvEventDetails = self.event_details['serviceEventDetails']
        # newAccInfo = srvEventDetails['createManagedAccountStatus']
        # ouInfo = srvEventDetails['createManagedAccountStatus']['organizationalUnit']
        # ouName = srvEventDetails['createManagedAccountStatus']['organizationalUnit']['organizationalUnitName']
        # odId = srvEventDetails['createManagedAccountStatus']['organizationalUnit']['organizationalUnitId']

    @property
    def create_account(self):
        if self.event_name == 'CreateManagedAccount' or self.event_name == 'UpdateManagedAccount':
            if self.create_status == 'SUCCEEDED':
                logger.info(f'CreateManagedAccountStatus state was {self.create_status}: proceeding to add account')
                return True
            else:
                logger.info('Create not SUCCESSFUL; ignoring event')
                return False
        else:
            logger.info(f'Not Create or Update; ignoring event: {self.event_name}')
            return False
