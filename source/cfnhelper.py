import urllib3
import enum
import json
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class responseCode:
	SUCCESS = "SUCCESS"
	FAILED = "FAILED"

class cfnResponse:
	def __init__(self, event=None, context=None, physicalResourceId=None, noEcho=False):
		self.responseUrl = event['ResponseURL']
		self.responseBody = {}
		self.responseBody['Reason'] = 'See the details in CloudWatch Log Stream: ' + context.log_stream_name
		self.responseBody['PhysicalResourceId'] = physicalResourceId or context.log_stream_name
		self.responseBody['StackId'] = event['StackId']
		self.responseBody['RequestId'] = event['RequestId']
		self.responseBody['LogicalResourceId'] = event['LogicalResourceId']
		self.responseBody['NoEcho'] = noEcho
		self.responseBody['Data'] = {}
		self.http = urllib3.PoolManager()
	def __jsonResponseBody(self):
		return json.dumps(self.responseBody)
	def send(self, status, noEcho=False):
		self.responseBody['Status'] = status
		json_responseBody = self.__jsonResponseBody()
		print("Response body:\n" + json_responseBody)
		headers = {
			'content-type' : '',
			'content-length' : str(len(json_responseBody))
		}
		try:
			response = self.http.request('PUT', self.responseUrl, body=json_responseBody, headers=headers)
			print("Status code: {status}".format(status=response.status))
		except Exception as e:
			print("send(..) failed executing http.request(..): {error}".format(error=str(e)))
