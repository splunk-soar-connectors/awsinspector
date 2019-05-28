# File: awsinspector_connector.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from awsinspector_consts import *

# Usage of the consts file is recommended
# from awsinspector_consts import *
import requests
import json
from boto3 import client
import datetime
from dateutil.tz import tzlocal


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AwsInspectorConnector(BaseConnector):

    def __init__(self):
        """
        The constructor for AwsInspectorConnector class.
        """

        # Call the BaseConnectors init first
        super(AwsInspectorConnector, self).__init__()

        self._state = None
        self._region = None
        self._access_key = None
        self._secret_key = None
        self._proxy = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS.
        """

        self._state = self.load_state()

        config = self.get_config()

        self._region = config['region']

        if 'access_key' in config:
            self._access_key = config['access_key']
        if 'secret_key' in config:
            self._secret_key = config['secret_key']

        self._proxy = {}
        env_vars = config.get('_reserved_environment_variables', {})
        if 'HTTP_PROXY' in env_vars:
            self._proxy['http'] = env_vars['HTTP_PROXY']['value']
        if 'HTTPS_PROXY' in env_vars:
            self._proxy['https'] = env_vars['HTTPS_PROXY']['value']

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _create_client(self, action_result):
        """This function is used to create a client which is necessary for Boto call

        :param action_result: Object of ActionResult class
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """

        try:

            if self._access_key and self._secret_key:

                self.debug_print("Creating boto3 client with API keys")
                self._client = client(
                        'inspector',
                        region_name=self._region,
                        aws_access_key_id=self._access_key,
                        aws_secret_access_key=self._secret_key)
            else:
                self.debug_print("Creating boto3 client without API keys")
                self._client = client(
                        'inspector',
                        region_name=self._region)

        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Could not create boto3 client: {0}".format(e))

        return phantom.APP_SUCCESS

    def _make_boto_call(self, action_result, method, **kwargs):
        """This function is used to make the Boto call.

        :param action_result: Object of ActionResult class
        :param method: Name of the method which is to be called in Boto call
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR) and response data of Boto call
        """

        try:
            boto_func = getattr(self._client, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), None)

        try:
            resp_json = boto_func(**kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, 'boto3 call to Inspector failed', e), None)

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, param):
        """ This function is used to handle the test connectivity action.

        :param param: Dictionary of input parameters
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        ret_val, response = self._make_boto_call(action_result, 'list_assessment_targets', maxResults=1)

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed")
            return ret_val

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_targets(self, param):
        """ This function is used to fetch targets of specific AWS account.

        :param param: Dictionary of input parameters
        :return: list of targets and their info for the specific AWS account
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        target_name = param.get('target_name')
        limit = param.get('limit', AWSINSPECTOR_MAX_PER_PAGE_LIMIT)

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSINSPECTOR_INVALID_LIMIT)

        filter = {}
        if target_name:
            filter['assessmentTargetNamePattern'] = target_name

        kwargs = {}
        kwargs['filter'] = filter
        kwargs['maxResults'] = limit

        list_targets = self._paginator('list_assessment_targets', action_result, **kwargs)

        if list_targets is None:
           return action_result.get_status()

        for target in list_targets:
            ret_val, res = self._make_boto_call(action_result, 'describe_assessment_targets', assessmentTargetArns=[target])

            tz = tzlocal()
            self.debug_print(tz)
            self.debug_print("The response of the action when added to the action_result")
            self.debug_print("It generates an error that the response data can not be serialized due to datetime object present in the output response")
            self.debug_print("To resolve that, we are trying to convert the datetime object into a corresponding datetime string")
            self.debug_print("List targets action's output response contains the datetime object consisting of a tzinfo attribute with the local timezone information")
            self.debug_print("If we try converting the datetime object in output response directly, we get the error that tzlocal module not found")
            self.debug_print("To avoid that error we have imported the tzlocal module")
            self.debug_print("To avoid the error of module is imported but never used, we have created an object of tzlocal and printed it's value in debug_print")

            assessment_targets = res.get('assessmentTargets')
            if assessment_targets:
                for target in assessment_targets:
                    for key, value in target.items():
                        if isinstance(value, datetime.datetime):
                            target[key] = str(value)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            # res['ThreatIntelSetId'] = threat
            action_result.add_data(res)

        summary = action_result.update_summary({})
        summary['total_targets'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_templates(self, param):
        """ This function is used to fetch templates that correspond to the assessment targets.

        :param param: Dictionary of input parameters
        :return: list of templates and their info for the specific AWS account
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        target_arns = param.get('target_arns')
        if param.get('target_arns'):
            target_arns = [target_arn.strip() for target_arn in target_arns.split(',')]
            target_arns = ' '.join(target_arns).split()

        template_name = param.get('template_name')
        limit = param.get('limit', AWSINSPECTOR_MAX_PER_PAGE_LIMIT)

        if (limit and not str(limit).isdigit()) or limit == 0:
            return action_result.set_status(phantom.APP_ERROR, AWSINSPECTOR_INVALID_LIMIT)

        filter = {}
        if template_name:
            filter['namePattern'] = template_name

        kwargs = {}
        if target_arns is not None:
            kwargs['assessmentTargetArns'] = target_arns
        kwargs['filter'] = filter
        kwargs['maxResults'] = limit

        list_templates = self._paginator('list_assessment_templates', action_result, **kwargs)

        if list_templates is None:
           return action_result.get_status()

        for template in list_templates:
            ret_val, res = self._make_boto_call(action_result, 'describe_assessment_templates', assessmentTemplateArns=[template])
            assessment_templates = res.get('assessmentTemplates')
            if assessment_templates:
                for template in assessment_templates:
                    for key, value in template.items():
                        if isinstance(value, datetime.datetime):
                            template[key] = str(value)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            try:
                del res['ResponseMetadata']
            except:
                pass

            action_result.add_data(res)

        summary = action_result.update_summary({})
        summary['total_templates'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_add_target(self, param):
        """ This function is used to create a new assessment target to the specific AWS account.

        :param param: Dictionary of input parameters
        :return: ARN of the assessment target that is created by this action.
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        target_name = param['target_name']
        resource_group_arn = param.get('resource_group_arn')

        kwargs = {}
        kwargs['assessmentTargetName'] = target_name

        if param.get('resource_group_arn'):
            kwargs['resourceGroupArn'] = resource_group_arn

        ret_val, response = self._make_boto_call(action_result, 'create_assessment_target', **kwargs)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            del response['ResponseMetadata']
        except:
            pass

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['total_target_arn'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS, "Target is added successfully")

    def _handle_delete_target(self, param):
        """ This function is used to delete the existing assessment target from the specific AWS account.

        :param param: Dictionary of input parameters
        :return: Status (phantom.APP_ERROR/phantom.APP_SUCCESS), target is deleted successfully
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._create_client(action_result)):
            return action_result.get_status()

        list_targets = self._paginator('list_assessment_targets', action_result)

        target_arn = param['target_arn']

        kwargs = {}
        kwargs['assessmentTargetArn'] = target_arn

        if target_arn in list_targets:
            ret_val, response = self._make_boto_call(action_result, 'delete_assessment_target', **kwargs)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Requested target arn does not exist")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            del response['ResponseMetadata']
        except:
            pass

        action_result.add_data(response)

        summary = action_result.update_summary({})
        summary['total_target_arn'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS, "Target is removed successfully")

    def _paginator(self, method_name, action_result, **kwargs):
        """
        This action is used to create an iterator that will paginate through responses from called methods.

        :param method_name: Name of method whose response is to be paginated
        :param action_result: Object of ActionResult class
        :param **kwargs: Dictionary of Input parameters
        """

        list_items = list()
        next_token = None

        while True:
            if next_token:
                ret_val, response = self._make_boto_call(action_result,
                                                        method_name,
                                                        nextToken=next_token,
                                                        **kwargs)
            else:
                ret_val, response = self._make_boto_call(action_result, method_name, **kwargs)

            if phantom.is_fail(ret_val):
                return None

            if response.get('assessmentTargetArns'):
                list_items.extend(response.get('assessmentTargetArns'))

            if response.get('assessmentTemplateArns'):
                list_items.extend(response.get('assessmentTemplateArns'))

            limit = kwargs.get('maxResults')
            if limit and len(list_items) >= limit:
                return list_items[:limit]

            next_token = response.get('NextToken')
            if not next_token:
                break

        return list_items

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: Dictionary which contains information about the actions to be executed
        :return: Status(phantom.APP_SUCCESS/phantom.APP_ERROR)
        """
        self.debug_print("action_id", self.get_action_identifier())
        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_targets': self._handle_list_targets,
            'list_templates': self._handle_list_templates,
            'add_target': self._handle_add_target,
            'delete_target': self._handle_delete_target
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print ("Accessing the Login page")
            response = requests.get(login_url, verify=False)
            csrftoken = response.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken={0}'.format(csrftoken)
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platform. Error: {0}".format(str(e)))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AwsInspectorConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
