#  Copyright (c) 2018 Dow Jones & Company, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import traceback

from reportportal_client import ReportPortalServiceAsync
from time import time

MAX_MESSAGE_LEN = 30000


def timestamp():
    return str(int(time() * 1000))


def my_error_handler(exc_info):
    """
    This callback function will be called by async service client when error occurs.
    Return True if error is not critical and you want to continue work.
    :param exc_info: result of sys.exc_info() -> (type, value, traceback)
    :return:
    """
    traceback.print_exception(*exc_info)


class ReportPortalDataWriter(object):
    """Wrapper around async Report Portal service"""

    def __init__(self, endpoint, token, project, launch_name=None,
                 launch_doc=None, launch_tags=None, verify_ssl=False):
        """
        :param endpoint:
            link to Report Portal
        :param token:
            user token
        :param project:
            Report Portal project name
        :param launch_name:
            Report Portal launch name
        :param launch_doc:
            launch description
        :param launch_doc:
            launch tags
        :param verify_ssl:
            option to not verify ssl certificates
        """
        self.endpoint = endpoint
        self.token = token
        self.project = project
        self.launch_name = launch_name
        self.launch_doc = launch_doc
        self.launch_tags = launch_tags
        self.service = None
        self.test = None
        self.verify_ssl = verify_ssl

    def start_test(self):
        """
        Start new launch in Report Portal
        """
        self.service = ReportPortalServiceAsync(endpoint=self.endpoint,
                                                project=self.project,
                                                token=self.token,
                                                error_handler=my_error_handler,
                                                verify_ssl=self.verify_ssl)
        self.service.start_launch(name=self.launch_name,
                                  start_time=timestamp(),
                                  description=self.launch_doc,
                                  tags=self.launch_tags)

    def finish_test(self):
        """
        Finish started launch in Report Portal
        """
        self.service.finish_launch(end_time=timestamp())
        self.service.terminate()
        self.service = None

    def is_test_started(self) -> bool:
        """
        Return True in case if launch was started
        """
        if self.service:
            return True
        return False

    def start_test_item(self, issue, description, tags, parameters):
        """
        Start new test item inside the launch
        :param issue:
        :param description:
        :param tags:
        :param parameters:
        """
        self.test = self.service.start_test_item(issue,
                                                 description=description,
                                                 tags=tags,
                                                 start_time=timestamp(),
                                                 item_type="STEP",
                                                 parameters=parameters)

    def test_item_message(self, message, level="ERROR", attachment=None):
        """
        Add new log message inside test item
        :param message:
        :param level:
        :param attachment:
        """
        self.service.log(time=timestamp(), message=message[:MAX_MESSAGE_LEN],
                         level=level, attachment=attachment)

    def finish_test_item(self, defect_type_info):
        """
        Finish started test item
        :param defect_type_info:
        """
        defect_mapping = {
            'To Investigate': 'TI001',
            'No Defect': 'ND001',
            'Product Bug': 'PB001',
            'System Issue': 'SI001'
        }
        defect_type = defect_type_info['RP Defect Type']
        issue = None
        if defect_type in defect_mapping:
            issue = {'issue_type': defect_mapping[defect_type], 'comment': defect_type_info['RP Comment']}
        self.service.finish_test_item(end_time=timestamp(),
                                      status="FAILED",
                                      issue=issue)
