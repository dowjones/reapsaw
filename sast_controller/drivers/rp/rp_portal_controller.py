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

import requests
import json
import urllib.parse
from copy import deepcopy

from sast_controller.drivers.rp import URLS


class ReportPortalService:
    """
    Service that realise Report Portal REST API
    """

    def __init__(self, host, token):
        """
        :param host:
            Report Portal host URL
        :param token:
            Report Portal API token
        """
        self._token = token
        headers = {
            'Accept': 'application/json',
            'Authorization': f'bearer {self._token}',
            'Content-type': 'application/json;charset=UTF-8'}
        self.report_portal_link = host
        self.ses = requests.Session()
        self.ses.headers.update(headers)
        self.urls = deepcopy(URLS)

    def close_session(self):
        """Close Report Portal session"""
        self.ses.close()

    def send_request(self, method, url, body=None, status_codes=None, verify=False):
        """
        Send request to Report Portal API

        :param method:
            HTTP method
        :param url:
            request URL
        :param body:
            request body
        :param status_codes:
            list of acceptable status codes
        :param verify:
            set True to verify ssl certificate
        :return:

        @:raise Exception in case if response code not in status codes
        """
        if status_codes is None:
            status_codes = [200]
        url_ = urllib.parse.urljoin(self.report_portal_link, url)
        if method == "GET":
            response = self.ses.get(url_, verify=verify)
        elif method == "POST":
            response = self.ses.post(url_, body, verify=verify)
        elif method == "PUT":
            response = self.ses.put(url_, body, verify=verify)
        else:
            raise Exception(f"Unsupported request method {method}")
        if response.status_code in status_codes:
            return json.loads(response.text)
        if response.text.find('invalid_token') > -1:
            raise AssertionError("Invalid Report Portal UUID token. Please verify RP_TOKEN param.")
        raise Exception(f"Wrong response.\n"
                        f"{method} {self.report_portal_link + url}\n"
                        f"Status code {response.status_code}\n "
                        f"{response.text}")

    def get_launch_info_by_number(self, project, scan_name, number):
        """
        GET /api/v1/{project}/launch?filter.eq.name={scan}&page.sort=number%2Cdesc&page.page={page}&page.size={size}
        :param project:
        :param scan_name:
        :param number:
        :return:
            launch ID,
            {
              "owner": "",
              "share": ,
              "id": "",
              "name": "",
              "number": 4,
              "start_time": ,
              "end_time": ,
              "status": "",
              "statistics": {
                "executions": {
                  "total": "",
                  "passed": "",
                  "failed": "",
                  "skipped": "0"
                },
                "defects": {
                }
              },
              "mode": "DEFAULT",
              "isProcessing": false,
              "approximateDuration": ,
              "hasRetries": false
            }
        """
        url = self.urls["get_launch_list_url"].format(
            project=project, scan=urllib.parse.quote_plus(scan_name),
            page=number, size=1)
        launch_list = self.send_request("GET", url)
        try:
            content = launch_list['content'][0]
        except IndexError:
            raise IndexError(
                'There is no {launch} inside {project} project.'
                '\nPlease double check Launch name and Project Name.'.format(
                    launch=scan_name, project=project))
        launch_id = content['id']
        return launch_id, launch_list

    def get_launch_info(self, project, launch_id):
        """
        GET /api/v1/{project}/item?filter.eq.launch={launch_id}&page.page={page}
        :param project:
        :param launch_id:
        :return:
            {
              "content": [],
              "page": {
                "number": 1,
                "size": 20,
                "totalElements": 0,
                "totalPages": 0
              }
            }
        """
        info_list = []
        page = 1
        total_pages = 1
        while page <= total_pages:
            url = self.urls["get_launch_info_url"].format(project=project,
                                                          launch_id=launch_id,
                                                          page=page)
            req = self.send_request("GET", url)
            info_list.append(req)
            total_pages = int(req['page']['totalPages'])
            page += 1
        return info_list

    def compare_launches(self, project, current_launch, previous_launch):
        """
        GET /api/v1/{project}/launch/compare?ids={current_launch}&ids={previous_launch}
        :param project:
        :param current_launch:
        :param previous_launch:
        :return:
            {
              "result": [
                {
                  "values": {},
                  "name": "",
                  "startTime": "",
                  "number": "",
                  "id": ""
                }
              ]
            }
        """
        url = self.urls["compare_url"].format(project=project,
                                              current_launch=current_launch,
                                              previous_launch=previous_launch)
        return self.send_request("GET", url)

    def get_test_item_log(self, project, test_item):
        """
        GET /api/v1/{project}/log?filter.eq.item={test_item}&page.page={page}&page.size=100&page.sort=time%2CASC
        :param project:
        :param test_item:
        :return:
            {
              "content": [
                {
                  "id": "",
                  "time": ,
                  "message": "",
                  "level": "",
                  "test_item": ""
                }
              ],
              "page": {
                "number": 1,
                "size": 20,
                "totalElements": 3,
                "totalPages": 1
              }
            }
        """
        content = []
        total_pages = 1
        page = 1
        while page <= total_pages:
            url = self.urls["get_log"].format(project=project,
                                              test_item=test_item,
                                              page=page)
            response = self.send_request("GET", url)
            content += response["content"]
            total_pages = int(response['page']['totalPages'])
            page += 1
        return content

    def get_prj_info(self, prj):
        """
        GET /api/v1/project/{project}
        :param prj:
        :return:
            {
              "addInfo": "string",
              "configuration": {
                "analyzer_mode": "ALL",
                "emailConfiguration": {
                },
                "entryType": "string",
                "externalSystem": [
                ],
                "interruptedJob": "ONE_HOUR",
                "isAutoAnalyzerEnabled": true,
                "keepLogs": "TWO_WEEKS",
                "keepScreenshots": "ONE_WEEK",
                "projectSpecific": "string",
                "statisticCalculationStrategy": "STEP_BASED",
                "subTypes": {}
              },
              "creationDate": "2019-03-27T12:26:56.203Z",
              "customer": "string",
              "projectId": "string",
              "users": [
                {
                  "login": "string",
                  "projectRole": "string",
                  "proposedRole": "string"
                }
              ]
            }
        """
        url = self.urls["get_project_info_url"].format(project=prj)
        return self.send_request("GET", url, status_codes=[200, 404])

    def get_external_system_info(self, project_):
        """
        Get external system config
        :raise IndexError if no external system in project
        :return
            {
                "accessKey": "string",
                "domain": "string",
                "fields": [
                  {
                    "definedValues": [
                      {
                        "valueId": "string",
                        "valueName": "string"
                      }
                    ],
                    "fieldName": "string",
                    "fieldType": "string",
                    "id": "string",
                    "required": true,
                    "value": [
                      "string"
                    ]
                  }
                ],
                "id": "string",
                "project": "string",
                "projectRef": "string",
                "systemAuth": "string",
                "systemType": "string",
                "url": "string",
                "username": "string"
              }
        """
        project_info = self.get_prj_info(project_)
        external_system = project_info["configuration"]["externalSystem"]
        if len(external_system) == 0:
            raise IndexError("No available external system. Please create one.")
        return external_system[0]

    def create_project(self, project_name):
        """
        Create project is project not exists
        POST /api/v1/project
        :param project_name:
        """
        project_info = self.get_prj_info(project_name)

        if 'Did you use correct project name?' in str(project_info):
            url = '/api/v1/project'
            post_body = {
                "entryType": "INTERNAL",
                "projectName": project_name
            }
            response = self.send_request("POST", url, json.dumps(post_body), status_codes=[201])
            self.enable_aa(project_name)
            return response
        return 'Project already exist'

    def update_ext_sys(self, prj, sys_id, params):
        """
        POST /api/v1/{prj}/external-system/{sys_id}
        params:
            {"url":"","systemType":"JIRA","systemAuth":"BASIC","project":"",
            "fields":[{"fieldName":"Issue Type","id":"issuetype","fieldType":"issuetype","required":true,
            "value":[""],"definedValues":[]},
            {"fieldName":"Summary","id":"summary","fieldType":"string","required":true,"definedValues":[],
            "value":[""]},
            {"fieldName":"Assignee","id":"assignee","fieldType":"user","required":true,"definedValues":[],
            "value":["test"]}]}

        :return:
        """
        url = f'/api/v1/{prj}/external-system/{sys_id}'
        return self.send_request("PUT", url, json.dumps(params))

    def assign_users(self, prj, users):
        """
        PUT /api/v1/project/test_new_prj_new/assign
        params:
                {"userNames":{"user":"ADMIN"}}
        :return:
        """
        url = f'/api/v1/project/{prj}/assign'

        return self.send_request("PUT", url, json.dumps(users))

    def setup_external_sys(self, project, params):
        """
        POST /api/v1/{project}/external-system
        params:
        {
          "domain": "",
          "password": "pwd",
          "project": "",
          "systemAuth": "Basic",
          "systemType": "JIRA",
          "url": "",
          "username": "userId"
        }

        :return:
        """
        url = f'/api/v1/{project}/external-system'
        return self.send_request("POST", url, json.dumps(params), status_codes=[201])

    def put_issue_status(self, project, body_params):
        """
        PUT /api/v1/{project}/item
        :param project:
        :param body_params:
        :return:
        """
        url = self.urls["put_item_url"].format(project=project)

        put_body = '{"issues": [{"issue": {"issue_type": "%s",' \
                   '"autoAnalyzed": false,"ignoreAnalyzer": false},' \
                   '"test_item_id": "%s"}]}' % (body_params["issue_type"], body_params["test_item_id"])
        return self.send_request("PUT", url, put_body)

    def enable_aa(self, project):
        try:
            url = f'/api/v1/project/{project}'
            body = '{"configuration":{"analyzerConfiguration":{"isAutoAnalyzerEnabled":true,' \
                   '"analyzer_mode":"LAUNCH_NAME","minDocFreq":"1","minShouldMatch":"95",' \
                   '"minTermFreq":"1","numberOfLogLines":"-1"}}}'
            return self.send_request("PUT", url, body, status_codes=[200])
        except Exception:
            pass
