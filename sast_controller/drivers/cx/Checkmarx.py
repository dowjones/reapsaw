import logging
import string
import random
import re
import os
import requests
import json
from requests_toolbelt import MultipartEncoder
# from sast_controller.drivers.cx.CheckmarxConnection2 import CheckmarxConnection
# from sast_controller.drivers.cx.utils import extract_zip, configure_logging


class Checkmarx(object):

    def __init__(self, project=None):

        self.server = os.environ.get('CX_URL')
        self.server += '/cxrestapi'
        print( self.server)
        self.username = os.environ.get('CX_USER', '')
        if not self.username:
            self.username = os.environ.get('OWNER')
        self.password = os.environ.get('CX_PASSWORD', '')
        if not self.password:
            self.password = os.environ.get('PASSWORD')

        self.urls = self.get_urls()
        self.token = self.get_token()

        self.headers = {
            'Authorization': f'Bearer {self.token}',
            "Accept": "application/json;v=1.0"}
        pass
    ReportFormat = 'XML'


    def get_urls(self):

        try:
            path = os.path.dirname(os.path.abspath(__file__))
            with open('/tmp/sast_controller/drivers/cx/urls.json') as urls:
                return json.loads(urls.read())
        except Exception as e:
            raise Exception("Unable to get configuration: {} . ".format(e))

    def send_requests(self, keyword, url_sub=None, headers=None, data=None, files=None):
        if url_sub is None:
            url_sub = dict(pattern="", value="")
        try:
            url_parameters = self.urls.get(keyword, None)
            if not url_parameters:
                raise Exception("Keyword not in urls.json")
            url = self.server + re.sub(url_sub.get("pattern"),
                                       url_sub.get("value"),
                                       url_parameters.get("url_suffix"))
            s = requests.Session()
            headers = headers or self.headers
            req = requests.Request(method=url_parameters.get("http_method"),
                                   headers=headers, url=url, data=data,
                                   files=files)
            prepped = req.prepare()
            resp = s.send(prepped, verify=False)
            if resp.status_code in [200, 201, 202, 204]:
                return resp
            elif resp.status_code == 400:
                raise Exception(" 400 Bad Request: {}.".format(resp.text))
            elif resp.status_code == 404:
                raise Exception(" 404 Not found {}.".format(resp.text))
            else:
                raise Exception(" Failed: {}.".format(resp.text))
        except Exception as e:
            raise Exception("{}".format(e))

    def get_token(self):

        data = {"username": self.username,
                "password": self.password,
                "grant_type": "password",
                "scope": "sast_rest_api",
                "client_id": "resource_owner_client",
                "client_secret": '014DF517-39D1-4453-B7B3-9930C563627C'}
        url = self.server + self.urls.get("token").get("url_suffix")
        token = requests.post(url=url, data=data, verify=False)
        token_get = json.loads(token.text)
        return token_get.get('access_token')

    def get_projects(self):

        keyword = "projects_list"
        return self.send_requests(keyword=keyword)

    def get_all_teams(self):

        keyword = "get_all_teams"
        return self.send_requests(keyword=keyword)

    def get_project_by_id(self, id):
        keyword = "get_project_by_id"
        url_sub = {"pattern": "{id}",
                   "value": str(id)}
        return self.send_requests(keyword=keyword, url_sub=url_sub)

    def get_project_details_by_id(self, project_id):

        keyword = "get_project_details_by_id"
        url_sub = {"pattern": "{project_id}",
                   "value": project_id}
        return self.send_requests(keyword=keyword, url_sub=url_sub)

    def get_reports_by_id(self, report_id, report_type):

        keyword = "get_reports_by_id"
        url_sub = {"pattern": "{report_id}",
                   "value": str(report_id)}
        headers = self.headers.copy()
        headers.update({"Accept": "application/" + report_type})
        return self.send_requests(keyword=keyword, url_sub=url_sub,
                                  headers=headers)

    def get_report_status_by_id(self, report_id):

        keyword = "get_report_status_by_id"
        url_sub = {"pattern": "{report_id}",
                   "value": str(report_id)}
        return self.send_requests(keyword=keyword, url_sub=url_sub)

    def register_scan_report(self, report_type, scan_id):

        keyword = "register_scan_report"
        data = {"reportType": report_type,
                "scanId": scan_id}
        return self.send_requests(keyword=keyword, data=data)

    def get_sast_scan_details_by_scan_id(self, id):
        keyword = "get_sast_scan_details_by_scan_id"
        url_sub = {"pattern": "{id}",
                   "value": str(id)}
        return self.send_requests(keyword=keyword, url_sub=url_sub)

    def create_new_scan(self, project_id, is_incremental=False, is_public=True,
                        force_scan=True):
        keyword = "create_new_scan"
        data = {"projectId": project_id,
                "isIncremental": is_incremental,
                "isPublic": is_public,
                "forceScan": force_scan}
        return self.send_requests(keyword=keyword, data=data)

    def define_sast_scan_settings(self, project_id, preset_id,
                                  engine_configuration_id):
        keyword = "define_sast_scan_settings"
        data = {"projectId": project_id,
                "presetId": preset_id,
                "engineConfigurationId": engine_configuration_id}
        return self.send_requests(keyword=keyword, data=data)

    def upload_source_code_zip_file(self, project_id, zip_path):
        keyword = "upload_source_code_zip_file"
        url_sub = {"pattern": "{project_id}",
                   "value": str(project_id)}
        file_name = zip_path.split()[-1]
        files = MultipartEncoder(fields={"zippedSource": (file_name,
                                                          open(zip_path, 'rb'),
                                                          "application/zip")})
        headers = self.headers.copy()
        headers.update({"Content-Type": files.content_type})
        return self.send_requests(keyword=keyword, url_sub=url_sub,
                                  headers=headers, data=files)

    def create_project_with_default_configuration(self, name, owning_team,
                                                  is_public=True):

        keyword = "create_project_with_default_configuration"
        data = {"name": name,
                "owningTeam": owning_team,
                "isPublic": is_public}
        return self.send_requests(keyword=keyword, data=data)

    def get_all_project_details(self):

        keyword = "get_all_project_details"
        return self.send_requests(keyword=keyword).json()

    def get_scan_queue_details_by_scan_id(self, id):
        keyword = "get_scan_queue_details_by_scan_id"
        url_sub = {"pattern": "{id}",
                   "value": str(id)}
        return self.send_requests(keyword=keyword, url_sub=url_sub)

    def find_project_by_name(self, project):
        projects_lists = self.get_all_project_details()
        for prj in projects_lists:
            name = prj.get('name')
            if name == project.lower():
                project_id = prj.get('id')
                return self.get_project_details_by_id(str(project_id))

    def check_project_by_name(self, project):
        projects_lists = self.get_all_project_details()

        for prj in projects_lists:
            name = prj.get('name')
            if name == project.lower():
                return True
        return False

    def get_project_id_by_name(self, project):
        projects_lists = self.get_all_project_details()

        for prj in projects_lists:
            name = prj.get('name')
            if name == project.lower():
                project_id  = prj.get('id')
        return project_id
