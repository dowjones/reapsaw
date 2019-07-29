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

import logging
import string
import random
import os

from sast_controller.drivers.cx.CheckmarxConnection import CheckmarxConnection
from sast_controller.drivers.cx.utils import extract_zip, configure_logging

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

PRESENT_ID = 0


def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


class Checkmarx(object):
    """Checkmarx connector wrapper"""

    ReportFormat = 'XML'

    def __init__(self, project=None):
        self.logger = configure_logging(logging.getLogger(__name__))
        self.checkmarx_url = os.environ.get('CX_URL')
        self.owner = os.environ.get('CX_USER', '')
        if not self.owner:
            self.owner = os.environ.get('OWNER')
        self.password = os.environ.get('CX_PASSWORD', '')
        if not self.password:
            self.password = os.environ.get('PASSWORD')
        self.project = project

        connection = CheckmarxConnection(self.checkmarx_url, self.owner,
                                         self.password)
        sdk_client = connection.get_client()
        session_id = connection.session_id
        self.version = "{http://Checkmarx.com/%s}" % (os.environ.get('CX_WSDL_VERSION'))
        if not session_id:
            self.client = None
            self.session = None
            self.valid = False

        else:
            # default client is SDK type client
            self.client = sdk_client
            self.sdk_client = sdk_client
            self.web_portal_client = connection.get_client('WebPortal')
            self.session = session_id
            self.valid = True
            project_settings = self.find_project_by_name(project)
            self.project_config = project_settings.ProjectSettings if project_settings else None
            self.group_details = self.get_associated_groups()
            self.scan_path = self.group_details['GroupList']['Group'][0]['GroupName']
            self.associated_group_id = self.group_details['GroupList']['Group'][0]['ID']

    def get_type(self, cx_type, *args):
        """
        Get client type
        :param cx_type:
        :param args:
        :return:
        """
        return self.client.get_type('%s%s' % (self.version, cx_type))(*args)

    def report_type(self):
        return self.get_type('CxWSReportType', self.ReportFormat)

    def report_request(self, long_scan_id):
        """
        Report request
        :param long_scan_id:
        :return:
        """
        return self.get_type('CxWSReportRequest', self.report_type(),
                             long_scan_id)

    def get_result_description(self, scan_id, path_id):
        """
        Get result description
        :param scan_id:
        :param path_id:
        :return:
        """
        res = self.web_portal_client.service.GetResultDescription(self.session, scan_id, path_id)
        if res['IsSuccesfull']:
            return res['ResultDescription']

    def get_query_description_by_query_id(self, query_id):
        """
        Get query description by query id
        :param query_id:
        :return:
        """
        res = self.web_portal_client.service.GetQueryDescriptionByQueryId(self.session, query_id)
        if res['IsSuccesfull']:
            return res['QueryDescription']

    def get_cwe_description(self, cwe_id):
        """
        Get Checkmarx description by CWE id
        :param cwe_id:
        :return:
        """
        res = self.web_portal_client.service.GetCWEDescription(self.session, cwe_id)
        if res['IsSuccesfull']:
            return res['QueryDescription']

    def run_scan(self, local_path=None, incremental_scan=False, long_project_id=None):
        """
        Run Checkmarx scan
        :param local_path:
        :param incremental_scan:
        :param long_project_id:
        :return:
        """
        args = self.client.get_type(f'{self.version}CliScanArgs')()
        if not long_project_id:
            if self.project_config:
                print('Existing Project:', self.project)
                args.PrjSettings = self.project_config
                args.IsIncremental = incremental_scan
            else:
                print('New project:', self.project)
                self.set_new_project_config(args, self.project)
        else:
            conf = self.client.service.GetProjectConfiguration(
                self.session, long_project_id).ProjectConfig
            if not conf:
                self.logger.critical(f"GetProjectConfiguration Failed: {conf.ErrorMessage}")
                return False
            args.PrjSettings = conf.ProjectSettings
            args.PrjSettings.PresetID = PRESENT_ID
            args.IsIncremental = incremental_scan
        args.PrjSettings.ProjectName = "%s\%s" % (self.scan_path, self.project)
        args.SrcCodeSettings = self.get_type('SourceCodeSettings')
        args.SrcCodeSettings.SourceOrigin = 'Local'
        args.SrcCodeSettings.UserCredentials = None
        args.SrcCodeSettings.PathList = None
        args.SrcCodeSettings.SourceControlSetting = None
        args.SrcCodeSettings.PackagedCode = self.get_type('LocalCodeContainer')
        args.SrcCodeSettings.PackagedCode.FileName = "@%s\%s.zip" % (self.scan_path, id_generator())
        args.SrcCodeSettings.PackagedCode.ZippedFile = extract_zip(local_path)
        args.SrcCodeSettings.SourceFilterLists = self.get_type('SourceFilterPatterns')
        args.SrcCodeSettings.SourceFilterLists.ExcludeFilesPatterns = ""
        args.SrcCodeSettings.SourceFilterLists.ExcludeFoldersPatterns = ""
        args.Comment = 'Running from code'
        args.IsPrivateScan = False
        args.ClientOrigin = 'SDK'
        args.IgnoreScanWithUnchangedCode = False
        args.SrcCodeSettings.SourceFilterLists.ExcludeFilesPatterns = ""
        args.SrcCodeSettings.SourceFilterLists.ExcludeFoldersPatterns = ""
        args.SrcCodeSettings.SourceControlCommandId = 0
        return self.client.service.Scan(self.session, args)

    def create_scan_report(self, long_scan_id):
        """
        Create scan report by long scan id
        :param long_scan_id:
        :return:
        """
        return self.client.service.CreateScanReport(
            self.session, self.report_request(long_scan_id))

    def get_scan_report_status(self, request_id):
        """
        Get scanning status
        :param request_id:
        :return:
        """
        return self.client.service.GetScanReportStatus(self.session, request_id)

    def get_status_of_single_run(self, run_id):
        """
        Get status for single run
        :param run_id:
        :return:
        """
        return self.client.service.GetStatusOfSingleScan(self.session, run_id)

    def get_project_scanned_display_data(self):
        """
        Get project scanned display data
        :return:
        """
        data = self.client.service.GetProjectScannedDisplayData(self.session)
        return data.ProjectScannedList.ProjectScannedDisplayData

    def get_scan_report(self, request_id):
        """
        Ger scan report by request id
        :param request_id:
        :return:
        """
        return self.client.service.GetScanReport(self.session, request_id)

    def get_associated_groups(self):
        """
        :return:
        {
            'IsSuccesfull': True,
            'ErrorMessage': None,
            'GroupList': {
                'Group': [
                    {
                        'GroupName': 'CxServer\\Z\\Org\\Group',
                        'ID': uuid,
                        'Type': 'Team',
                        'Guid': None,
                        'FullPath': None,
                        'Path': None
                    }
                ]
            }
        }
        """
        return self.client.service.GetAssociatedGroupsList(self.session)

    def get_projects_display_data(self):
        return self.client.service.GetProjectsDisplayData(self.session).projectList.ProjectDisplayData

    def set_project_config(self, args, conf):
        """
        Set config for project
        :param args:
        :param conf:
        """
        args.PrjSettings = conf.ProjectConfig.ProjectSettings
        project_name = args.PrjSettings.ProjectName
        args.PrjSettings.PresetID = 0
        args.PrjSettings.ProjectName = self.scan_path + "\\" + project_name

    def set_new_project_config(self, args, project):
        """
        Set new config for project
        :param args:
        :param project:
        """
        self.logger.info("Create new project")
        args.PrjSettings = self.get_type('ProjectSettings')
        args.PrjSettings.projectID = 0
        args.PrjSettings.TaskId = 0
        args.PrjSettings.PresetID = PRESENT_ID
        args.PrjSettings.AssociatedGroupID = self.associated_group_id
        args.PrjSettings.ScanConfigurationID = '1'
        args.PrjSettings.Description = project
        args.PrjSettings.Owner = self.owner
        args.PrjSettings.IsPublic = True
        args.PrjSettings.OpenSourceAnalysisOrigin = 'LocalPath'
        args.PrjSettings.ProjectName = self.scan_path + "\\" + project
        args.IsIncremental = False

    def find_project_by_name(self, project):
        """
        {
            'projectID': 000,
            'ProjectName': 'demo_project',
            'PresetID': 0000000,
            'TaskId': 000,
            'AssociatedGroupID': 'UUID',
            'ScanConfigurationID': 1,
            'Description': None,
            'Owner': 'some@example.com',
            'IsPublic': True,
            'OpenSourceSettings': None,
            'OpenSourceAnalysisOrigin': 'LocalPath'
        }
        """
        projects = self.get_projects_display_data()
        for prj in projects:
            if prj.ProjectName.lower() == project.lower():
                long_project_id = prj.projectID
                conf = self.client.service.GetProjectConfiguration(self.session, long_project_id).ProjectConfig
                if conf.ProjectSettings:
                    return conf
                else:
                    self.logger.critical(f"GetProjectConfiguration Failed: {conf.ErrorMessage}")
