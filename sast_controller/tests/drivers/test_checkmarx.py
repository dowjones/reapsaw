import logging
import os
import unittest
from unittest import mock

from sast_controller.drivers.cx import Checkmarx


class TestCheckmarx(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        env_vars = {
            'CX_URL': 'www.checkmarx.com',
            'OWNER': 'cx_owner',
            'PASSWORD': 'cx_password',
            'CX_WSDL_VERSION': '1'

        }
        env_patcher = mock.patch.dict(os.environ, env_vars)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        cx_connection_patcher = mock.patch('sast_controller.drivers.cx.Checkmarx.CheckmarxConnection')
        self.cx_connection_class = cx_connection_patcher.start()
        self.addCleanup(cx_connection_patcher.stop)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_associated_groups')
    @mock.patch.object(Checkmarx.Checkmarx, 'find_project_by_name')
    def test_checkmarx(self, find_project_by_name, get_associated_groups):
        sdk_client = mock.MagicMock()
        web_client = mock.MagicMock()

        def get_client(client_type=None):
            if client_type is None:
                return sdk_client
            return web_client
        cx_connection = self.cx_connection_class()
        cx_connection.get_client.side_effect = get_client

        cx_client = Checkmarx.Checkmarx(project='test_project')

        self.cx_connection_class.assert_called_with('www.checkmarx.com', 'cx_owner', 'cx_password')
        self.assertEqual('{http://Checkmarx.com/1}', cx_client.version)
        cx_connection.get_client.assert_called()
        find_project_by_name.assert_called_with('test_project')
        get_associated_groups.assert_called()
        self.assertEqual(sdk_client, cx_client.client)
        self.assertEqual(web_client, cx_client.web_portal_client)
        self.assertEqual(True, cx_client.valid)

    def test_get_type(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        get_type_func = cx_client.client.get_type.return_value = mock.MagicMock()
        ret = cx_client.get_type('cx_type', 'arg1', 'arg2')
        cx_client.client.get_type.assert_called_with('{http://Checkmarx.com/1}cx_type')
        get_type_func.assert_called_with('arg1', 'arg2')
        self.assertIsNotNone(ret)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_type')
    def test_report_type(self, get_type):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.report_type()
        get_type.assert_called_with('CxWSReportType', 'XML')
        self.assertIsNotNone(ret)

    @mock.patch.object(Checkmarx.Checkmarx, 'report_type')
    @mock.patch.object(Checkmarx.Checkmarx, 'get_type')
    def test_report_request(self, get_type, report_type):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        report_type_mock = mock.Mock()
        report_type.return_value = report_type_mock
        ret = cx_client.report_request('2')
        get_type.assert_called_with('CxWSReportRequest', report_type_mock, '2')
        self.assertIsNotNone(ret)

    def test_get_result_description(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_result_description('1', '2')
        cx_client.web_portal_client.service.GetResultDescription.assert_called_with(cx_client.session, '1', '2')
        self.assertIsNotNone(ret)

    def test_get_query_description_by_query_id(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_query_description_by_query_id('22')
        cx_client.web_portal_client.service.GetQueryDescriptionByQueryId.assert_called_with(cx_client.session, '22')
        self.assertIsNotNone(ret)

    def test_get_cwe_description(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_cwe_description('22')
        cx_client.web_portal_client.service.GetCWEDescription.assert_called_with(cx_client.session, '22')
        self.assertIsNotNone(ret)

    @mock.patch.object(Checkmarx, 'extract_zip')
    @mock.patch.object(Checkmarx.Checkmarx, 'get_type')
    def test_run_scan(self, get_type, extract_zip):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        get_type_func = mock.Mock()
        get_type.return_value = get_type_func
        ret = cx_client.run_scan('/root/path/to/project', incremental_scan=False)
        get_type_calls = [mock.call('ProjectSettings'),
                          mock.call('SourceCodeSettings'),
                          mock.call('LocalCodeContainer'),
                          mock.call('SourceFilterPatterns')]
        get_type.assert_has_calls(get_type_calls)
        cx_client.client.get_type.assert_called_with(f'{cx_client.version}CliScanArgs')
        self.assertIsNotNone(ret)

    @mock.patch.object(Checkmarx.Checkmarx, 'report_request')
    def test_create_scan_report(self, report_request):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        report_request_value = mock.Mock()
        report_request.return_value = report_request_value
        ret = cx_client.create_scan_report('23')
        cx_client.client.service.CreateScanReport.assert_called_with(cx_client.session, report_request_value)
        report_request.assert_called_with('23')
        self.assertIsNotNone(ret)

    def test_get_scan_report_status(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_scan_report_status('123')
        cx_client.client.service.GetScanReportStatus.assert_called_with(cx_client.session, '123')
        self.assertIsNotNone(ret)

    def test_get_status_of_single_run(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_status_of_single_run('122')
        cx_client.client.service.GetStatusOfSingleScan.assert_called_with(cx_client.session, '122')
        self.assertIsNotNone(ret)

    def test_get_project_scanned_display_data(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_project_scanned_display_data()
        cx_client.client.service.GetProjectScannedDisplayData.assert_called_with(cx_client.session)
        self.assertIsNotNone(ret)

    def test_get_scan_report(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_scan_report('1')
        cx_client.client.service.GetScanReport.assert_called_with(cx_client.session, '1')
        self.assertIsNotNone(ret)

    def test_get_associated_groups(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_associated_groups()
        cx_client.client.service.GetAssociatedGroupsList.assert_called_with(cx_client.session)
        self.assertIsNotNone(ret)

    def test_get_projects_display_data(self):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        ret = cx_client.get_projects_display_data()
        cx_client.client.service.GetProjectsDisplayData.assert_called_with(cx_client.session)
        self.assertIsNotNone(ret)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_type')
    def test_set_new_project_config(self, get_type):
        cx_client = Checkmarx.Checkmarx(project='test_project')
        cx_client.set_new_project_config(mock.Mock(), mock.Mock())
        get_type.assert_called_with('ProjectSettings')

    @mock.patch.object(Checkmarx.Checkmarx, 'get_projects_display_data')
    def test_find_project_by_name(self, get_projects_display_data):
        cx_client = Checkmarx.Checkmarx(project='test_project')

        class DummyProject():
            ProjectName = 'test_project'
            projectID = '42'

        dummy_project = DummyProject()
        project_config = mock.Mock()
        cx_client.client.service.GetProjectConfiguration.return_value = mock.Mock(ProjectConfig=project_config)
        get_projects_display_data.return_value = [dummy_project]

        ret = cx_client.find_project_by_name('test_project')
        get_projects_display_data.assert_called()
        cx_client.client.service.GetProjectConfiguration.assert_called_with(cx_client.session, '42')
        self.assertEqual(project_config, ret)
