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
        }
        env_patcher = mock.patch.dict(os.environ, env_vars)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    def test_checmarx(self, get_token):
        get_token.return_value = 'secret_token'
        cx_client = Checkmarx.Checkmarx()
        self.assertEqual('www.checkmarx.com/cxrestapi', cx_client.server)
        self.assertEqual('cx_owner', cx_client.username)
        self.assertEqual('cx_password', cx_client.password)
        self.assertEqual('secret_token', cx_client.get_token())
        self.assertEqual(
            {
                'Authorization': 'Bearer secret_token',
                "Accept": "application/json;v=1.0"
            },
            cx_client.headers
        )

    @mock.patch('sast_controller.drivers.cx.Checkmarx.requests.post')
    def test_get_token(self, requests_post):
        request_post_ret = mock.MagicMock()
        request_post_ret.text = '{"access_token": "token"}'
        requests_post.return_value = request_post_ret
        cx_client = Checkmarx.Checkmarx()
        token = cx_client.get_token()
        expected_data = {
            'username': 'cx_owner',
            'password': 'cx_password',
            'grant_type': 'password',
            'scope': 'sast_rest_api',
            'client_id': 'resource_owner_client',
            'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C'
        }
        requests_post.assert_called_with(
            url='www.checkmarx.com/cxrestapi/auth/identity/connect/token',
            data=expected_data,
            verify=False
        )
        self.assertEqual('token', token)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_projects(self, send_requests, get_token):
        send_requests.return_value = []
        cx_client = Checkmarx.Checkmarx()
        self.assertEqual(
            [],
            cx_client.get_projects()
        )
        send_requests.assert_called_with(keyword='projects_list')

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_all_teams(self, send_requests, get_token):
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_all_teams()
        send_requests.assert_called_with(keyword={
            "url_suffix": "/auth/teams",
            "http_method": "GET"
        })
        self.assertEqual(mock1.json(), res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_all_project_details(self, send_requests, get_token):
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_all_project_details()
        send_requests.assert_called_with(keyword={
            "url_suffix": "/projects",
            "http_method": "GET"
        })
        self.assertEqual(mock1.json(), res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_project_by_id(self, send_requests, get_token):
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_project_by_id(id)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/projects/{id}",
            "http_method": "GET"
        },
            url_sub={"pattern": "{id}",
                     "value": str(id)
                     }
        )
        self.assertEqual(mock1, res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_project_details_by_id(self, send_requests, get_token):
        project_id = 1
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_project_details_by_id(project_id)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/projects/{project_id}",
            "http_method": "GET"
        },
            url_sub={"pattern": "{project_id}",
                     "value": project_id
                     }
        )
        self.assertEqual(mock1, res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_report_status_by_id(self, send_requests, get_token):
        report_id = 1
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_report_status_by_id(report_id)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/reports/sastScan/{report_id}/status",
            "http_method": "GET"
        },
            url_sub={"pattern": "{report_id}",
                     "value": str(report_id)
                     }
        )
        self.assertEqual(mock1, res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_register_scan_report(self, send_requests, get_token):
        scan_id = 1
        report_type = 1
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.register_scan_report(report_type, scan_id)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/reports/sastScan",
            "http_method": "POST"
        },
            data={"reportType": report_type,
                  "scanId": scan_id
                  }
        )
        self.assertEqual(mock1, res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_sast_scan_details_by_scan_id(self, send_requests, get_token):
        id = 1
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_sast_scan_details_by_scan_id(id)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/sast/scans/{id}",
            "http_method": "GET"
        },
            url_sub={"pattern": "{id}",
                     "value": str(id)
                     }
        )
        self.assertEqual(mock1, res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_create_new_scan(self, send_requests, get_token):
        project_id = 1
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.create_new_scan(project_id, False, True, True)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/sast/scans",
            "http_method": "POST"
        },
            data={"projectId": project_id,
                  "isIncremental": False,
                  "isPublic": True,
                  "forceScan": True
                  }
        )
        self.assertEqual(mock1, res)

    @mock.patch.object(Checkmarx.Checkmarx, 'get_token')
    @mock.patch.object(Checkmarx.Checkmarx, 'send_requests')
    def test_get_scan_queue_details_by_scan_id(self, send_requests, get_token):
        id = 1
        mock1 = mock.MagicMock()
        send_requests.return_value = mock1
        cx_client = Checkmarx.Checkmarx()
        res = cx_client.get_scan_queue_details_by_scan_id(id)
        send_requests.assert_called_with(keyword={
            "url_suffix": "/sast/scansQueue/{id}",
            "http_method": "GET"
        },
            url_sub={"pattern": "{id}",
                     "value": str(id)
                     }
        )
        self.assertEqual(mock1, res)
