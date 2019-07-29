import unittest
from unittest import mock

from sast_controller.drivers.cx import CheckmarxConnection


class TestCheckmarxConnection(unittest.TestCase):
    def setUp(self):
        requests_session_patcher = mock.patch('sast_controller.drivers.cx.CheckmarxConnection.Session')
        self.requests_session_class = requests_session_patcher.start()
        self.addCleanup(requests_session_patcher.stop)

        zeep_client_patcher = mock.patch('sast_controller.drivers.cx.CheckmarxConnection.Client')
        self.zeep_client_class = zeep_client_patcher.start()
        self.addCleanup(zeep_client_patcher.stop)

        zeep_transport_patcher = mock.patch('sast_controller.drivers.cx.CheckmarxConnection.Transport')
        self.zeep_transport_class = zeep_transport_patcher.start()
        self.addCleanup(zeep_transport_patcher.stop)

    def test_checkmarx_connection(self):
        CheckmarxConnection.CheckmarxConnection('hostname', 'username', 'password')
        self.requests_session_class.assert_called()
        self.zeep_transport_class.assert_called_with(session=self.requests_session_class())
        self.zeep_client_class.assert_called_with('hostname/cxwebinterface/cxwsresolver.asmx?wsdl',
                                                  transport=self.zeep_transport_class())

    def test_client_url(self):
        cx_conn = CheckmarxConnection.CheckmarxConnection('hostname', 'username', 'password')
        cx_conn._resolver_client.service.GetWebServiceUrl('SDK', 1).ServiceURL = 'service_url'
        cx_conn._resolver_client.service.GetWebServiceUrl.assert_called_with('SDK', 1)
        self.assertEqual('service_url', cx_conn.get_client_url())

        cx_conn._resolver_client.service.GetWebServiceUrl('SDK_2', 1).ServiceURL = 'service_url_2'
        cx_conn._resolver_client.service.GetWebServiceUrl.assert_called_with('SDK_2', 1)
        self.assertEqual('service_url_2', cx_conn.get_client_url())

    def test_get_client(self):
        cx_conn = CheckmarxConnection.CheckmarxConnection('hostname', 'username', 'password')
        cx_conn._resolver_client.service.GetWebServiceUrl('SDK', 1).ServiceURL = 'service_url'
        client = cx_conn.get_client()
        self.zeep_client_class.assert_called_with('service_url?wsdl', transport=cx_conn.transport, strict=False)
        zeep_client = self.zeep_client_class()
        zeep_client.service.Login.assert_called_with({'User': 'username', 'Pass': 'password'}, 1033)
        self.assertEqual(client, cx_conn.clients['SDK'])
