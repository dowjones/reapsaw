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

import os
import requests
import logging

from requests import Session, ConnectionError
from zeep import Client
from zeep.transports import Transport

from sast_controller.drivers.cx.utils import configure_logging

requests.packages.urllib3.disable_warnings()

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class CheckmarxConnection(object):
    """Connector to Checkmarx"""

    def __init__(self, hostname=None, username=None, password=None):
        """
        :param hostname:
            Checkmarx hostname
        :param username:
            Checkmarx username
        :param password:
            Checkmarx password
        """
        self.logger = configure_logging(logging.getLogger(__name__))
        self.hostname = hostname
        self.username = username
        self.password = password
        self.resolver_url = "%s/cxwebinterface/cxwsresolver.asmx?wsdl" % self.hostname
        session = Session()
        session.verify = False
        self.transport = Transport(session=session)
        try:
            self._resolver_client = Client(self.resolver_url, transport=self.transport)
        except Exception as error:
            self.logger.error("Checkmarx connection failed: {error}".format(error=error))
            raise ConnectionError(f"Checkmarx connection failed. Wrong or inaccessible hostname: {hostname}") from None
        self.session_id = None
        self.clients = {}

    def get_client_url(self, client_type='SDK'):
        return self._resolver_client.service.GetWebServiceUrl(client_type, 1).ServiceURL

    def get_client(self, client_type='SDK'):
        """
        Connect to Checkmarx client
        :param client_type:
        :return:
        """
        if client_type in self.clients:
            return self.clients[client_type]
        try:
            client_url = self.get_client_url(client_type)
            client = Client(client_url + "?wsdl", transport=self.transport, strict=False)
            credentials = {'User': self.username, 'Pass': self.password}
            login = client.service.Login(credentials, 1033)
            if not login.IsSuccesfull:
                raise AssertionError(f"Unable to login in Checkmarx. \n"
                                     f"Please double check CX_PASSWORD and CX_USER.")

            if self.session_id is None:
                self.session_id = login.SessionId
            self.clients[client_type] = client
            return client
        except ConnectionError as error:
            self.logger.critical(
                "Checkmarx connection failed. Wrong or inaccessible hostname: {error}".format(error=error))
            return False, False
