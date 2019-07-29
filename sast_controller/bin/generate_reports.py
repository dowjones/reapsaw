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
import json
import os
import logging.config

import re
import requests

from junit_xml import TestSuite
from requests.exceptions import ConnectionError
from argparse import ArgumentParser, ArgumentTypeError

from sast_controller.bin.config import Config

from sast_controller.converters.CheckmarxReport import CheckmarxReport
from sast_controller.converters.SnykReport import SnykReport
from sast_controller.converters.Converter import Converter

from sast_controller.drivers.rp.report_portal_writer import ReportPortalDataWriter
from sast_controller.drivers.rp.rp_portal_controller import ReportPortalService

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger(__name__)


def str2bool(v):
    """
    Convert from str to bool
    :param v:
    :return:
    :raise: ArgumentTypeError if unable to convert to bool
    """
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise ArgumentTypeError('Boolean value expected.')


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-r', '--reportportal', type=str2bool, default=True, help="Write to report portal data or not")
    parser.add_argument('-o', '--output', type=str, default='/code/reports/junit_report.xml', help="output file")
    parser.add_argument('--json_output', type=str, default=Config.JSON_OUTPUT_PATH, help="json output file")
    parser.add_argument('--cm_input', type=str, default=Config.CX_OUTPUT_PATH, help="input file")
    parser.add_argument('--sn_input', type=str, default=Config.SNYK_OUTPUT_PATH, help="input file")
    return parser.parse_args()


def check_connectivity(endpoint, error_msg='ConnectionError'):
    """
    Check connectivity to endpoint
    :param error_msg:
    :param endpoint:
    :return:
    """
    error = False
    response = None
    try:
        response = requests.get(endpoint, verify=False)
    except ConnectionError:
        error = True
    try:
        ip = requests.get('https://api.ipify.org').text
        if error:
            raise ConnectionError('{}. Endpoint: {}. Public IP: {}'.format(error_msg, endpoint, ip))
        elif response and response.status_code != 200:
            raise ConnectionError('{}. Invalid response code : {}. Public IP: {}'.format(error_msg,
                                                                                         response.status_code, ip))
    except ConnectionError:
        raise ConnectionError('Internet Connection Error!')


def send_items_to_rp(items, url=None, project=None, launch_name=None, token=None, launch_tags=None):
    """
        Send findings to RP
        :param items:
        :param launch_name:
        :param url:
        :param project:
        :param token:
        :param launch_tags:
        :return:
        """
    if not url:
        url = os.environ.get('REPORT_PORTAL_URL', '')
    if not project:
        project = os.environ.get('RP_PROJECT', os.environ.get('PROJECT', None))
    if not launch_name:
        launch_name = os.environ.get('RP_LAUNCH_NAME', 'SAST scan')
    if not token:
        token = os.environ.get('RP_TOKEN', None)
    logger.critical(f"REPORT_PORTAL_URL = {url}")
    logger.critical(f"RP_PROJECT = {project}")
    logger.critical(f"RP_LAUNCH_NAME = {launch_name}")

    if not (url and project and token):
        raise Exception('Please specify REPORT_PORTAL_URL, RP_PROJECT and RP_TOKEN!')

    if not re.fullmatch('[a-zA-Z_\-0-9]+', project):
        raise Exception('Only latin letters, numeric characters, '
                        'underscores and dashes are supported in RP project name.')

    check_connectivity(url, 'ConnectionError with Report Portal')

    rp_service = ReportPortalService(url, token)
    print(rp_service.create_project(project))

    rp_data_writer = ReportPortalDataWriter(endpoint=url, token=token, project=project,
                                            launch_name=launch_name, launch_tags=launch_tags)
    rp_data_writer.start_test()
    for item in items:
        rp_data_writer.start_test_item(item.issue, description=item.description, tags=item.get_tags(),
                                       parameters=item.get_params())
        info_msg = []
        for msg in item.msgs:
            if msg.status == 'ERROR':
                rp_data_writer.test_item_message(msg.message, msg.status)
            else:
                info_msg.append(msg.message)
        if item.attachments:
            for attachment in item.attachments:
                rp_data_writer.test_item_message(attachment['name'], 'INFO', attachment)
        rp_data_writer.test_item_message('!!!MARKDOWN_MODE!!! %s ' % '\n\n'.join(set(info_msg)), 'INFO')
        rp_data_writer.finish_test_item(item.defect_type_info)
    if rp_data_writer.is_test_started():
        rp_data_writer.finish_test()


def get_models(args):
    """
    :param args: argparse.Namespace
        commandline arguments
    :return: dict of BaseReport
    """
    models = dict()
    if os.path.isfile(args.cm_input):
        models[args.cm_input] = CheckmarxReport
    if os.path.isfile(args.sn_input):
        models[args.sn_input] = SnykReport
    return models


def generate_reports(args, models):
    """
    Generate Report Portal, JUnit, JSON reports
    :param args: argparse.Namespace
        commandline arguments
    :param models: dict of BaseReport
    """
    repo = os.environ.get('REPO', '')
    branch = os.environ.get('BRANCH', 'develop')
    if repo.endswith('.git'):
        repo = repo[:-len('.git')]
    canonical = Converter(models, repo, branch)
    ti = canonical.get_rp_items()

    if ti:
        if args.reportportal:
            send_items_to_rp(ti)

        junit_items = canonical.get_junit_items()
        if os.path.exists(os.path.dirname(args.output)):
            if junit_items:
                with open(args.output, 'w') as f:
                    TestSuite.to_file(f, [junit_items], prettyprint=False)
        if os.path.exists(os.path.dirname(args.json_output)):
            json_items = canonical.get_json_items()
            if json_items:
                with open(args.json_output, 'w') as f:
                    json.dump(json_items, f, indent=4, sort_keys=True)
    else:
        logger.critical('There are no findings in report.')


def main():
    """Entrypoint for execution script"""
    args = parse_args()

    models = get_models(args)

    generate_reports(args, models)


if __name__ == '__main__':
    main()
