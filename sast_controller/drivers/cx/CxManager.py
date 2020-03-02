import os

from sast_controller.drivers.cx.Checkmarx import Checkmarx

import os
import re
import time
import json

import requests
from requests import Request, Session
from requests_toolbelt import MultipartEncoder

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class CxIncrementalScanException(Exception):
    """Use when unable to start Checkmarx incremental scan"""

    def __init__(self, message):
        self.message = message


class CxNoSourceScanException(Exception):
    """Use when no supported files in zip"""

    def __init__(self, message):
        self.message = message


def scan_project(local_path=None, project=None, incremental_scan=False):
    cxClient = Checkmarx(project)
    ReportFormat = 'XML'
    preset_id = 1
    engine_configuration_id = 5

    check_prj_exists = cxClient.check_project_by_name(project)
    if check_prj_exists:
        project_id = cxClient.get_project_id_by_name(project)
    else:
        project = cxClient.create_project_with_default_configuration(
            name=project,
            owning_team='d728ada5-5a56-442e-9562-0f506be3ecae',
            is_public=True)
        project_id = project.json().get("id")

    cxClient.upload_source_code_zip_file(project_id=project_id,
                                         zip_path=local_path)

    cxClient.define_sast_scan_settings(project_id=project_id,
                                       preset_id=preset_id,
                                       engine_configuration_id=engine_configuration_id)
    scan = cxClient.create_new_scan(project_id=project_id)
    scan_id = scan.json().get("id")
    scan_status = None

    while scan_status != 'Finished':
        scan_status = cxClient.get_sast_scan_details_by_scan_id(
            id=scan_id).json().get('status').get('name')
        if scan_status == 'Failed':
            cxClient.logger.critical("Scan Failed")
        if scan_status == 'Finished':
            cxClient.logger.info("Scan Finished")
        time.sleep(10)

    report_type = ReportFormat.upper()
    report = cxClient.register_scan_report(report_type=report_type,
                                           scan_id=scan_id)
    report_id = report.json().get('reportId')


    report_status = None
    while report_status != 'Created':
        report_status = cxClient.get_report_status_by_id(
            report_id=report_id).json().get("status").get("value")
        time.sleep(5)
    report_outfile = cxClient.get_reports_by_id(report_id=report_id,
                                                report_type=report_type).content

    return report_outfile
