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
from time import sleep

from sast_controller.drivers.cx.Checkmarx import Checkmarx

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

INCREMENTAL_SCAN_ERROR = 'full scan should be submitted for accurate results'
NO_SOURCES_ERROR = 'worker failed to retrieve scan'
NO_SOURCES = "No supported files to scan in Checkmarx. \n Please find details by the link:\n " \
             "https://checkmarx.atlassian.net/wiki" \
             "/spaces/KC/pages/141328390/8.5.0+Supported+Code+Languages+and+Frameworks "
SCAN_CANCELLED = 'Checkmarx scan was cancelled'


class CxIncrementalScanException(Exception):
    """Use when unable to start Checkmarx incremental scan"""

    def __init__(self, message):
        self.message = message


class CxNoSourceScanException(Exception):
    """Use when no supported files in zip"""

    def __init__(self, message):
        self.message = message


class CxScanCancelledException(Exception):
    """Use when no supported files in zip"""

    def __init__(self, message):
        self.message = message


def scan_project(local_path=None, project=None, incremental_scan=False):
    """
    Scan project using Checkmarx
    :param local_path:
        path to folder with project
    :param project:
        name of Checkmarx project
    :param incremental_scan:
    :return:
    :raise: CxIncrementalScanException
        if unable to start incremental scan
    """
    cxClient = Checkmarx(project)
    report = None
    if not cxClient.valid:
        cxClient.logger.critical("Invalid connection")
        return report
    response = cxClient.run_scan(local_path=local_path,
                                 incremental_scan=incremental_scan)
    if not response:
        cxClient.logger.critical("No response")
        return report
    run_id = response.RunId
    if run_id:
        currently_running = None
        scan_id = None
        total_progress = 0
        while currently_running != 'Finished':
            scan = cxClient.get_status_of_single_run(run_id)
            status = scan.CurrentStatus
            currently_running = status
            if currently_running == 'Finished':
                cxClient.logger.info("Scan Finished")
                try:
                    scan_id = scan.ScanId
                except Exception:
                    cxClient.logger.critical(str(scan))
                    raise
                break
            if currently_running == 'Failed':
                cxClient.logger.critical("Scan Failed")
                if scan.StageMessage.find(NO_SOURCES_ERROR) > -1:
                    raise CxNoSourceScanException(NO_SOURCES)

                cxClient.logger.critical(str(scan))
                if str(scan).find(INCREMENTAL_SCAN_ERROR) > -1:
                    raise CxIncrementalScanException(str(scan))
                break
            if currently_running == 'Canceled':
                raise CxScanCancelledException(SCAN_CANCELLED)
            if total_progress != scan.TotalPercent:
                cxClient.logger.info(f'The scan is in progress, {total_progress} percent completed.')
                total_progress = scan.TotalPercent
        if currently_running != "Failed":
            sleep(5)
            report_id = cxClient.create_scan_report(scan_id).ID
            while not cxClient.get_scan_report_status(report_id).IsReady:
                sleep(5)
                cxClient.logger.info("Report generation in progress")
            report = cxClient.get_scan_report(report_id)
    return report
