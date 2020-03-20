import time
from sast_controller.drivers.cx.Checkmarx import Checkmarx
from sast_controller.bin.config import Config


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

    check_prj_exists = cxClient.get_project_id_by_name(project)
    if Config.TEAM_NAME:
        team_name = cxClient.get_team_id_by_name(Config.TEAM_NAME)
    else:
        team_name = cxClient.get_team_default_name()

    if check_prj_exists:
        project_id = cxClient.get_project_id_by_name(project)
    else:
        project = cxClient.create_project_with_default_configuration(
            name=project,
            owning_team=team_name,
            is_public=True)
        project_id = project.json().get("id")

        cxClient.define_sast_scan_settings(project_id=project_id,
                                           preset_id=preset_id,
                                           engine_configuration_id=engine_configuration_id)

    cxClient.upload_source_code_zip_file(project_id=project_id,
                                         zip_path=local_path)

    scan = cxClient.create_new_scan(project_id=project_id)
    scan_id = scan.json().get("id")
    scan_status = None
    report_status = None

    while scan_status != 'Finished':
        scan_status = cxClient.get_sast_scan_details_by_scan_id(
            id=scan_id).json().get('status').get('name')
        if scan_status == 'Failed':
            cxClient.logger.critical("Scan Failed")
            break
        if scan_status == 'Finished':
            cxClient.logger.info("Scan Finished")
        time.sleep(10)

    report_type = ReportFormat.upper()
    report = cxClient.register_scan_report(report_type=report_type,
                                           scan_id=scan_id)
    report_id = report.json().get('reportId')

    while report_status != 'Created':
        report_status = cxClient.get_report_status_by_id(
            report_id=report_id).json().get("status").get("value")
        if report_status == 'Failed':
            cxClient.logger.critical("Report Failed")
            break
        time.sleep(5)
    report_outfile = cxClient.get_reports_by_id(report_id=report_id,
                                                report_type=report_type).content

    return report_outfile
