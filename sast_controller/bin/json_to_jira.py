import json
from argparse import ArgumentParser

from sast_controller.bin.config import Config
from sast_controller.converters import PRIORITY_MAPPING

from sast_controller.drivers.jira.baseClient import JiraBaseClient


def send_to_jira(project, assignee, defect_type, json_items):
    """
    Create JIRA tickets from JSON report
    :param project:
    :param assignee:
    :param defect_type:
    :param json_items:
    """
    jira = JiraBaseClient()

    if jira and jira.check_project(project):
        for item in json_items:
            labels = []
            for _ in item['Tags']:
                labels.extend(_.values())
            issue_data = {
                'project': {'key': project},
                'summary': item.get('Jira Name', item['Issue Name']),
                'description': item['Jira Description'],
                'issuetype': {'name': defect_type},
                'assignee': {'name': assignee},
                'priority': {'name': PRIORITY_MAPPING.get(item['Issue Severity'], item['Issue Priority'])},
                'labels': labels
            }
            jira.create_issue(issue_data)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-p', '--jira_project', type=str, help="Jira project name")
    parser.add_argument('-a', '--jira_assignee', type=str, help="Jira assignee")
    parser.add_argument('-f', '--report_file', type=str, default=Config.JSON_OUTPUT_PATH,
                        help="Path to json report file")
    parser.add_argument('--defect_type', type=str, default='Vulnerability', help="Jira tickets type")
    return parser.parse_args()


def main():
    """Entry point for execution script"""
    args = parse_args()
    with open(args.report_file, 'r') as f:
        report = json.loads(f.read())
    send_to_jira(args.jira_project, args.jira_assignee, args.defect_type, report)


if __name__ == '__main__':
    main()
