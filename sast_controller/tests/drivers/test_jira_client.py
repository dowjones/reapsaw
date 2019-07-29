import unittest
from unittest import mock
from unittest.mock import MagicMock

from sast_controller.bin.json_to_jira import send_to_jira

JSON_ITEMS = [
    {
        "Issue Name": "Secrets Exposed.src/builder.js",
        "Issue Priority": "Major",
        "Issue Severity": "High",
        "Description": "While adding general comments is very useful, some programmers tend to leave important data, "
                       "such as: filenames related to the web application, old links or links which were not meant to "
                       "be browsed by users, old code fragments, etc.",
        "Tags": [
            {
                "TestType": "sast"
            },
            {
                "Tool": "Checkmarx"
            }
        ],
        "Jira Name": "Secrets Exposed",
        "Jira Description": "While adding general comments is very useful, some programmers tend to leave important "
                            "data, such as: filenames related to the web application, old links or links which were "
                            "not meant to be browsed by users, old code fragments, etc.",
    }
]

EXPECTED_ISSUE_DATA = {
    'project': {'key': 'DBG'},
    'summary': 'Secrets Exposed',
    'description': 'While adding general comments is very useful, some programmers tend to leave important '
                   'data, such as: filenames related to the web application, old links or links which were '
                   'not meant to be browsed by users, old code fragments, etc.',
    'issuetype': {'name': 'Vulnerability'},
    'assignee': {'name': 'testuser'},
    'priority': {'name': 'Critical'},
    'labels': ['sast', 'Checkmarx']
}


class TestJiraReport(unittest.TestCase):
    @mock.patch('sast_controller.drivers.jira.baseClient.JiraBaseClient.connect')
    def test_create_issue(self, jira_client):
        with mock.patch('jira.JIRA') as MockJIRA:
            instance = MockJIRA.return_value
            instance.create_issue.return_value = MagicMock(key='DBG-1')
            instance.check_project.return_value = True
            jira_client.return_value = MockJIRA()

            send_to_jira('DBG', 'testuser', 'Vulnerability', json_items=JSON_ITEMS)

            instance.search_issues.assert_called_with('project = DBG')
            instance.create_issue.assert_called_with(fields=EXPECTED_ISSUE_DATA)
