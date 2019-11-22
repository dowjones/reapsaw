import copy
import json
import os
import unittest
from unittest import mock

from sast_controller.bug_bar import bug_bar
from sast_controller.converters import SnykReport
from json import loads

BUG_BAR = {
    "Vulnerable Software": {
        "risk_rating": "High",
        "jira_priority": "Major",
        "burp": "",
        "cxsast": "",
        "dev": "",
        "infra": "",
        "notes": "",
        "": ""
    }
}


def get_bug_bar_mock(file_path=None, default=None):
    return BUG_BAR


EXPECTED_REPORT = [{
    'Attachments': [],
    'CWE': 'CWE-400',
    'Description': '*Vulnerable Package:* brace-expansion\n'
                   '*Current Version:* 1.1.6\n'
                   '*Vulnerable Version(s):* <1.1.7\n'
                   ' \n'
                   ' *Remediation:*\n'
                   'Upgrade `brace-expansion` to version 1.1.7 or higher.\n'
                   '\n'
                   '\n'
                   '  Overview\n'
                   '[`brace-expansion`](https://www.npmjs.com/package/brace-expansion) '
                   'is a package that performs brace expansion as known '
                   'from sh/bash.\n'
                   'Affected versions of this package are vulnerable to '
                   'Regular Expression Denial of Service (ReDoS) attacks.\n'
                   '\n'
                   '\n'
                   ' ',
    'Instances': '@nyc.dotted',
    'Issue Confidence': 'Certain',
    'Issue Name': 'Regular Expression Denial of Service (ReDoS).@nyc.dotted',
    'Issue Priority': 'Major',
    'Issue Severity': 'Medium',
    'Security Tool': 'Snyk',
    'Jira Name': 'Vulnerable Software',
    'Paths': 'MyAPP>@nyc.dotted@7.1.0>glob@7.0.5>minimatch@3.0.2>brace-expansion@1.1.6',
    'Recommendations': 'Upgrade `@nyc.dotted` to version 8.1.0 or higher',
    'References': '\n'
                  '- [GitHub '
                  'PR](https://github.com/juliangruber/brace-expansion/pull/35)\n'
                  '- [GitHub '
                  'Issue](https://github.com/juliangruber/brace-expansion/issues/33)\n'
                  '- [GitHub '
                  'Commit](https://github.com/juliangruber/brace-expansion/pull/35/commits/b13381281cead487cbdbfd6a69'
                  'fb097ea5e456c3)\n',
    'Repo': '',
    'Steps To Reproduce': '',
    'Tags': [{'TestType': 'sast'}, {'Provider': 'Reapsaw'}, {'Tool': 'Snyk'}],
    'error_string': '@nyc.dotted',
    'language': 'js',
    'top_level_module': '@nyc.dotted',
    'upgrades': [False,
                 '@nyc.dotted@8.1.0',
                 'glob@7.0.5',
                 'minimatch@3.0.2',
                 'brace-expansion@1.1.7'],
    'RP Defect Type': 'No Defect'}]


class TestSnykReport(unittest.TestCase):
    def setUp(self):
        original_read_json = bug_bar.read_json
        bug_bar.read_json = get_bug_bar_mock
        self.addCleanup(setattr, bug_bar, 'read_json', original_read_json)
        self.maxDiff = None

    def test_report_upgrade_recommendation(self):
        snyk_report = SnykReport.SnykReport(os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json')
        self.assertEqual(EXPECTED_REPORT, snyk_report.report)

    @mock.patch.dict(os.environ, {'BRANCH': 'develop'})
    def test_report_with_git_branch(self):
        snyk_report = SnykReport.SnykReport(os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json')
        expected_report = copy.deepcopy(EXPECTED_REPORT)
        expected_report[0]['Instances'] += '\nBranch: develop'
        self.assertEqual(expected_report, snyk_report.report)

    @mock.patch('sast_controller.converters.SnykReport.SnykReport.__init__')
    def test_report_reinstall_recommendation(self, report_constructor):
        report_constructor.return_value = None
        snyk_report = SnykReport.SnykReport('test')
        with open(os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json', 'r') as report_file:
            report_json = json.loads(report_file.read())
            report_json['vulnerabilities'][0]['upgradePath'][1] = report_json['vulnerabilities'][0]['from'][1]
            snyk_report.report = report_json
            snyk_report.new_items = dict()
            snyk_report.report = snyk_report._canonify()
        expected_report = copy.deepcopy(EXPECTED_REPORT)
        expected_report[0]['upgrades'][1] = '@nyc.dotted@7.1.0'
        expected_report[0]['Recommendations'] = (
            'Your dependencies are out of date. Please remove your `node_modules` directory and lock file, run '
            '`npm install` and commit new lock file to your repo. Note, this will likely make a lot of changes to '
            'lock file.')
        self.assertEqual(expected_report, snyk_report.report)

    @mock.patch('sast_controller.converters.SnykReport.SnykReport.__init__')
    def test_report_no_reinstall_if_not_js(self, report_constructor):
        report_constructor.return_value = None
        snyk_report = SnykReport.SnykReport('test')
        with open(os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json', 'r') as report_file:
            report_json = json.loads(report_file.read())
            report_json['vulnerabilities'][0]['upgradePath'][1] = report_json['vulnerabilities'][0]['from'][1]
            report_json['vulnerabilities'][0]['language'] = 'scala'
            snyk_report.report = report_json
            snyk_report.new_items = dict()
            snyk_report.report = snyk_report._canonify()
        self.assertEqual([], snyk_report.report)

    def test_report_dotnet_severity(self):
        snyk_report = SnykReport.SnykReport(os.path.dirname(os.path.abspath(__file__)) + '/snyk_dotnet.json')
        self.assertEqual(snyk_report.report[0]['Issue Severity'], 'High')
        self.assertEqual(1, len(snyk_report.report))

    def test_report_dotnet_grouping(self):
        with open(os.path.dirname(os.path.abspath(__file__)) + '/snyk_dotnet.json') as f:
            data = loads(f.read())
        # update severity
        data[0]['vulnerabilities'][1]['severity'] = 'low'
        # changed upgrade path to test grouping
        data[0]['vulnerabilities'][0]['from'][1] = 'test_grouping'
        snyk_report = SnykReport.SnykReport(os.path.dirname(os.path.abspath(__file__)) + '/snyk_dotnet.json')
        snyk_report.report = data
        snyk_report.report = snyk_report._canonify()
        self.assertEqual(snyk_report.report[0]['Issue Severity'], 'Medium')
        self.assertEqual(2, len(snyk_report.report))

    def test_report_example_grouping(self):
        with open(os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json') as f:
            data = loads(f.read())
        # update severity

        test_data = "**Example:**\r\n```js\r\nqs.parse('toString=foo', { allowPrototypes: false })```"
        # added code snippet
        data['vulnerabilities'][0]['description'] = '## Overview\r\n[`qs`]' + test_data
        snyk_report = SnykReport.SnykReport(os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json')
        snyk_report.report = data
        snyk_report.report = snyk_report._canonify()

        self.assertIn('Overview\r\n[`qs`]', snyk_report.report[0]['Description'])

        self.assertNotIn('**Example:**', snyk_report.report[0]['Description'])

    @mock.patch('builtins.open')
    @mock.patch('json.loads')
    def test_get_exact_top_deps(self, json_loads, open_file):
        json_loads.return_value = {
            'dependencies': {
                'exact_dep': '1.1.0',
                'dep_a': '~1.0.0',
                'dep_b': '^1.0.0',
                'dep_c': '>=3.3.0',
                'dep_d': '<=3.3.0'
            }
        }
        self.assertEqual(['exact_dep@1.1.0'], SnykReport.SnykReport.get_exact_top_deps())

    @mock.patch('sast_controller.converters.SnykReport.SnykReport.get_exact_top_deps')
    def test_filter_vulnerable_paths(self, get_top_deps):
        get_top_deps.return_value = ['A@1.0.0', 'B@1.0.0']
        vulnerabilities = [
            {
                'Paths': {
                    'this_package_name@1.0.0>A@1.0.0>E@1.0.0>F@1.0.0'
                },
                'Recommendations': 'Re-install...'
            },
            {
                'Paths': {
                    'this_package_name@1.0.0>B@1.0.0>E@1.0.0>F@1.0.0'
                },
                'Recommendations': 'Re-install...'
            },
            {
                'Paths': {
                    'this_package_name@1.0.0>C@1.0.0>A@1.0.0>E@1.0.0>F@1.0.0',
                    'this_package_name@1.0.0>C@1.0.0>G@2.2.2',
                },
                'Recommendations': 'Re-install...'
            },
            {
                'Paths': {
                    'this_package_name@1.0.0>H@1.0.0>B@1.0.0>E@1.0.0>F@1.0.0'
                },
                'Recommendations': 'Re-install...'
            },
            {
                'Paths': {
                    'this_package_name@1.0.0>I@1.0.0>B@2.0.0>E@2.0.0>F@2.0.0'
                },
                'Recommendations': 'Re-install...'
            }
        ]
        expected_vulns = copy.deepcopy(vulnerabilities)
        expected_vulns[2]['Paths'].remove('this_package_name@1.0.0>C@1.0.0>A@1.0.0>E@1.0.0>F@1.0.0')
        del expected_vulns[3]
        filtered_vulns = SnykReport.SnykReport.filter_vulnerable_paths(vulnerabilities)
        self.assertEqual(4, len(filtered_vulns))
        self.assertEqual(expected_vulns, filtered_vulns)

    @mock.patch('sast_controller.converters.SnykReport.SnykReport.get_item')
    @mock.patch('sast_controller.converters.SnykReport.SnykReport.__init__')
    def test_group_vulnerabilities(self, report_constructor, get_item_mock):
        report_constructor.return_value = None
        snyk_report = SnykReport.SnykReport('test')

        def get_item(item):
            return item

        get_item_mock.side_effect = get_item
        vulnerabilities = [
            {
                'from': ['thisapp', 'A@1.0.0', 'A_A@1.0.0', 'A_A_A@1.0.0'],
                'upgrades': [False, 'A@1.0.1', 'A_A@1.0.0', 'A_A_A@1.0.0'],
                'language': 'js',
                'top_level_module': 'A',
                'Recommendations': 'Update A_A_A to some version',
                'Issue Severity': 'High',
                'Paths': {'A@1.0.1>A_A@1.0.0>A_A_A@1.0.0'}
            },
            {
                'from': ['thisapp', 'A@1.0.0', 'A_A@1.0.0', 'A_A_A@1.0.0'],
                'upgrades': [False, 'A@1.0.1', 'B_B@1.0.0', 'A_A_A@1.0.0'],
                'language': 'js',
                'top_level_module': 'A',
                'Recommendations': 'Update A_A_A to some version',
                'Issue Severity': 'Medium',
                'Paths': {'A@1.0.1>B_B@1.0.0>A_A_A@1.0.0'}
            },
            {
                'from': ['thisapp', 'A@1.0.0', 'B_B@1.0.0', 'D_D_D@1.0.0'],
                'upgrades': [False, 'A@1.0.1', 'B_B@1.0.0', 'D_D_D@1.0.0'],
                'language': 'js',
                'top_level_module': 'A',
                'Recommendations': 'Update D_D_D to some version',
                'Issue Severity': 'High',
                'Paths': {'A@1.0.1>A_A@1.0.0>D_D_D@1.0.0'}
            },
            {
                'from': ['thisapp', 'B@1.0.0', 'B_B@1.0.0', 'C_C_C@1.0.0'],
                'upgrades': [False, 'B@1.0.0', 'B_B@1.0.0', 'C_C_C@1.0.0'],
                'language': 'js',
                'top_level_module': 'B',
                'Recommendations': 'Update C_C_C to some version',
                'Issue Severity': 'Medium'
            },
            {
                'from': ['thisapp', 'B@1.0.0', 'B_B@1.0.0', 'C_C_C@1.0.0'],
                'upgrades': [],
                'language': 'js',
                'top_level_module': 'B',
                'Recommendations': 'Update C_C_C to some version',
                'Issue Severity': 'Medium'
            }
        ]
        grouped_vulns = snyk_report.group_vulnerabilities(vulnerabilities)
        expected_groped_vulns = [
            {
                'from': ['thisapp', 'A@1.0.0', 'A_A@1.0.0', 'A_A_A@1.0.0'],
                'Issue Severity': 'High',
                'Paths': {'A@1.0.1>A_A@1.0.0>A_A_A@1.0.0', 'A@1.0.1>B_B@1.0.0>A_A_A@1.0.0'},
                'RP Defect Type': 'Product Bug',
                'Recommendations': 'Update A_A_A to some version',
                'language': 'js',
                'top_level_module': 'A',
                'upgrades': [False, 'A@1.0.1', 'A_A@1.0.0', 'A_A_A@1.0.0']
            },
            {
                'from': ['thisapp', 'A@1.0.0', 'B_B@1.0.0', 'D_D_D@1.0.0'],
                'Issue Severity': 'High',
                'Paths': {'A@1.0.1>A_A@1.0.0>D_D_D@1.0.0'},
                'RP Defect Type': 'Product Bug',
                'Recommendations': 'Update D_D_D to some version',
                'language': 'js',
                'top_level_module': 'A',
                'upgrades': [False, 'A@1.0.1', 'B_B@1.0.0', 'D_D_D@1.0.0']
            },
            {
                'from': ['thisapp', 'B@1.0.0', 'B_B@1.0.0', 'C_C_C@1.0.0'],
                'Issue Severity': 'Medium',
                'RP Defect Type': 'No Defect',
                'Recommendations': 'Update C_C_C to some version',
                'language': 'js',
                'top_level_module': 'B',
                'upgrades': [False, 'B@1.0.0', 'B_B@1.0.0', 'C_C_C@1.0.0']
            }
        ]
        self.assertEqual(3, len(grouped_vulns))
        self.assertEqual(expected_groped_vulns, grouped_vulns)
