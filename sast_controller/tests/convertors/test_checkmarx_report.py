import copy
import os
import unittest
from unittest import mock

from sast_controller.converters import CheckmarxReport

BUG_BAR_CSS = {
    "Cross-site Scripting (XSS)": {
        "is_issue": "",
        "risk_rating": "High",
        "jira_priority": "Major",
        "burp": "",
        "grouped": "",
        "cxsast": "Cross-site scripting (reflected);Reflected_XSS_All_Clients;Stored_XSS",
        "description": {},
        "recommendation": {}
    },
}

BUG_BAR_SQLI = {
    "SQL Injection": {
        "is_issue": "",
        "risk_rating": "Critical",
        "jira_priority": "Major",
        "burp": "SQL Injection",
        "grouped": "",
        "cxsast": "SQL Injection in Content Provider;SQL_Injection"
    },
}

EXPECTED_REPORT = [{
    'Attachments': [],
    'CVE': '',
    'CWE': '[CWE-79|https://cwe.mitre.org/data/definitions/79]',
    'Description': ' Cross-site Scripting (XSS)\n'
                   '    GROUP: CSharp_High_Risk\n'
                   '    CATEGORY: A7-Cross-Site Scripting (XSS)\n'
                   '    *Code*:\n'
                   '    ``` public IActionResult PostTranslate(JsonApiResponse '
                   'article, IContentTranslation contentTranslation) ```',
    'Instances': 'File code/src/MyApp.Api.Web/Controllers/Controller.cs\n'
                 'Checkmarx project: myproj',
    'Issue Confidence': 'Certain',
    'Issue Name': 'Cross-site Scripting (XSS).code/src/MyApp.Api.Web/Controllers/Controller.cs',
    'Issue Priority': 'Major',
    'Issue Severity': 'High',
    'Issue Tool': 'Checkmarx',
    'Jira Name': 'Cross-site Scripting (XSS)',
    'Links': 'https://sast.mysite.com/CxWebClient/ViewerMain.aspx?scanid=1027717&projectid=3076&pathid=11',
    'Overview': '',
    'Paths': '',
    'RP Comment': '',
    'RP Defect Type': 'To Investigate',
    'Recommendations': 'Please review and modify vulnerable code in line 553 of Controller.cs',
    'References': 'Line 553 in file '
                  '[code/src/MyApp.Api.Web/Controllers/Controller.cs|https://sast.mysite.com/CxWebClient/'
                  'ViewerMain.aspx?scanid=1027717&projectid=3076&pathid=11]',
    'Repo': 'https://github.com/myrepo',
    'Snippet': 'public IActionResult PostTranslate(JsonApiResponse article, '
               'IContentTranslation contentTranslation)',
    'Steps To Reproduce': '',
    'Tags': [
        {'TestType': 'sast'},
        {'Provider': 'Reapsaw'},
        {'Tool': 'Checkmarx'}],
    'error_string': 'Cross-site Scripting (XSS) 79\n'
                    'code/src/MyApp.Api.Web/Controllers/Controller.cs'}, {
    'Attachments': [],
    'CVE': '',
    'CWE': '[CWE-79|https://cwe.mitre.org/data/definitions/79]',
    'Description': ' Cross-site Scripting (XSS)\n'
                   '    GROUP: CSharp_High_Risk\n'
                   '    CATEGORY: A7-Cross-Site Scripting (XSS)\n'
                   '    *Code*:\n'
                   '    ``` public async Task<IActionResult> GetById(string id, '
                   'string apiKey) ```',
    'Instances': 'File code/src/MyApp.Api.Web/Controllers/Controller.cs\n'
                 'Checkmarx project: myproj',
    'Issue Confidence': 'Certain',
    'Issue Name': 'Cross-site Scripting (XSS).code/src/MyApp.Api.Web/Controllers/Controller.cs',
    'Issue Priority': 'Major',
    'Issue Severity': 'High',
    'Issue Tool': 'Checkmarx',
    'Jira Name': 'Cross-site Scripting (XSS)',
    'Links': 'https://sast.mysite.com/CxWebClient/ViewerMain.aspx?scanid=1027717&projectid=3076&pathid=12',
    'Overview': '',
    'Paths': '',
    'RP Comment': 'Oleksii C my_project, [Monday, July 29, 2019 10:36:13 AM]: '
                  'Changed status to Confirmed\r\n'
                  'Oleksii C my_project, [Monday, July 29, 2019 10:35:47 AM]: '
                  'Changed status to Not Exploitable',
    'RP Defect Type': 'Product Bug',
    'Recommendations': 'Please review and modify vulnerable code in line 553 of Controller.cs',
    'References': 'Line 467 in file '
                  '[code/src/MyApp.Api.Web/Controllers/Controller.cs|https://sast.mysite.com/CxWebClient/'
                  'ViewerMain.aspx?scanid=1027717&projectid=3076&pathid=12]',
    'Repo': 'https://github.com/myrepo',
    'Snippet': 'public async Task<IActionResult> GetById(string id, string '
               'apiKey)',
    'Steps To Reproduce': '',
    'Tags': [
        {'TestType': 'sast'},
        {'Provider': 'Reapsaw'},
        {'Tool': 'Checkmarx'}],
    'error_string': 'Cross-site Scripting (XSS) 79\n'
                    'code/src/MyApp.Api.Web/Controllers/Controller.cs'}
]


@mock.patch.object(CheckmarxReport, 'CX_PROJECT', 'myproj')
class TestCheckmarxReport(unittest.TestCase):
    def setUp(self):
        return_json_patcher = mock.patch('sast_controller.bug_bar.bug_bar.read_json')
        self.mock_return_json = return_json_patcher.start()
        self.addCleanup(return_json_patcher.stop)
        self.maxDiff = None

    @mock.patch.dict(os.environ, {'REPO': 'https://github.com/myrepo'})
    @mock.patch('sast_controller.drivers.cx.Checkmarx.Checkmarx')
    def test_report(self, cx_klass):
        self.mock_return_json.return_value = BUG_BAR_CSS
        cx_report = CheckmarxReport.CheckmarxReport(
            os.path.dirname(os.path.abspath(__file__)) + '/checkmarx_report.xml')
        self.assertEqual(EXPECTED_REPORT, cx_report.report)
        self.assertEqual({'Checkmarx': set()}, cx_report.new_items)

    @mock.patch.dict(os.environ, {'REPO': 'https://github.com/myrepo'})
    @mock.patch('sast_controller.drivers.cx.Checkmarx.Checkmarx')
    def test_report_not_in_bug_bar(self, cx_klass):
        self.mock_return_json.return_value = BUG_BAR_SQLI
        cx_report = CheckmarxReport.CheckmarxReport(
            os.path.dirname(os.path.abspath(__file__)) + '/checkmarx_report.xml')
        self.assertEqual([], cx_report.report)
        self.assertEqual({'Checkmarx': {'Reflected_XSS_All_Clients'}}, cx_report.new_items)

    @mock.patch.dict(os.environ, {'REPO': 'https://github.com/myrepo'})
    @mock.patch('sast_controller.drivers.cx.Checkmarx.Checkmarx')
    def test_report_not_an_issue(self, cx_klass):
        new_bug_bar = copy.deepcopy(BUG_BAR_CSS)
        new_bug_bar['Cross-site Scripting (XSS)']['is_issue'] = 'FALSE'
        self.mock_return_json.return_value = new_bug_bar
        cx_report = CheckmarxReport.CheckmarxReport(
            os.path.dirname(os.path.abspath(__file__)) + '/checkmarx_report.xml')
        self.assertEqual([], cx_report.report)
        self.assertEqual({'Checkmarx': set()}, cx_report.new_items)

    @mock.patch.dict(os.environ, {'REPO': 'https://github.com/myrepo', 'BRANCH': 'develop'})
    @mock.patch('sast_controller.drivers.cx.Checkmarx.Checkmarx')
    def test_report_git(self, cx_klass):
        self.mock_return_json.return_value = BUG_BAR_CSS
        cx_report = CheckmarxReport.CheckmarxReport(
            os.path.dirname(os.path.abspath(__file__)) + '/checkmarx_report.xml')
        expected = copy.deepcopy(EXPECTED_REPORT)
        for _ in expected:
            _['Instances'] = \
                'File ' \
                'https://github.com/myrepo/blob/develop/code/src/MyApp.Api.Web/Controllers/Controller.cs\n' \
                'Checkmarx project: myproj'
        self.assertEqual(expected, cx_report.report)
        self.assertEqual({'Checkmarx': set()}, cx_report.new_items)

    @mock.patch('sast_controller.drivers.cx.Checkmarx.Checkmarx')
    def test_report_bug_bar_desc_csharp(self, cx_klass):
        #  possible languages in CX: javascript ; csharp; java; scala
        expected = "test custom description"
        expected_rec = "test custom rec"
        test = copy.deepcopy(BUG_BAR_CSS)
        test["Cross-site Scripting (XSS)"]['description'] = {"csharp": expected}
        test["Cross-site Scripting (XSS)"]['recommendation'] = {"csharp": expected_rec}
        self.mock_return_json.return_value = test
        cx_report = CheckmarxReport.CheckmarxReport(
            os.path.dirname(os.path.abspath(__file__)) + '/checkmarx_report.xml')

        item = cx_report.report[0]
        self.assertIn(expected, item['Description'])
        self.assertEqual(expected_rec, item['Recommendations'])
