import os
import unittest
from unittest import mock

from sast_controller.converters import Converter
from sast_controller.converters import SnykReport

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


EXPECTED_ERR_MSG = '@nyc.dotted'
EXPECTED_INFO_MSG = (
    'h3.*Instances:*\n'
    '@nyc.dotted\n'
    'h3.*Recommendations:*\n'
    '\n'
    'Upgrade `@nyc.dotted` to version 8.1.0 or higher\n'
    'h3.*Overview:*\n'
    '{panel:title=Regular Expression Denial of Service (ReDoS)}*Description*: \n'
    '*Vulnerable Package:* brace-expansion\n'
    '*Current Version:* 1.1.6\n'
    '*Vulnerable Version(s):* <1.1.7\n'
    ' \n'
    ' *Remediation:*\n'
    'Upgrade `brace-expansion` to version 1.1.7 or higher.\n'
    '\n'
    '\n'
    '  Overview\n'
    '[`brace-expansion`](https://www.npmjs.com/package/brace-expansion) is a '
    'package that performs brace expansion as known from sh/bash.\n'
    'Affected versions of this package are vulnerable to Regular Expression '
    'Denial of Service (ReDoS) attacks.\n'
    '\n'
    '*References*: \n'
    '- [GitHub PR](https://github.com/juliangruber/brace-expansion/pull/35)\n'
    '- [GitHub Issue](https://github.com/juliangruber/brace-expansion/issues/33)\n'
    '- [GitHub '
    'Commit](https://github.com/juliangruber/brace-expansion/pull/35/commits/'
    'b13381281cead487cbdbfd6a69fb097ea5e456c3)\n'
    '\n'
    '*Paths*: \n'
    'MyAPP>@nyc.dotted@7.1.0>glob@7.0.5>minimatch@3.0.2>brace-expansion@1.1.6\n'
    '\n'
    '{panel}\n'
)

TEST_ISSUE = {'Issue Name': 'Prototype Pollution.nyc',
              'Issue Tool': 'Snyk',
              'Steps To Reproduce': '',
              'Issue Priority': 'Major',
              'Issue Severity': 'Medium',
              'Issue Confidence': 'Certain',
              'Recommendations': 'Upgrade `nyc` to version 11.7.2 or higher',
              'Paths': 'MyApp>nyc@7.1.0>istanbul-lib-instrument@1.1.0-alpha.4>babel-generator@6.11.4'
                       '>babel-types@6.11.1>lodash@4.13.1\n\n'
                       'MyApp>nyc@7.1.0>istanbul-lib-instrument@1.1.0-alpha.4>'
                       'babel-traverse@6.11.4>lodash@4.13.1\n\n'
                       'MyApp>nyc@7.1.0>istanbul-lib-instrument@1.1.0-alpha.4>babel-traverse@6.11.4'
                       '>babel-types@6.11.1>lodash@4.13.1',
              'Description': '*Vulnerable Package:* lodash\n'
                             '*Current Version:* 4.13.1\n*Vulnerable Version(s):* <4.17.5\n \n *Remediation:*\n'
                             'Upgrade `lodash` to version 4.17.5 or higher.\n\n\n  Overview\n'
                             'Affected versions of this package are vulnerable to Prototype '
                             'Pollution. \nThe utilities function allow modification of the `Object` prototype.\n\n\n ',
              'upgrades': [False, 'nyc@7.1.0', 'istanbul-lib-instrument@1.1.0', 'babel-template@6.9.0',
                           'lodash@4.17.5'], 'language': 'js', 'RP Defect Type': 'No Defect'}

EXPECTED_INFO_MESSAGE = (
    '{panel:title=Prototype Pollution}*Description*: \n'
    '*Vulnerable Package:* lodash\n'
    '*Current Version:* 4.13.1\n'
    '*Vulnerable Version(s):* <4.17.5\n \n'
    ' *Remediation:*\n'
    'Upgrade `lodash` to version 4.17.5 or higher.\n\n\n'
    '  Overview\n'
    'Affected versions of this package are vulnerable to Prototype Pollution. \n'
    'The utilities function allow modification of the `Object` prototype.\n\n'
    '*Paths*: \n'
    'MyApp>nyc@7.1.0>istanbul-lib-instrument@1.1.0-alpha.4'
    '>babel-generator@6.11.4>babel-types@6.11.1>lodash@4.13.1\n'
    'MyApp>nyc@7.1.0>istanbul-lib-instrument@1.1.0-alpha.4'
    '>babel-traverse@6.11.4>babel-types@6.11.1>lodash@4.13.1\n'
    'MyApp>nyc@7.1.0>istanbul-lib-instrument@1.1.0-alpha.4'
    '>babel-traverse@6.11.4>lodash@4.13.1\n\n'
    '{panel}'
)


class TestConverter(unittest.TestCase):
    def setUp(self):
        return_json_patcher = mock.patch('sast_controller.bug_bar.bug_bar.read_json')
        self.mock_return_json = return_json_patcher.start()
        self.addCleanup(return_json_patcher.stop)
        self.maxDiff = None

    def test_get_rp_items_snyk(self):
        self.mock_return_json.return_value = BUG_BAR
        snyk_report_file = os.path.dirname(os.path.abspath(__file__)) + '/snyk_report.json'
        models = {snyk_report_file: SnykReport.SnykReport}
        converter = Converter.Converter(models)
        items = converter.get_rp_items()
        self.assertEqual('Medium', items[0].severity)
        self.assertEqual('Major', items[0].priority)
        self.assertEqual('Certain', items[0].confidence)
        self.assertEqual([], items[0].attachments)
        self.assertEqual({'RP Defect Type': 'No Defect', 'RP Comment': ''}, items[0].defect_type_info)
        self.assertEqual(EXPECTED_ERR_MSG, items[0].msgs[0].message)
        self.assertEqual(EXPECTED_INFO_MSG, items[0].msgs[1].message)

    def test_get_get_info_msg(self):
        self.assertEqual(EXPECTED_INFO_MESSAGE, Converter.Converter.get_info_msg(TEST_ISSUE, ''))
