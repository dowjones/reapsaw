import os
import unittest
from unittest import mock

from sast_controller.drivers.cx import utils

JIRA_RECOMMENDATION = '# Validate all dynamic data, regardless of source. Validation should be based on a whitelist: ' \
                      'accept only data fitting a specified structure, rather than reject bad patterns. ' \
                      'Check for:\n#* Data type\n#* Size\n#* Range\n#* Format\n#* Expected values\n# Validation is ' \
                      'not a replacement for encoding. Fully encode all dynamic data, regardless of source, before ' \
                      'embedding it in output. Encoding should be context-sensitive. For example:\n#* HTML encoding ' \
                      'for HTML content\n#* HTML attribute encoding for data output to attribute values\n#* ' \
                      'Javascript encoding for server-generated Javascript.\n# Consider using either the ESAPI ' \
                      'encoding library, or its built-in functions. For earlier versions of ASP.NET, consider using ' \
                      'the AntiXSS library.\n# In the Content-Type HTTP response header, explicitly define character ' \
                      'encoding (charset) for the entire page.\n# Set the httpOnly flag on the session cookie, to ' \
                      'prevent XSS exploits from stealing the cookie.\n\n'


JIRA_OVERVIEW = 'The software does not sufficiently validate, filter, escape, and/or encode user-controllable input ' \
                'before it is placed in output that is used as a web page that is served to other users.'


class TestUtils(unittest.TestCase):

    def test_get_jira_recommendations(self):
        cx_client = mock.MagicMock()
        file_name = os.path.dirname(os.path.abspath(__file__)) + '/jira_recommendation.html'
        with open(file_name, 'r') as recommendation_file:
            recommendation = recommendation_file.read()
            cx_client.get_query_description_by_query_id.return_value = recommendation
            jira_recommendation = utils.get_jira_recommendations(cx_client, '123')
            self.assertEqual(JIRA_RECOMMENDATION, jira_recommendation)

    def test_get_jira_overview(self):
        cx_client = mock.MagicMock()
        file_name = os.path.dirname(os.path.abspath(__file__)) + '/jira_overview.html'
        with open(file_name, 'r') as overview_file:
            overview = overview_file.read()
            cx_client.get_cwe_description.return_value = overview
            jira_overview = utils.get_jira_overview(cx_client, '123')
            self.assertEqual(JIRA_OVERVIEW, jira_overview)

    def test_get_jira_tag(self):
        self.assertEqual('', utils.get_jira_tag('script'))
        self.assertEqual('#', utils.get_jira_tag('ol'))
        self.assertEqual('*', utils.get_jira_tag('ul'))
        self.assertEqual('', utils.get_jira_tag('li'))
