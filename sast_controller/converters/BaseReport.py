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

import xml.etree.ElementTree as ET
from json import loads

import os

from sast_controller.bug_bar import bug_bar


class BaseReport(object):
    """Canonical data model"""
    _bug_bar = None
    provider = "Reapsaw"
    test_type = "sast"
    severity_mapping = {
        'Critical': 'Blocker',
        'High': 'Critical',
        'Medium': 'Major',
        'Moderate': 'Minor',
        'Low': 'Minor',
        'Information': 'Trivial',
        'Info': 'Trivial'
    }

    canonical_issue_model = {
        "Issue Name": "",  # Name issue will have in RP and Jira
        "Issue Tool": "",
        "Steps To Reproduce": "",
        "Issue Priority": "",  # Priority according to Bug Bar
        "Issue Severity": "",  # Risk Rating according to Bug Bar
        "Issue Confidence": "",
        "CWE": "",  # in case available
        "CVE": "",  # in case available
        "Overview": "",
        "Recommendations": "",
        "References": "",  # where you can read more about issue(s)
        "Paths": "",  # paths in code affected by issue
        "error_string": "",
        "Description": "",
        "Instances": "",
        "Attachments": [],
        "Tags": [],
        "Jira Name": "",
        "Repo": os.environ.get('REPO', '')
    }

    def __init__(self, report):
        """
        :param report:
            raw report from SAST tool
        """
        if 'xml' not in report:
            with open(report) as f:
                self.report = loads(f.read())
        else:
            tree = ET.parse(report)
            self.report = tree.getroot()
        self.new_items = dict()
        self.report = self._canonify()

    @property
    def bug_bar(self):
        if not self._bug_bar:
            self._bug_bar = bug_bar.read_json()
        return self._bug_bar

    @staticmethod
    def get_git_path(repo, branch, file, line=''):
        if not repo or not branch:
            return ''
        git_path = f'{repo}/blob/{branch}/{file}'
        if line:
            git_path += f"#L{line}"
        return git_path

    def _canonify(self):
        raise NotImplementedError
