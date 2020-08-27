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

from copy import deepcopy
import json
import os
from re import sub

import semver

from sast_controller.converters.BaseReport import BaseReport
from sast_controller.converters import SEVERITY_MAPPING, SEVERITY_MAPPING_TYPE


class SnykReport(BaseReport):
    """Canonical dta model implementation for Snyk"""

    tool_name = "Snyk"

    @staticmethod
    def max_severity(item1, item2):
        if SEVERITY_MAPPING.get(item1['Issue Severity']) > SEVERITY_MAPPING.get(item2['Issue Severity']):
            return item1['Issue Severity']
        return item2['Issue Severity']

    @staticmethod
    def get_exact_top_deps():
        """
        Returns top level packages that have exact versions (non-range)
        :return:
        """
        # Note, this currently works only for NPM and only when running from folder containing package.json file
        try:
            with open('package.json', 'r') as package_json:
                dependencies = json.loads(package_json.read()).get('dependencies', [])
        except FileNotFoundError:
            return []
        fixed_dependencies = []
        for dependency in dependencies:
            if not any(symbol in dependencies[dependency] for symbol in ['^', '~', '>', '<']):
                fixed_dependencies.append('@'.join([dependency, dependencies[dependency]]))
        return fixed_dependencies

    @staticmethod
    def filter_vulnerable_paths(vulnerabilities):
        fixed_deps = SnykReport.get_exact_top_deps()
        if not fixed_deps:
            return vulnerabilities
        result = []
        for vulnerability in vulnerabilities:
            vuln_paths = vulnerability['Paths'].copy()
            for vuln_path in vuln_paths:
                if (any(fixed_dependency in vuln_path.split('>')[2:] for fixed_dependency in fixed_deps)
                        and 'Re-install' in vulnerability['Recommendations']):
                    vulnerability['Paths'].remove(vuln_path)
            if vulnerability['Paths']:
                result.append(vulnerability)
        return result

    def group_vulnerabilities(self, vulnerabilities):
        """
        Groups vulnerabilities by top level module and recommendations
        :return:
        """
        grouped_issues = {}
        for vuln in vulnerabilities:
            converted_vuln = self.get_item(vuln)
            if not converted_vuln['upgrades'] and converted_vuln['language'] != 'dotnet':
                continue
            # do not report issues which don't contain upgrades for top modules, except javascript until
            # we know from Snyk what we can do for such vulnerable modules
            if (converted_vuln['upgrades'] and converted_vuln['upgrades'][1] == converted_vuln['from'][1]
                    and converted_vuln['language'] != 'js'):
                continue
            key = (converted_vuln['top_level_module'], converted_vuln['Recommendations'])
            if key not in grouped_issues:
                grouped_issues[key] = converted_vuln
            else:
                grouped_issues[key]['Paths'] = grouped_issues[key]['Paths'].union(converted_vuln['Paths'])
                grouped_issues[key]['Issue Severity'] = self.max_severity(grouped_issues[key],
                                                                          converted_vuln)
            grouped_issues[key]['RP Defect Type'] = SEVERITY_MAPPING_TYPE[grouped_issues[key]['Issue Severity']]
        return list(grouped_issues.values())

    @staticmethod
    def update_recommendations(vulnerabilities):
        recommendations = dict()
        for vuln in vulnerabilities:
            # dotnet issues don't have upgrades
            if not vuln['upgrades']:
                continue
            if vuln['from'][1] not in recommendations:
                recommendations[vuln['from'][1]] = vuln['upgrades'][1]
            else:

                module = vuln['upgrades'][1][:vuln['upgrades'][1].rfind('@')]
                if semver.compare(vuln['upgrades'][1].split('@')[-1], recommendations[vuln['from'][1]].split('@')[-1],
                                  loose=True) == -1:
                    max_version = recommendations[vuln['from'][1]].split('@')[-1]
                else:
                    max_version = vuln['upgrades'][1].split('@')[-1]
                recommendations[vuln['from'][1]] = '@'.join([module, max_version])
        for vuln in vulnerabilities:
            if vuln['language'] == 'dotnet':
                vuln['Recommendations'] = f'Upgrade `{vuln["top_level_module"]}` to the latest compatible version.'
                continue
            if semver.compare(vuln['from'][1].split("@")[-1], recommendations[vuln['from'][1]].split("@")[-1],
                              loose=True) == -1:
                vuln['Recommendations'] = (f'Upgrade `{vuln["top_level_module"]}` '
                                           f'to version {recommendations[vuln["from"][1]].split("@")[-1]} or higher')
            else:
                vuln['Recommendations'] = ('Your dependencies are out of date. Please remove your `node_modules` '
                                           'directory and lock file, run `npm install` and commit new lock file to '
                                           'your repo. Note, this will likely make a lot of changes to lock file.')

    def _canonify(self):
        if isinstance(self.report, list):
            vulnerabilities = []
            for project_report in self.report:
                vulnerabilities.extend(project_report.get('vulnerabilities', []))
        else:
            vulnerabilities = self.report.get('vulnerabilities', [])
        grouped_vulnerabilites = self.group_vulnerabilities(vulnerabilities)
        SnykReport.update_recommendations(grouped_vulnerabilites)
        filtered_vulns = self.filter_vulnerable_paths(grouped_vulnerabilites)
        for vulnerability in filtered_vulns:
            vulnerability['Paths'] = '\n\n'.join(vulnerability['Paths'])
            del vulnerability['from']
        return filtered_vulns

    def get_item(self, vulnerability):
        """
        Convert to canonical data model
        :param vulnerability:
        :return:
        """
        smileys = [':\)', ':\(', ':P', ':D',
                   ';\)', '\(y\)', '\(n\)', '\(on\)', '\(off\)',
                   '\(!\)', '\(\*\)', '\(\*r\)', '\(\*g\)', '\(\*b\)',
                   '\(\*y\)', '\(/\)', '\(x\)', '\(i\)', '\(\+\)',
                   '\(-\)', '\(\?\)', '<3', '</3'
                   ]
        if isinstance(vulnerability['semver']['vulnerable'], list):
            vulnerable_versions = ", ".join(vulnerability['semver']['vulnerable'])
        else:
            vulnerable_versions = vulnerability['semver']['vulnerable']

        priority = 'Major'
        for bug_bar_issue in self.bug_bar:
            if bug_bar_issue == 'Vulnerable Software':
                priority = self.bug_bar[bug_bar_issue]['jira_priority']
        vulnerability['from'][0] = vulnerability['from'][0][:vulnerability['from'][0].rfind('@')]
        vulnerable_path = '>'.join(vulnerability['from'])
        issue_base = deepcopy(self.canonical_issue_model)
        issue_base['Paths'] = set()
        issue_base['Security Tool'] = self.tool_name
        issue_base['Issue Priority'] = priority
        issue_base['Issue Severity'] = vulnerability['severity'].title()

        description = vulnerability['description'].split('##')
        remediation = " ".join([s for s in description if 'Remediation' in s])
        remediation = remediation.replace('Remediation', '*Remediation:*')
        overview = " ".join([s for s in description if 'Overview' in s])

        issue_base['Description'] = f"*Vulnerable Package:* " \
                                    f"{vulnerability['packageName']}\n*Current Version:* " \
                                    f"{vulnerability['version']}\n*Vulnerable Version(s):* " \
                                    f"{vulnerable_versions}\n " \
                                    f"\n{remediation}\n " \
                                    f"{overview}\n "

        issue_base['Paths'].add(vulnerable_path)
        issue_base['Description'] = issue_base['Description'].replace("##", "").replace("**Example:**", '')
        issue_base['Description'] = sub(r'```((.|\n)*)```', '', issue_base['Description']).replace(r'', '')
        issue_base['Description'] = sub(r'|'.join(smileys), '', issue_base['Description'])
        try:
            issue_base['Recommendations'] = f"Package {vulnerability['from'][1]} " \
                                            f"contains known vulnerabilities"
            issue_base['Issue Name'] = f'{vulnerability["title"]}.{vulnerability["from"][1]}'
        except Exception:
            issue_base['Recommendations'] = f"Package {vulnerability['packageName']}:{vulnerability['version']} " \
                                            f"contains known vulnerabilities"
            issue_base['Issue Name'] = f'{vulnerability["title"]}.' \
                                       f'{vulnerability["packageName"]}:{vulnerability["version"]}'
        if 'Remediation' in vulnerability.get("description"):
            issue_base['Recommendations'] = \
                vulnerability["description"].split("Remediation")[1].split("References")[0].replace("#", "").strip()
            issue_base['References'] = vulnerability["description"].split("Remediation")[1].split("References")[1]
        try:
            issue_base['CWE'] = vulnerability['identifiers']['CWE'][0]
        except Exception:
            pass
        separator_index = vulnerability["from"][1].rfind('@')
        top_level_module = vulnerability["from"][1][:separator_index]
        issue_base['top_level_module'] = top_level_module
        issue_base['error_string'] = top_level_module
        issue_base['upgrades'] = vulnerability.get('upgradePath')
        issue_base['from'] = vulnerability.get('from')
        issue_base['language'] = vulnerability.get('language')
        issue_base['Issue Confidence'] = 'Certain'
        issue_base["Tags"].extend([{"TestType": self.test_type},
                                   {"Provider": self.provider},
                                   {"Tool": self.tool_name}])
        issue_base['Jira Name'] = 'Vulnerable Software'
        branch = os.environ.get('BRANCH', '')
        instances = issue_base['top_level_module']
        if branch:
            instances += f'\nBranch: {branch}'
        issue_base['Instances'] = instances
        issue_base['Issue Name'] = f"{vulnerability['title']}.{issue_base['top_level_module']}"

        return issue_base
