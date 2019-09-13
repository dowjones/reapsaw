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
import logging

import os

from sast_controller.bin import config
from sast_controller.drivers.cx import Checkmarx, utils
from sast_controller.extractors import vulnerability_info as vi
from sast_controller.converters.BaseReport import BaseReport


LOG = logging.getLogger(__name__)
utils.configure_logging(LOG)

CX_PROJECT = config.Config().CX_PROJECT_NAME

RP_DEFECT_TYPES = {
    '0': 'To Investigate',
    '1': 'No Defect',
    '2': 'Product Bug',
    '3': 'Product Bug',
    '4': 'System Issue'
}


class CheckmarxReport(BaseReport):
    """Canonical dta model implementation for Checkmarx"""
    tool_name = "Checkmarx"
    info_message = """ {}
    GROUP: {}
    CATEGORY: {}
    *Code*:
    ``` {} ```"""
    instance = 'Line {} in file [{}|{}]'
    recommendation = 'Please review and modify vulnerable code in line {} of {}'

    @staticmethod
    def mask(text):
        """
        Add masking for found secrets
        :param text:
        :return:
        """
        hidden_part = max(int(len(text) * float(os.environ['MASK_PERCENT'])), len(text) - int(
            os.environ['MAX_TOKEN_LEN']))
        hidden_token = "".join((text[:-hidden_part], "*" * (len(text) - hidden_part)))
        return hidden_token

    @staticmethod
    def _get_repo(repo, cx_client):
        """
        Get Repo from Cx project Settingssa
        :param repo:
        :return:
        """
        conf = cx_client.find_project_by_name(CX_PROJECT)
        if conf and "SourceCodeSettings" in conf and conf.SourceCodeSettings.SourceOrigin == 'SourceControl':
            repo = conf.SourceCodeSettings.SourceControlSetting.ServerName
            if '@' in repo:
                repo = f"https://{str(repo).split('@')[1].replace(':', '/')}"
        return repo

    def _canonify(self):
        # TODO: If no connectivity with CX should we generate report or not?
        cx_client = Checkmarx.Checkmarx(CX_PROJECT)
        report = []
        bugbar_vulns = set()
        existing_bb = set()
        jira_recommendations = {}
        jira_desc = {}
        repo = os.environ.get('REPO', '')
        branch = os.environ.get('BRANCH', '')
        if not repo:
            self._get_repo(repo, cx_client)
        existing_results = set()
        for query in self.report:
            group = query.attrib.get("group")
            query_id = query.attrib.get("id")
            cwe = query.attrib.get("cweId")
            category = query.attrib.get("categories")
            bugbar_vulns.add(query.attrib.get("name"))
            if category and category.rfind(";"):
                category_place = category.rfind(";") + 1
                category = category[category_place:]
            for result in query:
                for path_ in result:
                    result_file = result.attrib["FileName"]
                    name = query.attrib.get("name")
                    language = query.attrib.get("Language")
                    line = result.attrib.get("Line")
                    result_state = result.attrib.get('state')
                    remark = result.attrib.get("Remark")
                    rp_defect_type = RP_DEFECT_TYPES[result_state]
                    priority = ''
                    severity = result.attrib.get("Severity")
                    deep_link = result.attrib.get("DeepLink")
                    git_link = self.get_git_path(repo, branch, result.attrib["FileName"])
                    file_index = str(result_file).rfind("/")
                    test_name = str(result_file)[file_index + 1:]
                    issue = deepcopy(self.canonical_issue_model)
                    name, priority, severity, desc, rec = self.__get_from_bugbar(existing_bb, issue, name, priority,
                                                                                 severity, language)

                    if not priority and not os.environ.get("send_without_bb", ""):
                        continue
                    issue['Issue Name'] = f"{name}.{result_file}" if issue.get('Grouped', True) else name
                    issue['Jira Name'] = name
                    issue['Issue Tool'] = self.tool_name
                    issue["Issue Severity"] = severity
                    issue["Issue Priority"] = priority
                    issue['Issue Confidence'] = 'Certain'
                    issue['error_string'] = f"{name} {cwe}\n{result_file}"
                    issue['Links'] = deep_link
                    issue['CWE'] = f"[CWE-{cwe}|{vi.CWE_LINK + cwe}]"
                    issue['Repo'] = repo
                    if rp_defect_type:
                        issue['RP Defect Type'] = rp_defect_type
                        issue['RP Comment'] = remark
                    if not rec:
                        try:
                            if query_id not in jira_recommendations:
                                jira_recommendations[query_id] = utils.get_jira_recommendations(cx_client, query_id)

                            issue['Recommendations'] = jira_recommendations[query_id]
                        except Exception:
                            LOG.info(f'Could not parse issue recommendation for this query id {query_id}')
                            # use hardcoded recommendations in case of any issues with parsing html returned by Cx
                            issue['Recommendations'] = self.recommendation.format(line, test_name)
                            jira_recommendations[query_id] = self.recommendation.format(line, test_name)
                    else:
                        issue['Recommendations'] = rec
                    issue["Tags"].extend([{"TestType": self.test_type},
                                          {"Provider": self.provider},
                                          {"Tool": self.tool_name}])
                    place = self.instance.format(line, result_file, deep_link)
                    issue['References'] = place

                    if git_link:
                        issue['Instances'] = f"File {git_link}\nCheckmarx project: {CX_PROJECT}"
                    else:
                        issue['Instances'] = f"File {result_file}\nCheckmarx project: {CX_PROJECT}"
                    try:
                        # TODO: remove hardcoded values - use config instead
                        if name == 'Sensitive Information Disclosure':
                            snippet = self.mask(path_[0].find("Snippet").find("Line").find("Code").text.strip())
                        else:
                            snippet = path_[0].find("Snippet").find("Line").find("Code").text.strip()
                    except AttributeError:
                        snippet = path_[0].find("Name").text.strip()
                    issue['Snippet'] = snippet
                    if not desc:
                        issue["Description"] = self.info_message.format(name, group, category, snippet[:100])
                        try:
                            if cwe not in jira_desc:
                                jira_desc[cwe] = utils.get_jira_overview(cx_client, cwe)
                            issue["Description"] = self.info_message.format(jira_desc[cwe], group, category,
                                                                            snippet[:100])
                        except Exception:
                            LOG.info(f'Could not parse issue overview for this cwe id {cwe}')
                            issue["Description"] = self.info_message.format(name, group, category, snippet[:100])
                            jira_desc[cwe] = name
                    else:
                        issue["Description"] = self.info_message.format(desc, group, category,
                                                                        snippet[:100])
                    # do not append multiple results with the same file and line of code to report
                    if result_file + line + name not in existing_results:
                        existing_results.add(result_file + line + name)
                    else:
                        continue
                    report.append(issue)
        print("Checkmarx report generation finished")
        self.new_items[self.tool_name] = bugbar_vulns.difference(existing_bb)
        return report

    def __get_from_bugbar(self, existing_bb, issue, name, priority, severity, lang):
        desc = ''
        recommendation = ''
        for bug_bar_issue in self.bug_bar:
            items = [item.lower() for item in self.bug_bar[bug_bar_issue]['cxsast'].split(';')]
            if name.lower() in items:
                existing_bb.add(name)
                name = bug_bar_issue
                if self.bug_bar[bug_bar_issue]['is_issue'] == 'FALSE':
                    continue
                severity = self.bug_bar[bug_bar_issue]['risk_rating']
                priority = self.bug_bar[bug_bar_issue]['jira_priority']
                if lang.lower() in self.bug_bar[bug_bar_issue]['description']:
                    desc = self.bug_bar[bug_bar_issue]['description'][lang.lower()]
                if lang.lower() in self.bug_bar[bug_bar_issue]['recommendation']:
                    recommendation = self.bug_bar[bug_bar_issue]['recommendation'][lang.lower()]

                if self.bug_bar[bug_bar_issue].get('grouped', '') == 'FALSE':
                    issue['Grouped'] = False
        return name, priority, severity, desc, recommendation
