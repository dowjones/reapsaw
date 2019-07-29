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

from json import dumps
from junit_xml import TestSuite, TestCase

from sast_controller.drivers.rp.TestItem import TestItem
from sast_controller.drivers.rp.TestMessage import TestMessage
from sast_controller.converters import PRIORITY_MAPPING, RP_DEFECT_TYPE_PRIORITY, SEVERITY_MAPPING


class Converter(object):
    """Convert report to canonical data model"""

    def __init__(self, models, repo='', branch=''):
        self.report = []
        self.test_items = []
        self.json_items = []
        self.report_name = 'SAST Scan'
        for report_file, model in models.items():
            model.repo = repo
            model.branch = branch
            model_ = model(report_file)
            self.report += model_.report

    def get_rp_items(self):
        """
        Convert from canonical data model to Report portal test items
        :return:
        """
        test_items_ = []
        aggregated_issues = dict()
        # aggregate issues by issue name and file that contains the issue
        for item in self.report:
            tags = item.get('Tags', None)
            issue_name = item['Issue Name']
            if item.get('Grouped', True):
                issue_key = '%s_%s' % (issue_name, item['Instances'])
            else:
                issue_key = issue_name
            if {'Tool': 'Snyk'} in tags:
                issue_key = item.get('top_level_module')
            if issue_key in aggregated_issues:
                aggregated_issues[issue_key].append(item)
            else:
                aggregated_issues[issue_key] = [item]
        for issues in aggregated_issues.values():
            tags = issues[0].get('Tags', None)
            severity = issues[0]["Issue Severity"]
            priority = issues[0]["Issue Priority"]
            name = issues[0]['Issue Name']
            if {'Tool': 'Snyk'} in tags:
                pkg_name = '.'.join(name.split('.')[1:])
                name = f"Vulnerable Software Version.{pkg_name}"
            issue_confidence = issues[0]['Issue Confidence']
            attachments = []
            tools = set()
            recommendations = ''
            rp_defect_info = self.get_rp_defect_info(issues)
            error_msgs = set()
            info_msgs = set()
            description = set()
            instances = set()
            steps = set()
            paths = set()
            refs = set()
            params = None
            if not name:
                continue
            if not priority:
                priority = PRIORITY_MAPPING[severity]
            severity_val = SEVERITY_MAPPING[issues[0]["Issue Severity"]]
            issue = None
            for issue in issues:
                if issue['Recommendations'] and issue['Recommendations'] not in recommendations:
                    recommendations += f"\n{issue['Recommendations']}"
                if issue['Description']:
                    description.add(issue['Description'])
                if issue['Attachments']:
                    attachments.extend(issue['Attachments'])
                if issue['Instances']:
                    instances.add(issue['Instances'])
                if issue['Repo'] and not any([_ for _ in instances if issue['Repo'] in _]):
                    instances.add(f"Repo {issue['Repo']}")
                if issue['References']:
                    refs.add(issue['References'])
                if issue['Steps To Reproduce']:
                    steps.add(issue['Steps To Reproduce'])
                if issue['Paths']:
                    paths.add(issue['Paths'])
                if severity_val < SEVERITY_MAPPING[issue["Issue Severity"]]:
                    severity = issue["Issue Severity"]
                    severity_val = SEVERITY_MAPPING[issue["Issue Severity"]]
                    if issue["Issue Priority"]:
                        priority = issue["Issue Priority"]
                    else:
                        priority = PRIORITY_MAPPING[severity]
                if issue['Jira Name']:
                    params = {"Name": issue['Jira Name']}
                tools.add(issue['Issue Tool'])
                error_msgs.add(issue['error_string'])
                info_msgs.add(self.get_info_msg(issue, info_msgs))

            ti = self.create_ti(name, tools, priority, severity, steps,
                                issue_confidence, recommendations, paths, refs,
                                error_msgs, info_msgs, description, instances, tags,
                                attachments, params, rp_defect_info)
            test_items_.append(ti)
            if issue:
                issue['Jira Description'] = self.get_jira_description(ti)
                self.json_items.append(issue)

        self.test_items = test_items_
        return test_items_

    @staticmethod
    def get_jira_description(ti):
        for msg in ti.msgs:
            if msg.status == 'INFO':
                return msg.message
        return ti.description

    @staticmethod
    def get_rp_defect_info(issues):
        defect_type = issues[0].get('RP Defect Type', 'To Investigate')
        defect_type_comment = issues[0].get('RP Comment', '')
        for issue in issues:
            current_defect_type = issue.get('RP Defect Type', 'To Investigate')
            if current_defect_type != defect_type:
                if defect_type is None:
                    defect_type = current_defect_type
                    defect_type_comment = issue.get('RP Comment', '')
                else:
                    if current_defect_type is not None:
                        if RP_DEFECT_TYPE_PRIORITY[current_defect_type] < RP_DEFECT_TYPE_PRIORITY[defect_type]:
                            defect_type = current_defect_type
                            defect_type_comment = issue.get('RP Comment', '')
        return {
            'RP Defect Type': defect_type,
            'RP Comment': defect_type_comment
        }

    def get_junit_items(self, new_items=''):
        """
        Convert from canonical data model to junit test suit
        :param new_items:
        :return:
        """
        test_cases = []
        if not self.test_items and not new_items:
            raise ValueError('There it no test items')
        data = self.test_items if not new_items else new_items

        for item in data:
            tc = TestCase(item.issue, classname=item.confidence)
            message = ''
            for msg in item.msgs:
                message = message + msg.message + "\n\n"
            tc.add_error_info(message=message, error_type=item.severity)
            test_cases.append(tc)
        ts = TestSuite(self.report_name, test_cases)
        return ts

    def get_json_items(self):
        """
        Returns items after conversion in canonical format as JSON report
        :return:
        """
        return self.json_items

    def get_raw_data(self):
        return dumps(self.report, indent=2)

    @staticmethod
    def create_ti(name, tools, priority, severity, steps, confidence, recommendations, paths, refs, error_msgs,
                  info_msgs, description, instances, tags=None, attachments=None, params=None,
                  rp_defect_info=None) -> TestItem:
        """Create test item with parameters"""
        issue_description = ""
        info_log = ""

        if len(instances) > 0:
            info_log += "h3.*Instances:*\n{}\n".format('\n'.join(sorted(instances)))

        if len(recommendations) > 0:
            issue_description += "%s: %s\n" % ('Recommendations', recommendations)
            info_log += "h3.*Recommendations:*\n{}\n".format(recommendations)

        if len(steps) > 0:
            info_log += "h3.*Steps to Reproduce:*\n{}\n".format('\n'.join(sorted(steps)))

        if len(paths) > 0:
            issue_description += "%s: %s\n" % ('Paths', '\n'.join(sorted(paths)))
        if len(refs) > 0:
            issue_description += "%s: %s\n" % ('References', '\n'.join(sorted(refs)))

        if any(info_msgs):
            info_log += "h3.*Overview:*\n"
            for _ in sorted(info_msgs):
                if _:
                    info_log += _ + '\n'

        test_item = TestItem(name, tool=tools.pop(), severity=severity, confidence=confidence,
                             description=issue_description, priority=priority, attachments=attachments,
                             defect_type_info=rp_defect_info)
        for _ in tools:
            test_item.add_tag("Tool", _)
        if tags and isinstance(tags, list):
            for item in tags:
                (k, v), = item.items()
                test_item.add_tag(k, v)
        for _ in error_msgs:
            test_item.add_message(TestMessage(_, "ERROR"))

        test_item.add_message(TestMessage(info_log, "INFO"))
        if params:
            for k, v in params.items():
                test_item.add_param(k, v)
        return test_item

    @staticmethod
    def get_info_msg(issue, exists_msgs):
        """
        Convert canonical date model to log message
        :param issue:
        :param exists_msgs:
        :return:
        """
        issue_name = issue['Issue Name']
        if '.' in issue['Issue Name']:
            issue_name = issue['Issue Name'].split('.')[0]
        info_message = '{panel:title=%s}' % issue_name
        for field in ['Description', 'References']:
            if issue.get(field, ''):
                info_message += "*%s*: \n%s\n\n" % (field, issue[field].strip())
        if issue.get('Paths', ''):
            paths = '\n'.join(sorted(issue['Paths'].strip().split('\n\n')))
            info_message += "*Paths*: \n%s\n\n" % paths
        info_message += '{panel}'
        for _ in exists_msgs:
            if info_message in _:
                return ''
        return info_message
