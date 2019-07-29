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


class TestItem(object):
    """Test item for Report Portal"""

    def __init__(self, issue, severity, confidence, description, tool=None, priority='', attachments=None,
                 defect_type_info=None):
        """
        :param issue:
        :param severity:
        :param confidence:
        :param description:
        :param tool:
        :param priority:
        :param attachments:
        :param defect_type_info:
        """
        self.issue = issue
        self.tool = tool
        self.severity = severity
        self.priority = priority
        self.confidence = confidence
        self.description = description
        self.attachments = attachments
        self.msgs = []
        self.tags = {"Tool": tool, "Severity": severity,
                     "Confidence": confidence, "Priority": priority}
        self.params = {
            "Tool": tool
        }
        self.defect_type_info = defect_type_info

    def add_message(self, msg):
        """
        Add new message to test item
        :param msg:
        """
        if self.msgs.count(msg) == 0:
            self.msgs.append(msg)

    def add_tag(self, key, value):
        """
        Add tag to test item
        :param key:
        :param value:
        """
        self.tags[key] = value

    def add_param(self, param, value):
        """
        Add parameter to test item
        :param param:
        :param value:
        """
        self.params[param] = value

    def get_tags(self) -> list:
        """
        Get list of tags from test item
        """
        tags = []
        for tag in self.tags:
            tags.append(f"{tag}: {self.tags[tag]}")
        return tags

    def get_params(self) -> dict:
        """
        Get list of parameters from test item
        """
        params = {
            "Severity": self.severity,
            "Confidence": self.confidence
        }
        for k, v in self.params.items():
            params[k] = v
        return params

    def __eq__(self, other):
        """Overrides the default implementation"""
        if isinstance(self, other.__class__):
            is_same_name = (self.issue.count(other.issue) > 0 or other.issue.count(self.issue) > 0)
            is_same_link = (self.params == other.params
                            or (self.params.get("Links") and other.params.get("Links")
                                and (self.params.get("Links").count(other.params.get("Links")) > 0
                                     or other.params.get("Links").count(self.params.get("Links")) > 0)))
            return ((self.issue == other.issue and self.confidence == other.confidence)
                    or (is_same_name and is_same_link))
        return False
