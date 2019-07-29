#  Copyright (c) 2018 Dow Jones & Company, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the 'License');
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

SEVERITY_MAPPING = {
    'Critical': 4,
    'High': 3,
    'Medium': 2,
    'Moderate': 2,
    'Low': 1,
    'Information': 0,
    'Info': 0
}

SEVERITY_MAPPING_TYPE = {
    'Critical': 'Product Bug',
    'High': 'Product Bug',
    'Medium': 'No Defect',
    'Moderate': 'No Defect',
    'Low': 'No Defect',
    'Information': 'No Defect',
    'Info': 'No Defect'
}

PRIORITY_MAPPING = {
    'Critical': 'Blocker',
    'High': 'Critical',
    'Medium': 'Major',
    'Moderate': 'Major',
    'Low': 'Minor',
    'Information': 'Trivial',
}

STATUS_MAPPING = {
    'Blocker': 'Critical',
    'Critical': 'Critical',
    'Major': 'High',
    'Minor': 'Medium',
    'Info': 'Information',
}

SONAR_RULES_LINK = 'https://rules.sonarsource.com/javascript/type/Vulnerability/RSPEC-{}'
SONAR_PROJECT_LINK = '{}:{}/project/issues?id={}&types=VULNERABILITY'

RP_DEFECT_TYPE_PRIORITY = {
    'Product Bug': 0,
    'System Issue': 1,
    'To Investigate': 2,
    'No Defect': 3
}
