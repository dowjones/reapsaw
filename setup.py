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

from setuptools import setup, find_packages

setup(
    name='DowJones Reapsaw',
    version='1.0.0',
    description='Core component',
    long_description='',
    license='Apache License 2.0',
    packages=find_packages(),
    install_requires=['bandit==1.5.1', 'junit-xml==1.8', 'requests==2.21.0', 'zeep==2.5.0', 'PyYAML==3.12',
                      'bs4==0.0.1', 'slackclient==1.2.1', 'jira==1.0.15',
                      'configparser==3.5.0', 'PyJWT==1.6.4', 'cryptography==2.2.2',
                      'xmltodict==0.11.0', 'junit2html==21', 'node-semver==0.6.1', 'texttable==1.6.2'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'bugbar_to_json = sast_controller.bug_bar.bugbar_to_json:main',
            'create_jira_tickets = sast_controller.bin.create_jira_tickets:main',
            'generate_reports = sast_controller.bin.generate_reports:main',
            'notifications = sast_controller.bin.notifications:main',
            'scan = sast_controller.bin.scan:main',
            'push_to_jira = sast_controller.bin.json_to_jira:main',
        ]
    },
)
