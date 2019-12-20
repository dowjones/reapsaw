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

import os


def str_to_bool(string):
    if string == 'true':
        return True
    return False


class Config(object):
    """Class with default configuration parameters"""
    EXCLUDED_TYPES = ["png", "zip", "css", "txt", "svg", "mp3", "wav", "less", "gif"]
    EXCLUDED_PATH = ["node_modules", "config", "coverage", "dist_", "test", "report", "i18n"]
    CODE_PATH = os.environ.get('CODE_PATH') or '/code'

    CX_PROJECT_NAME = os.environ.get('CX_PROJECT', os.environ.get('PROJECT', None))

    CX_INCREMENTAL = os.environ.get('cx_incremental', 'true')
    CX_FILES = os.environ.get('cx_files', None)
    CX_PATH = os.environ.get("cx_path", None)

    ENABLE_SNYK_MONITOR = str_to_bool(os.environ.get('ENABLE_SNYK_MONITOR', 'false'))

    TMP_FOLDER = '/tmp'
    ZIP_NAME = 'cx.zip'

    # OUTPUT
    CX_OUTPUT_PATH = os.environ.get('CX_OUTPUT_PATH') or '/code/reports/checkmarx-report.xml'
    SNYK_OUTPUT_PATH = os.environ.get('SNYK_OUTPUT_PATH') or '/code/reports/snyk.json'
    BUGBAR_ITEMS_OUTPUTPATH = os.environ.get('BUGBAR_ITEMS_OUTPUTPATH') or '/code/reports/bugbar_output.json'
    JSON_OUTPUT_PATH = os.environ.get('JSON_OUTPUT_PATH') or '/code/reports/json_report.json'
