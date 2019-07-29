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

import logging
import json

import os

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

BUGBAR_FILE = os.environ.get('BUGBAR_FILE', '/tmp/bugbar/bugbar.json')


def read_json(file_path=BUGBAR_FILE, default=None):
    """
    Read json file. Error while reading return default value
    :param file_path:
    :param default:
    :return:
    """
    try:
        with open(file_path) as fd:
            try:
                return json.load(fd)
            except JSONDecodeError as exception:
                logging.warning(exception)
    except (OSError, IOError) as exception:
        logging.error(exception)
    return default
