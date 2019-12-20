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
import json
import fnmatch
import os
import traceback
from multiprocessing import Pool
from os import environ, path
import subprocess
from time import time
import logging

from requests.exceptions import ConnectionError

from sast_controller.drivers.cx.utils import zip_prj, write_file, zip_latest_files

from sast_controller.drivers.cx import CxManager
from sast_controller.drivers.cx.CxManager import CxIncrementalScanException
from sast_controller.bin.config import Config
from sast_controller.bin.generate_reports import check_connectivity


def cx_scan(local_, prj_, inc_, f_path):
    try:
        report = CxManager.scan_project(local_path=local_, project=prj_, incremental_scan=inc_)
    except CxIncrementalScanException:
        report = CxManager.scan_project(local_path=local_, project=prj_, incremental_scan=False)
    except Exception as e:
        logging.error(str(e))
        return
    if report and report.ScanResults:
        data = str(report.ScanResults).replace("b'\\xef\\xbb\\xbf", "", 1)
        data = data.replace("\\r\\n", "\n")
        data = data.replace(">'", ">")
        write_file(f_path, data)


def cx_exclude_rules():
    user_files_excl = Config.CX_FILES
    if user_files_excl:
        user_files_excl = user_files_excl.split(",")
    else:
        user_files_excl = []
    user_path_excl = Config.CX_PATH
    if user_path_excl:
        user_path_excl = user_path_excl.split(",")
    else:
        user_path_excl = []
    paths = Config.EXCLUDED_PATH + user_path_excl
    logging.info("Checkmarx excluded paths: %s" % ", ".join(paths))
    types = Config.EXCLUDED_TYPES + user_files_excl
    logging.info("Checkmarx excluded extensions: %s" % ", ".join(types))
    return paths, types


def run_checkmarx_test(project, path_, excluded_paths, excluded_types, incremental_scan, xml_path):
    local_path = path.join(path_, Config.ZIP_NAME)
    try:
        zip_prj(path_, local_path, excluded_paths, excluded_types)
    except FileNotFoundError:
        logging.error('No such directory:', path_)
        return
    except Exception as e:
        logging.error(str(e))
        return
    cx_scan(local_path, project, incremental_scan, xml_path)


def cx_connectivity():
    if not (environ.get('OWNER') or environ.get('CX_USER')) or not (
            environ.get('PASSWORD') or environ.get('CX_PASSWORD')) or not environ.get('CX_URL'):
        logging.critical(
            f'Please specify Checkmarx data: CX_USER, CX_PASSWORD and CX_URL environment variables.')
    else:
        try:
            check_connectivity(environ['CX_URL'], 'Unable to connect to Checkmarx')
            return True
        except ConnectionError as ex:
            logging.error(str(ex))
    return False


def snyk_monitor(file_path=None):
    if file_path:
        cmd = f'snyk monitor --file={file_path}'
    else:
        cmd = 'snyk monitor'
    subprocess.Popen(cmd.split(' '), encoding='utf-8', stdout=subprocess.PIPE).stdout.read()


def snyk_scan_dotnet():
    sln_file = environ.get('sln_file', '')
    if sln_file:
        cmd = f'snyk test --file={sln_file} --json'.split(" ")
        if Config.ENABLE_SNYK_MONITOR:
            snyk_monitor(sln_file)
        raw_result = subprocess.Popen(cmd, encoding='utf-8', stdout=subprocess.PIPE).stdout.read()
        return raw_result

    scanned_projects = dict()
    for root, dirs, files in os.walk('.'):
        for file_name in files:
            if fnmatch.fnmatch(file_name, '*.sln'):
                file_path = path.join(root, file_name)
                cmd = f'snyk test --file={file_path} --json'.split(' ')
                if Config.ENABLE_SNYK_MONITOR:
                    snyk_monitor(file_path)
                raw_result = subprocess.Popen(cmd, encoding='utf-8', stdout=subprocess.PIPE).stdout.read()
                try:
                    json_result = json.loads(raw_result)
                    if not isinstance(json_result, list):
                        json_result = [json_result]
                    if 'error' in json_result:
                        logging.critical(json_result)
                    else:
                        for report in json_result:
                            scanned_projects[report['path']] = report
                except Exception:
                    logging.error(raw_result)
    snyk_report = []
    for report in scanned_projects.values():
        snyk_report.append(report)
    return json.dumps(snyk_report)


def snyk_scan():
    lang_ = environ.get("lang", "")

    if not environ.get('SNYK_TOKEN'):
        logging.error(f'Please specify SNYK_TOKEN environment variable.')
        return
    if lang_ == 'dotnet':
        output = snyk_scan_dotnet()
    elif lang_ == 'python':
        subprocess.Popen(['/tmp/snyk_py_scan.sh', Config.SNYK_OUTPUT_PATH], encoding="utf-8",
                         stdout=subprocess.PIPE).communicate()
        return
    else:
        if Config.ENABLE_SNYK_MONITOR:
            snyk_monitor()
        cmd = 'snyk test --json'.split(" ")
        test = subprocess.Popen(cmd, encoding="utf-8", stdout=subprocess.PIPE)
        output = test.stdout.read()
    json_output = json.loads(output)
    if "error" in json_output:
        if 'Invalid auth token provided' in output:
            logging.error(f"Invalid auth token provided. Please double check SNYK_TOKEN")
            raise AssertionError('Invalid Snyk auth token provided')
        logging.error(f"{output}")
        if path.isfile('package-lock.json'):
            subprocess.Popen(['/usr/bin/npm', "i", "--package-lock-only"], encoding="utf-8",
                             stdout=subprocess.PIPE).communicate()
            logging.info("Try to run using package-lock.json")
            cmd = 'snyk test --file=package-lock.json --json'.split(" ")
            test = subprocess.Popen(cmd, encoding="utf-8", stdout=subprocess.PIPE)
            output = test.stdout.read()
        else:
            logging.error(f'Unable to run Snyk')
            return

    write_file(Config.SNYK_OUTPUT_PATH, output)


def copy_folder(source, dest):
    """
    Copy folder content

    :param source:
    :param dest: destination
    :return:
    """
    subprocess.Popen(["rsync", "-av", source, dest, "--exclude", "node_modules",
                      "--exclude", "test", "--exclude", "dist_integration", "--exclude", "dist_production",
                      "--exclude", "dist_staging"], encoding="utf-8", stdout=subprocess.PIPE).communicate()


def f(cmd):
    """
    :param cmd: command to execute
    :return:
    """
    output = ''
    ts_ = time()
    source_path = path.join(Config.TMP_FOLDER, path.basename(Config.CODE_PATH))

    if cmd == 'cx_commit':
        if cx_connectivity():
            logging.info("Starting Checkmarx commit-base scan..")
            copy_folder(Config.CODE_PATH, Config.TMP_FOLDER)

            cx_exclude_paths, cx_exclude_types = cx_exclude_rules()
            zip_path = path.join(Config.TMP_FOLDER, Config.ZIP_NAME)
            zip_latest_files(source_path, zip_path, cx_exclude_types, cx_exclude_paths)
            if path.os.path.exists(zip_path):
                logging.info('Start Scanning ..')
                cx_scan(zip_path, Config.CX_PROJECT_NAME, Config.CX_INCREMENTAL, Config.CX_OUTPUT_PATH)
            else:
                logging.info("Based on excluded rules there are no files to scan")

    elif cmd == 'cx':
        if cx_connectivity():
            cx_exclude_paths, cx_exclude_types = cx_exclude_rules()
            project_name = Config.CX_PROJECT_NAME
            cx_incremental_scan = Config.CX_INCREMENTAL
            if project_name:
                run_checkmarx_test(project_name, Config.CODE_PATH, cx_exclude_paths, cx_exclude_types,
                                   cx_incremental_scan, Config.CX_OUTPUT_PATH)
    elif cmd == 'snyk':
        try:
            snyk_scan()
        except Exception:
            traceback.print_exc()
    print(cmd, ' fin ', time() - ts_)
    return output


def main():
    """Entrypoint for execution script"""
    p = Pool(5)
    tasks = environ.get("TASKS", "cx,snyk").replace(' ', '').split(",")
    logging.info(f'Your tasks: {tasks}')
    r = p.map_async(f, tasks)
    r.wait()


if __name__ == '__main__':
    main()
