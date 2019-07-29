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
import re
import time
import sys
import os
import zipfile

import bs4
from git import Repo


def configure_logging(logger):
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


def is_not_excluded_type(file, exclude_types):
    """Return False if file type excluded, else True"""
    if exclude_types:
        for exclude_type in exclude_types:
            if file.lower().endswith(exclude_type.lower()):
                return False
    return True


def zinfo_from_file(fullname):
    st = os.stat(fullname)
    mtime = time.localtime(st.st_mtime)
    date_time = mtime[0:6]

    if date_time[0] > 1980:
        # TODO Add Jira ticket with list of files/ add to sast documentations
        return True
    return False


def is_not_excluded_path(path, exclude_paths):
    """Return False if path excluded, else True"""
    if exclude_paths:
        for exclude_path in exclude_paths:
            if exclude_path.lower().strip() in path.lower():
                return False
    return True


def generate_zip(zip_path, files_to_pack, project_path):
    """
    Generate zip from file list
    :param zip_path:
    :param files_to_pack:
    """
    zipf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
    for file_ in files_to_pack:
        zipf.write(file_, file_.replace(project_path, '', 1))
    zipf.close()


def zip_prj(prj_path, zip_path, exclude_pathes=None, exclude_types=None):
    """
    Generate zip file
    :param prj_path:
        folder to archive
    :param zip_path:
        path to zip archive
    :param exclude_pathes:
        paths to exclude from zip
    :param exclude_types:
        file types to exclude from zip
    """
    files_ = []
    for root, dirs, files in os.walk(prj_path):
        files = [f for f in files if not f[0] == '.']
        dirs[:] = [d for d in dirs if not d[0] == '.']

        if is_not_excluded_path(root, exclude_pathes):
            for file in files:
                if is_not_excluded_type(file, exclude_types):
                    f_path = os.path.join(root, file)
                    try:
                        if zinfo_from_file(f_path):
                            files_.append(f_path)
                    except Exception:
                        print('Unable to include in zip ', f_path)
                        pass
    generate_zip(zip_path, files_, prj_path)


def extract_zip(local_path):
    """
    Extract zip file
    :param local_path:
    :return:
    """
    with open(local_path, 'rb') as f:
        return f.read()


def write_file(f_path, data):
    """
    Write data to output file
    :param f_path:
        output file path
    :param data:
        data to write
    """
    with open(f_path, 'w') as f_out:
        f_out.write(data)


def diff(path_, excluded_, excluded_path_):
    """
    Get modified and new files from last commit
    :param path_:
    :param excluded_:
    :param excluded_path_:
    :return:
    """
    repo = Repo(path_)
    hcommit = repo.head.commit
    difs_ = hcommit.diff('HEAD~1')
    inc = list()
    for type_ in ("M", "D"):
        for _ in difs_.iter_change_type(type_):
            filename, file_extension = os.path.splitext(os.path.join(path_, _.a_path))
            if os.path.basename(filename)[0] != '.':
                if file_extension not in excluded_:
                    excluded = [True for _ in excluded_path_ if _ in filename.lower()]
                    if not excluded:
                        inc.append(_.a_path)
    return inc


def zip_latest_files(path_to_repo, zip_path, excluded_types, excluded_paths):
    """
    Create zip archive with last commit files
    :param excluded_paths:
    :param path_to_repo:
    :param zip_path:
    :param excluded_types:
    :return:
    """
    print('excluded:', excluded_types)
    inc_f = diff(path_to_repo, excluded_types, excluded_paths)
    print("Files changed in last commit: ", inc_f)
    files_changed = [os.path.join(path_to_repo, f_path) for f_path in inc_f]
    if inc_f:
        generate_zip(zip_path, files_changed, path_to_repo)


def get_jira_tag(html_tag):
    """
    Convert from HTML tags to JIRA markdown
    :param html_tag:
    :return:
    """
    html_to_jira_tags = {
        'ol': '#',
        'ul': '*',
        'li': ''
    }
    if html_tag not in html_to_jira_tags:
        return ''
    else:
        return html_to_jira_tags[html_tag]


def _get_recommendations(element, parent_tag=''):
    children = [child for child in element.children]
    parent_name = element.name
    tag = parent_tag + get_jira_tag(parent_name)
    text = ''
    for child in children:
        if isinstance(child, str):
            continue
        if child.name == 'li':
            # check if list element contains nested list elements and then parse them
            # otherwise retrieve the text of the element
            if child.find('li') or child.find('ol') or child.find('ul'):
                child_text = child.find(text=True, recursive=False)
                text += f"{tag} {child_text}\n"
                text += _get_recommendations(child, tag)
            else:
                child_text = child.text.strip()
                text += f"{tag} {child_text}\n"
        else:
            text += _get_recommendations(child, tag)
    return text


def get_jira_recommendations(cx_client, query_id):
    """
    Get recommendation from Checkmarx
    :param cx_client:
    :param query_id:
    :return:
    """
    query_description = cx_client.get_query_description_by_query_id(query_id)
    soup = bs4.BeautifulSoup(query_description, 'html.parser')
    pattern = re.compile('How to avoid it')
    recommendations = soup(text=pattern)[0]
    current_tag = recommendations.next
    response = ""
    while True:
        if current_tag is None:
            break
        if isinstance(current_tag, bs4.element.NavigableString):
            current_tag = current_tag.next
            continue
        text = current_tag.find(text=True, recursive=False)
        if text is None:
            current_tag = current_tag.next
            continue
        # `Source Code Examples` is the next section after `How to avoid it`
        # should stop processing here
        if 'Source Code Examples' not in text:
            if current_tag.name in ['ol', 'ul']:
                response += _get_recommendations(current_tag, '') + '\n'
                current_tag = current_tag.next_sibling
            else:
                text = text.strip()
                if text:
                    response += text + '\n'
                current_tag = current_tag.next
        else:
            break
    return response


def get_jira_overview(cx_client, cwe_id):
    """
    Get overview by CWE code
    :param cx_client:
    :param cwe_id:
    :return:
    """
    cwe_description = cx_client.get_cwe_description(cwe_id)
    soup = bs4.BeautifulSoup(cwe_description, 'html.parser')
    summary_pattern = 'Description Summary'
    summary = soup(text=summary_pattern)[0].next
    while True:
        try:
            summary_text = summary.text
        except AttributeError:
            summary_text = str(summary)
        if summary_text.strip():
            summary_text = summary_text.replace('\n', ' ')
            return ' '.join(summary_text.split())
        summary = summary.next
