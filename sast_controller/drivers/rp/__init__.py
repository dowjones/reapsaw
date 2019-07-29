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

URLS = {
    "login_url": "/uat/sso/oauth/token?grant_type=password&password={password}&username={login}",
    "get_launch_list_url": "/api/v1/{project}/launch?filter.eq.name={scan}&page.sort=number%2Cdesc&page.page={page}&page.size={size}",  # noqa
    "compare_url": "/api/v1/{project}/launch/compare?ids={current_launch}&ids={previous_launch}",
    "launch_url": "/ui/#{project}/launches/all%7Cpage.page=1&page.size=50&page.sort=start_time,number%2CDESC/{launch_id}?page.page=1&page.size=50&page.sort=start_time%2CASC",  # noqa
    "update_launch_url": "/api/v1/{project}/launch/{launch_id}",
    "update_test_item_url": "/api/v1/{project}/activity/item/{test_item_id}",
    "get_project_info_url": "/api/v1/project/{project}",
    "get_launch_info_url": "/api/v1/{project}/item?filter.eq.launch={launch_id}&page.page={page}",
    "post_ticket_url": "/api/v1/{project}/external-system/{system_id}/ticket",
    "put_item_url": "/api/v1/{project}/item",
    "load_issue": "/api/v1/{project}/item/issue/add",
    "get_log": "/api/v1/{project}/log?filter.eq.item={test_item}&page.page={page}&page.size=100&page.sort=time%2CASC"
}
