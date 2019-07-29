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

from math import fabs
from slackclient import SlackClient
from os import environ
from argparse import ArgumentParser
from sast_controller.drivers.rp.rp_portal_controller import ReportPortalService

logger = logging.getLogger(__name__)

launch_description_template = """*{project} "{name}" #{number} has been finished*
*Total Issues: {failed}* <{link}/ui/#{project}/launches/all%7Cpage.page=1&page.size=50&page.sort=start_time,number\
%2CDESC/{launch_id}?page.page=1&page.size=50&page.sort=start_time%2CASC|link>
>Product Bugs: {product_bug}
>Validate With Dev Team: {automation_bug}
>System Issues: {system_issue}
>To Investigate: {to_investigate}
>No Defects: {no_defect}"""


def parse_args():
    parser = ArgumentParser()
    parser.add_argument('-r', '--reportportal', type=str,
                        default=environ.get("REPORT_PORTAL_URL", ""),
                        help="Report Portal URL")
    parser.add_argument('-t', '--token', type=str,
                        default=environ.get("RP_TOKEN", ""),
                        help="Report Portal authorisation token")
    parser.add_argument('-sc', '--slack_channel', type=str,
                        default=environ.get("SLACK_CHANNEL", ""),
                        help="Slack channel")
    parser.add_argument('-st', '--slack_token', type=str,
                        default=environ.get("SLACK_TOKEN", ""),
                        help="Slack token")
    parser.add_argument('-rs', '--reportportal_scan', type=str,
                        default=environ.get("RP_LAUNCH_NAME", ""),
                        help="Report portal scan name")
    parser.add_argument('-rp', '--reportportal_project', type=str,
                        default=environ.get("RP_PROJECT", ""),
                        help="Report portal project name")
    return parser.parse_args()


def send_slack_message(sc, message, channel, thread_ts=None):
    """
    Send message to Slack channel
    :param sc:
    :param message:
    :param channel:
    :param thread_ts:
    :return:
    """
    return sc.api_call("chat.postMessage", channel=channel,
                       text=message, thread_ts=thread_ts)


def get_difference(current, previous):
    """
    Get difference between two Report Portal launches
    :param current:
    :param previous:
    :return:
    """
    if current - previous == 0:
        return "No difference"
    dif = int(fabs(current - previous))
    percent = dif / max(current, previous) * 100
    if current - previous > 0:
        return f"rate increased {round(percent, 2)}% (+{dif} item(s))"
    else:
        return f"rate decreased {round(percent, 2)}% (-{dif} item(s))"


def get_launch_info_msg(rp_link, project, launch_id, launch_info):
    """
    Format launch info message using template
    :param rp_link:
    :param project:
    :param launch_id:
    :param launch_info:
    :return:
    """
    content = launch_info['content'][0]
    number = content["number"]
    name = content["name"]
    status = content["status"]
    statistics = content["statistics"]
    message_ = launch_description_template.format(link=rp_link, project=project,
                                                  name=name,
                                                  number=number,
                                                  launch_id=launch_id,
                                                  status=status,
                                                  failed=statistics["executions"]["failed"],
                                                  product_bug=statistics["defects"]["product_bug"]["total"],
                                                  automation_bug=statistics["defects"]["automation_bug"]["total"],
                                                  system_issue=statistics["defects"]["system_issue"]["total"],
                                                  to_investigate=statistics["defects"]["to_investigate"]["total"],
                                                  no_defect=statistics["defects"]["no_defect"]["total"])
    return message_


def get_compare_launches_msg(current_launch, previous_launch):
    """
    Format compare launches message using template
    :param current_launch:
    :param previous_launch:
    :return:
    """
    defects = current_launch["statistics"]["defects"]
    previous_defects = previous_launch["statistics"]["defects"]
    message_ = ""
    for defect in defects:
        current = defects[defect]["total"]
        previous = previous_defects[defect]["total"]
        if (current - previous) != 0:
            message_ = f"{message_}\n" \
                       f">{defect.capitalize().replace('_', ' ')} " \
                       f"{get_difference(current, previous)}"
    if len(message_) == 0:
        message_ = "No difference."
    return "*Comparison with previous run:* " + message_


def main():
    """Entrypoint for execution script"""
    args = parse_args()
    token = args.token
    rp = ReportPortalService(args.reportportal, token)
    try:
        launch_id, response = rp.get_launch_info_by_number(args.reportportal_project, args.reportportal_scan, 1)
        message = get_launch_info_msg(args.reportportal, args.reportportal_project, launch_id, response)

        if 'page' in response and response['page']['totalPages'] > 1:
            second_launch_id, second_launch_response = rp.get_launch_info_by_number(args.reportportal_project,
                                                                                    args.reportportal_scan, 2)
            message += "\n" + get_compare_launches_msg(response["content"][0], second_launch_response["content"][0])

        sc = SlackClient(args.slack_token)

        if sc.rtm_connect():
            send_slack_message(sc, channel=args.slack_channel, message=message)
            logger.info("Notification was sent.")
        else:
            logger.critical("Unable to connect to Slack.")
    except Exception as ex:
        print("Error occurred: [{}] {}".format(type(ex), ex))
    finally:
        rp.close_session()


if __name__ == '__main__':
    main()
