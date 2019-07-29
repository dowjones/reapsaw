import logging

from os import environ
from jira import JIRA, JIRAError


class JiraBaseClient(object):
    def __init__(self):
        self.client = self.connect()

    def connect(self):
        """Connect to Jira. Return None on error """
        try:
            jira = JIRA(environ['JIRA_HOST'], basic_auth=(environ['JIRA_USR'], environ['JIRA_PWD']),
                        options={'verify': False})
            return jira
        except Exception as e:
            logging.error("Failed to connect to JIRA: %s" % e)
            return None

    def create_issue(self, issue_data):
        """Create new Jira ticket"""
        issue = self.client.create_issue(fields=issue_data)
        logging.info('  \u2713 %s issue was created: %s',
                     issue_data['issuetype']['name'], issue.key)
        return issue

    def check_project(self, project):
        """Check if project exists in Jira"""
        logging.info('checking if project "%s" exists in jira', project)
        try:
            self.client.search_issues('project = {}'.format(project))
            logging.info('project "%s" exists', project)
            return True
        except JIRAError as exc:
            logging.error('project "%s" not found in jira', project)
            logging.info(
                'please specify correct project name or create project "%s" in jira',
                project)
            logging.debug('status code: %s; text: %s', exc.status_code, exc.text)
