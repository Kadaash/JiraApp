import requests
import base64
import os
import mimetypes

class JiraAPI:
    def __init__(self, jira_url: str, username: str, api_token: str):
        self.jira_url = jira_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.auth_header = self._get_auth_header()

    def _get_auth_header(self) -> dict:
        """Prepares the Basic Authentication header."""
        credentials = f"{self.username}:{self.api_token}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        return {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def verify_credentials(self) -> bool:
        """Verifies credentials by making a request to the /myself endpoint."""
        api_url = f"{self.jira_url}/rest/api/3/myself"
        try:
            response = requests.get(api_url, headers=self.auth_header, timeout=10)
            if response.status_code == 200:
                print("Credentials verified successfully.")
                return True
            else:
                print(f"Failed to verify credentials. Status code: {response.status_code}, Response: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"Error verifying credentials: {e}")
            return False

    def search_issues(self, jql_query: str, fields: list = None, max_results: int = 50) -> list:
        """Searches for issues using JQL."""
        api_url = f"{self.jira_url}/rest/api/3/search"
        params = {
            'jql': jql_query,
            'maxResults': max_results
        }
        if fields:
            params['fields'] = ",".join(fields)

        try:
            response = requests.get(api_url, headers=self.auth_header, params=params, timeout=10)
            if response.status_code == 200:
                return response.json().get('issues', [])
            else:
                print(f"Failed to search issues. Status code: {response.status_code}, Response: {response.text}")
                return []
        except requests.exceptions.RequestException as e:
            print(f"Error searching issues: {e}")
            return []

    def create_issue(self, project_key: str, summary: str, description: str, issue_type_name: str, custom_fields: dict = None) -> dict | None:
        """Creates a new issue."""
        api_url = f"{self.jira_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {
                    "key": project_key
                },
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": issue_type_name
                }
            }
        }

        if custom_fields:
            payload["fields"].update(custom_fields)

        try:
            response = requests.post(api_url, headers=self.auth_header, json=payload, timeout=10)
            if response.status_code == 201: # 201 Created
                print(f"Issue created successfully: {response.json().get('key')}")
                return response.json()
            else:
                print(f"Failed to create issue. Status code: {response.status_code}, Response: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Error creating issue: {e}")
            return None

    def add_attachment(self, issue_key: str, file_path: str):
        """Placeholder for adding an attachment to an issue."""
        """Adds an attachment to an issue."""
        api_url = f"{self.jira_url}/rest/api/3/issue/{issue_id_or_key}/attachments"

        headers = self.auth_header.copy()
        headers["X-Atlassian-Token"] = "no-check" # Required for file attachments

        try:
            file_name = os.path.basename(file_path)
            content_type, _ = mimetypes.guess_type(file_path)
            if content_type is None:
                content_type = 'application/octet-stream'

            with open(file_path, 'rb') as file_obj:
                files = {'file': (file_name, file_obj, content_type)}
                response = requests.post(api_url, headers=headers, files=files, timeout=30) # Increased timeout for uploads

            if response.status_code == 200:
                print(f"Attachment '{file_name}' added successfully to issue '{issue_id_or_key}'.")
                return response.json()
            else:
                print(f"Failed to add attachment. Status code: {response.status_code}, Response: {response.text}")
                return None
        except FileNotFoundError:
            print(f"Error adding attachment: File not found at '{file_path}'.")
            return None
        except requests.exceptions.RequestException as e:
            print(f"Error adding attachment: {e}")
            return None

    def get_create_meta(self, project_keys: list, issue_type_names: list = None, expand: str = None) -> dict | None:
        """
        Gets metadata for creating issues, such as available projects, issue types, and fields.
        project_keys: A list of project keys (e.g., ['PROJ1', 'PROJ2']).
        issue_type_names: Optional list of issue type names to filter by (e.g., ['Bug', 'Task']).
        expand: Optional string for expanding sections (e.g., 'projects.issuetypes.fields').
        """
        api_url = f"{self.jira_url}/rest/api/3/issue/createmeta"
        params = {
            'projectKeys': ",".join(project_keys) # Must be comma-separated string
        }
        if issue_type_names:
            params['issuetypeNames'] = ",".join(issue_type_names) # Must be comma-separated
        if expand:
            params['expand'] = expand

        try:
            response = requests.get(api_url, headers=self.auth_header, params=params, timeout=15)
            if response.status_code == 200:
                # The response contains a 'projects' list.
                return response.json()
            else:
                print(f"Failed to get create metadata. Status code: {response.status_code}, Response: {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Error getting create metadata: {e}")
            return None

if __name__ == '__main__':
    # Example Usage (for testing purposes, replace with actual values)
    # NOTE: This part will be removed or commented out in the final application
    # JIRA_URL = "https://your-domain.atlassian.net"
    # USERNAME = "your-email@example.com"
    # API_TOKEN = "your_api_token"

    # print(f"Attempting to connect to {JIRA_URL}")
    # jira_client = JiraAPI(JIRA_URL, USERNAME, API_TOKEN)

    # if jira_client.verify_credentials():
    #     print("Successfully connected to JIRA.")
    # else:
    #     print("Failed to connect to JIRA.")
    pass
