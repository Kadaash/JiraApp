import requests
import base64
import os
import mimetypes
import logging
import json # For logging payloads
import re

# Configure basic logging - INFO level for general app flow, DEBUG for detailed API stuff
# Change level to logging.DEBUG in basicConfig to see all detailed logs by default.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # Logger for this specific module

class JiraAPI:
    def __init__(self, jira_url: str, username: str, api_token: str, ssl_verify: bool = True):
        # Mask API token in log message for __init__
        # Simple mask: show first/last few chars of token if needed, or just indicate its presence.
        # For this, we'll just log that a token was received, not its value.
        logger.debug(f"JiraAPI initializing with URL: {jira_url}, Username: {username}, SSL Verify: {ssl_verify}, API Token: [PRESENT]")
        self.jira_url = jira_url.rstrip('/')
        self.username = username
        self.api_token = api_token # Stored in memory, be careful with logging this directly elsewhere
        self.ssl_verify = ssl_verify
        self.auth_header = self._get_auth_header()
        logger.info(f"JiraAPI instance created for {self.jira_url}")

    def _mask_auth_header(self, headers: dict) -> dict:
        """Masks the Authorization token in a copy of the headers for logging."""
        log_headers = headers.copy()
        if "Authorization" in log_headers and log_headers["Authorization"].lower().startswith("basic "):
            parts = log_headers["Authorization"].split(" ", 1)
            if len(parts) > 1 and len(parts[1]) > 8: # Basic <token>
                # Masking: show first 4 and last 4 characters of the base64 encoded string
                masked_token = parts[1][:4] + "****" + parts[1][-4:]
                log_headers["Authorization"] = f"{parts[0]} {masked_token}"
        return log_headers

    def _get_auth_header(self) -> dict:
        """Prepares the Basic Authentication header."""
        credentials = f"{self.username}:{self.api_token}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        # Not logging credentials here as they are sensitive. Masked header will be logged per request.
        return {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def verify_credentials(self) -> bool:
        method_name = "verify_credentials"
        logger.debug(f"Method {method_name} called.")
        api_url = f"{self.jira_url}/rest/api/3/myself"

        logger.info(f"Requesting URL ({method_name}): {api_url}")
        logger.debug(f"Request Headers ({method_name}): {self._mask_auth_header(self.auth_header)}")

        try:
            response = requests.get(api_url, headers=self.auth_header, timeout=10, verify=self.ssl_verify)
            logger.info(f"Response Status Code ({method_name}): {response.status_code}")
            logger.debug(f"Response Headers ({method_name}): {response.headers}")
            logger.debug(f"Response Content ({method_name}, first 500 chars): {response.text[:500]}")

            if response.status_code == 200:
                logger.info(f"Credentials verified successfully for {self.username}.")
                logger.debug(f"Method {method_name} returning True.")
                return True
            else:
                logger.error(f"Failed to verify credentials ({method_name}). Status: {response.status_code}, Response: {response.text}")
                logger.debug(f"Method {method_name} returning False.")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"RequestException in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning False due to RequestException.")
            return False
        except Exception as e: # Catch any other unexpected error
            logger.error(f"Generic exception in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning False due to generic exception.")
            return False


    def search_issues(self, jql_query: str, fields: list = None, max_results: int = 50) -> list:
        method_name = "search_issues"
        logger.debug(f"Method {method_name} called with JQL: '{jql_query}', Fields: {fields}, MaxResults: {max_results}")
        api_url = f"{self.jira_url}/rest/api/3/search"
        params = {
            'jql': jql_query,
            'maxResults': max_results
        }
        if fields:
            params['fields'] = ",".join(fields)

        logger.info(f"Requesting URL ({method_name}): {api_url} with params: {params}")
        logger.debug(f"Request Headers ({method_name}): {self._mask_auth_header(self.auth_header)}")

        try:
            response = requests.get(api_url, headers=self.auth_header, params=params, timeout=10, verify=self.ssl_verify)
            logger.info(f"Response Status Code ({method_name}): {response.status_code}")
            logger.debug(f"Response Headers ({method_name}): {response.headers}")
            logger.debug(f"Response Content ({method_name}, first 500 chars): {response.text[:500]}")

            if response.status_code == 200:
                issues = response.json().get('issues', [])
                logger.info(f"Search successful. Found {len(issues)} issues.")
                logger.debug(f"Method {method_name} returning list of {len(issues)} issues.")
                return issues
            else:
                logger.error(f"Failed to search issues ({method_name}). Status: {response.status_code}, Response: {response.text}")
                logger.debug(f"Method {method_name} returning empty list due to error.")
                return []
        except requests.exceptions.RequestException as e:
            logger.error(f"RequestException in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to RequestException.")
            return None # Explicitly return None for RequestException
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError in {method_name} processing response: {e}. Response text: {response.text[:500] if 'response' in locals() else 'Response object not available'}")
            logger.debug(f"Method {method_name} returning empty list due to JSONDecodeError.")
            return []
        except Exception as e:
            logger.error(f"Generic exception in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning empty list due to generic exception.")
            return []


    def create_issue(self, project_key: str, summary: str, description: str, issue_type_name: str, custom_fields: dict = None) -> dict | None:
        method_name = "create_issue"
        # Limit description length in log
        log_description = description[:100] + "..." if len(description) > 100 else description
        logger.debug(f"Method {method_name} called with ProjectKey: {project_key}, Summary: '{summary}', Description (snippet): '{log_description}', IssueType: {issue_type_name}, CustomFields: {custom_fields}")
        api_url = f"{self.jira_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{"type": "paragraph", "content": [{"type": "text", "text": description}]}]
                },
                "issuetype": {"name": issue_type_name}
            }
        }
        if custom_fields:
            payload["fields"].update(custom_fields)

        logger.info(f"Requesting URL ({method_name}): {api_url}")
        logger.debug(f"Request Headers ({method_name}): {self._mask_auth_header(self.auth_header)}")
        logger.debug(f"Request Payload ({method_name}): {json.dumps(payload)}")

        try:
            response = requests.post(api_url, headers=self.auth_header, json=payload, timeout=10, verify=self.ssl_verify)
            logger.info(f"Response Status Code ({method_name}): {response.status_code}")
            logger.debug(f"Response Headers ({method_name}): {response.headers}")
            logger.debug(f"Response Content ({method_name}, first 500 chars): {response.text[:500]}")

            if response.status_code == 201:
                created_issue = response.json()
                logger.info(f"Issue {created_issue.get('key')} created successfully.")
                logger.debug(f"Method {method_name} returning created issue data.")
                return created_issue
            else:
                logger.error(f"Failed to create issue ({method_name}). Status: {response.status_code}, Response: {response.text}")
                logger.debug(f"Method {method_name} returning None due to error.")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"RequestException in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to RequestException.")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError in {method_name} processing response: {e}. Response text: {response.text[:500] if 'response' in locals() else 'Response object not available'}")
            logger.debug(f"Method {method_name} returning None due to JSONDecodeError.")
            return None
        except Exception as e:
            logger.error(f"Generic exception in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to generic exception.")
            return None


    def add_attachment(self, issue_id_or_key: str, file_path: str) -> dict | None: # Corrected type hint for issue_id_or_key
        method_name = "add_attachment"
        logger.debug(f"Method {method_name} called for Issue: {issue_id_or_key}, FilePath: {file_path}")
        api_url = f"{self.jira_url}/rest/api/3/issue/{issue_id_or_key}/attachments"

        headers = self.auth_header.copy() # Start with base auth header
        headers.pop("Content-Type", None) # Let requests set Content-Type for multipart/form-data
        headers["X-Atlassian-Token"] = "no-check"

        logger.info(f"Requesting URL ({method_name}): {api_url}")
        # Log headers without Content-Type as it's handled by requests for files
        log_headers_for_attach = headers.copy()
        logger.debug(f"Request Headers ({method_name}): {self._mask_auth_header(log_headers_for_attach)}")


        try:
            file_name = os.path.basename(file_path)
            content_type, _ = mimetypes.guess_type(file_path)
            if content_type is None:
                content_type = 'application/octet-stream'
            logger.debug(f"Attaching file: {file_name} (Type: {content_type}) to {issue_id_or_key}")

            with open(file_path, 'rb') as file_obj:
                files = {'file': (file_name, file_obj, content_type)}
                response = requests.post(api_url, headers=headers, files=files, timeout=30, verify=self.ssl_verify)

            logger.info(f"Response Status Code ({method_name}): {response.status_code}")
            logger.debug(f"Response Headers ({method_name}): {response.headers}")
            logger.debug(f"Response Content ({method_name}, first 500 chars): {response.text[:500]}")

            if response.status_code == 200:
                attachment_data = response.json()
                logger.info(f"Attachment '{file_name}' added successfully to issue '{issue_id_or_key}'.")
                logger.debug(f"Method {method_name} returning attachment data (count: {len(attachment_data)}).")
                return attachment_data
            else:
                logger.error(f"Failed to add attachment ({method_name}). Status: {response.status_code}, Response: {response.text}")
                logger.debug(f"Method {method_name} returning None due to error.")
                return None
        except FileNotFoundError:
            logger.error(f"Error adding attachment ({method_name}): File not found at '{file_path}'.")
            logger.debug(f"Method {method_name} returning None due to FileNotFoundError.")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"RequestException in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to RequestException.")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError in {method_name} processing response: {e}. Response text: {response.text[:500] if 'response' in locals() else 'Response object not available'}")
            logger.debug(f"Method {method_name} returning None due to JSONDecodeError.")
            return None
        except Exception as e:
            logger.error(f"Generic exception in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to generic exception.")
            return None


    def get_create_meta(self, project_keys: list, issue_type_names: list = None, expand: str = None) -> dict | None:
        method_name = "get_create_meta"
        logger.debug(f"Method {method_name} called with ProjectKeys: {project_keys}, IssueTypeNames: {issue_type_names}, Expand: {expand}")
        api_url = f"{self.jira_url}/rest/api/3/issue/createmeta"
        params = {'projectKeys': ",".join(project_keys)}
        if issue_type_names:
            params['issuetypeNames'] = ",".join(issue_type_names)
        if expand:
            params['expand'] = expand

        logger.info(f"Requesting URL ({method_name}): {api_url} with params: {params}")
        logger.debug(f"Request Headers ({method_name}): {self._mask_auth_header(self.auth_header)}")

        try:
            response = requests.get(api_url, headers=self.auth_header, params=params, timeout=15, verify=self.ssl_verify)
            logger.info(f"Response Status Code ({method_name}): {response.status_code}")
            logger.debug(f"Response Headers ({method_name}): {response.headers}")
            logger.debug(f"Response Content ({method_name}, first 500 chars): {response.text[:500]}")

            if response.status_code == 200:
                meta_data = response.json()
                logger.info(f"Successfully fetched createmeta for projects: {project_keys}.")
                logger.debug(f"Method {method_name} returning createmeta data.")
                return meta_data
            else:
                logger.error(f"Failed to get create metadata ({method_name}). Status: {response.status_code}, Response: {response.text}")
                logger.debug(f"Method {method_name} returning None due to error.")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"RequestException in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to RequestException.")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSONDecodeError in {method_name} processing response: {e}. Response text: {response.text[:500] if 'response' in locals() else 'Response object not available'}")
            logger.debug(f"Method {method_name} returning None due to JSONDecodeError.")
            return None
        except Exception as e:
            logger.error(f"Generic exception in {method_name}: {e}")
            logger.debug(f"Method {method_name} returning None due to generic exception.")
            return None


if __name__ == '__main__':
    # Example Usage (for testing purposes, replace with actual values)
    # To see DEBUG logs, you might need to set the root logger level if running this directly
    # logging.getLogger().setLevel(logging.DEBUG)
    # logger.setLevel(logging.DEBUG) # or just for this module's logger

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
