import customtkinter as ctk
from jira_api import JiraAPI
import json
import os
import threading

CONFIG_FILE = "config.json"

class JiraApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("JIRA Client")
        self.geometry("600x650")
        self.jira_client = None
        self.selected_files_for_ticket = []
        self.createmeta_data = None
        self.projects_map = {} # Stores {display_name: {'key': str, 'issuetypes': [name_str,...]}}
        self.current_project_var = ctk.StringVar()


        # --- Main Frames ---
        self.login_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.create_ticket_frame = ctk.CTkFrame(self, fg_color="transparent")
        # self.create_ticket_frame.grid_columnconfigure(1, weight=1) # For entry widgets to expand
        self.search_ticket_frame = ctk.CTkFrame(self, fg_color="transparent")

        self._setup_login_view()
        self._setup_create_ticket_view()
        self._setup_search_ticket_view()


        # --- Status Bar ---
        self.status_label = ctk.CTkLabel(self, text="Status: Ready", anchor="w")
        self.status_label.pack(side="bottom", fill="x", padx=5, pady=5)

        # Load config and show initial view
        self.load_config()
        self.show_login_view()

    def _setup_login_view(self):
        """Populates the login frame."""
        ctk.CTkLabel(self.login_frame, text="JIRA URL:").grid(row=0, column=0, padx=20, pady=10, sticky="w")
        self.url_entry = ctk.CTkEntry(self.login_frame, width=300)
        self.url_entry.grid(row=0, column=1, padx=20, pady=10)

        ctk.CTkLabel(self.login_frame, text="Username (Email):").grid(row=1, column=0, padx=20, pady=10, sticky="w")
        self.user_entry = ctk.CTkEntry(self.login_frame, width=300)
        self.user_entry.grid(row=1, column=1, padx=20, pady=10)

        ctk.CTkLabel(self.login_frame, text="API Token:").grid(row=2, column=0, padx=20, pady=10, sticky="w")
        self.token_entry = ctk.CTkEntry(self.login_frame, width=300, show="*")
        self.token_entry.grid(row=2, column=1, padx=20, pady=10)

        self.remember_me_checkbox = ctk.CTkCheckBox(self.login_frame, text="Remember Me (URL & Username)")
        self.remember_me_checkbox.grid(row=3, column=0, columnspan=2, padx=20, pady=15)

        self.login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.login_action)
        self.login_button.grid(row=4, column=0, columnspan=2, padx=20, pady=15)

        self.login_frame.grid_columnconfigure(0, weight=1) # Center content
        self.login_frame.grid_columnconfigure(1, weight=1) # Center content


    def _setup_create_ticket_view(self):
        """Populates the create ticket frame."""
        self.create_ticket_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self.create_ticket_frame, text="Project:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.project_combobox = ctk.CTkComboBox(
            self.create_ticket_frame,
            values=[], width=250,
            variable=self.current_project_var,
            command=self._on_project_selected, # Use command for selection change
            state="readonly" # Start as readonly until populated
        )
        self.project_combobox.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.current_project_var.trace_add("write", self._on_project_selected) # Fallback if command doesn't fire first time

        ctk.CTkLabel(self.create_ticket_frame, text="Issue Type:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.issuetype_combobox = ctk.CTkComboBox(
            self.create_ticket_frame,
            values=[], width=250,
            state="readonly" # Start as readonly
        )
        self.issuetype_combobox.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(self.create_ticket_frame, text="Summary:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.summary_entry = ctk.CTkEntry(self.create_ticket_frame)
        self.summary_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        ctk.CTkLabel(self.create_ticket_frame, text="Description:").grid(row=3, column=0, padx=10, pady=5, sticky="nw")
        self.description_textbox = ctk.CTkTextbox(self.create_ticket_frame, height=150)
        self.description_textbox.grid(row=3, column=1, padx=10, pady=5, sticky="ew")

        self.select_files_button = ctk.CTkButton(self.create_ticket_frame, text="Select Files...", command=self.select_files_action)
        self.select_files_button.grid(row=4, column=0, padx=10, pady=10, sticky="w")

        self.selected_files_label = ctk.CTkLabel(self.create_ticket_frame, text="No files selected.", anchor="w", wraplength=350)
        self.selected_files_label.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

        self.create_ticket_button = ctk.CTkButton(self.create_ticket_frame, text="Create Ticket", command=self.create_ticket_action)
        self.create_ticket_button.grid(row=5, column=0, columnspan=2, padx=10, pady=20)

        self.logout_button_ct = ctk.CTkButton(self.create_ticket_frame, text="Logout", command=self.logout_action, fg_color="grey")
        self.logout_button_ct.grid(row=6, column=0, columnspan=2, pady=5, sticky="ew")

        self.goto_search_button_ct = ctk.CTkButton(self.create_ticket_frame, text="Go to Search Tickets", command=self.show_search_ticket_view)
        self.goto_search_button_ct.grid(row=7, column=0, columnspan=2, pady=10, sticky="ew")
        # self.create_ticket_frame.grid_rowconfigure(7, weight=1) # Push logout and nav to bottom if needed


    def _setup_search_ticket_view(self):
        """Populates the search ticket frame."""
        self.search_ticket_frame.grid_columnconfigure(0, weight=1) # Allow JQL entry to expand slightly
        self.search_ticket_frame.grid_columnconfigure(1, weight=0) # Search button fixed size
        self.search_ticket_frame.grid_rowconfigure(1, weight=1) # Allow results textbox to expand

        # JQL Query
        ctk.CTkLabel(self.search_ticket_frame, text="JQL Query:").grid(row=0, column=0, padx=(10,0), pady=10, sticky="w")
        self.jql_query_entry = ctk.CTkEntry(self.search_ticket_frame, placeholder_text="e.g., project = 'TEST' AND status = 'Open' ORDER BY created DESC", width=400)
        self.jql_query_entry.grid(row=0, column=0, padx=(80,5), pady=10, sticky="ew") # Label takes some space

        self.search_button = ctk.CTkButton(self.search_ticket_frame, text="Search", command=self.search_ticket_action, width=100)
        self.search_button.grid(row=0, column=1, padx=5, pady=10, sticky="e")

        # Results Textbox
        self.search_results_textbox = ctk.CTkTextbox(self.search_ticket_frame, state="disabled", wrap="none", height=300) # Read-only initially
        self.search_results_textbox.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        # Action Buttons Frame
        action_buttons_frame = ctk.CTkFrame(self.search_ticket_frame, fg_color="transparent")
        action_buttons_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
        action_buttons_frame.grid_columnconfigure(0, weight=1) # Distribute space
        action_buttons_frame.grid_columnconfigure(1, weight=1)
        action_buttons_frame.grid_columnconfigure(2, weight=1)


        self.clear_results_button = ctk.CTkButton(action_buttons_frame, text="Clear Results", command=self.clear_search_results_action)
        self.clear_results_button.grid(row=0, column=0, padx=5, pady=5)

        self.goto_create_button_st = ctk.CTkButton(action_buttons_frame, text="Go to Create Ticket", command=self.show_create_ticket_view)
        self.goto_create_button_st.grid(row=0, column=1, padx=5, pady=5)

        self.logout_button_st = ctk.CTkButton(action_buttons_frame, text="Logout", command=self.logout_action, fg_color="grey")
        self.logout_button_st.grid(row=0, column=2, padx=5, pady=5)


    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                self.url_entry.insert(0, config.get("jira_url", ""))
                self.user_entry.insert(0, config.get("username", ""))
                if config.get("remember_me", False):
                    self.remember_me_checkbox.select()
                self.status_label.configure(text="Status: Loaded saved configuration.")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.status_label.configure(text=f"Status: Error loading config: {e}")
            # If config is corrupted or not found, try to remove it if it exists
            # Ensure that if a file is found not to exist, it's not due to a previous failed load
            if isinstance(e, FileNotFoundError) and "Corrupted config removed" in self.status_label.cget("text"):
                 pass # Don't show FileNotFoundError if we just deleted it.
            elif os.path.exists(CONFIG_FILE) and isinstance(e, json.JSONDecodeError):
                try:
                    os.remove(CONFIG_FILE)
                    self.status_label.configure(text="Status: Corrupted config removed. Please re-enter details.")
                except OSError as oe:
                    print(f"Error removing corrupted config file: {oe}")
            elif not isinstance(e, FileNotFoundError): # Report other errors
                 self.status_label.configure(text=f"Status: Error loading config: {e}")
        except Exception as e: # Catch any other unexpected error during load
            self.status_label.configure(text=f"Status: Unexpected error loading config: {e}")


    def save_config(self):
        try:
            if self.remember_me_checkbox.get():
                config = {
                    "jira_url": self.url_entry.get(),
                    "username": self.user_entry.get(),
                    "remember_me": True
                }
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(config, f)
                # self.status_label.configure(text="Status: Configuration saved.") # Avoid overriding login messages
            else:
                if os.path.exists(CONFIG_FILE):
                    os.remove(CONFIG_FILE)
                # self.status_label.configure(text="Status: Configuration removed.")
        except (IOError, OSError) as e:
            self.status_label.configure(text=f"Status: Error saving/deleting config: {e}")

    def login_action(self):
        if self.login_button.cget("state") == "disabled": # Already logging in
            return
        self.login_button.configure(state="disabled")
        self.status_label.configure(text="Status: Logging in...")

        # Store current URL and username in case they are cleared by switching views
        # before save_config is called in the threaded callback.
        self.current_url_for_config = self.url_entry.get()
        self.current_username_for_config = self.user_entry.get()

        thread = threading.Thread(target=self._perform_login)
        thread.daemon = True
        thread.start()

    def _perform_login(self):
        # Use stored values for consistency as entries might change
        jira_url = self.current_url_for_config
        username = self.current_username_for_config
        api_token = self.token_entry.get() # Token is not saved, always get fresh

        if not all([jira_url, username, api_token]):
            self.after(0, self._update_gui_post_login, False, {"message": "JIRA URL, Username, and API Token are required."})
            return

        try:
            # Ensure previous client (if any) is cleared before creating a new one
            self.jira_client = None
            temp_client = JiraAPI(jira_url, username, api_token)
            if temp_client.verify_credentials():
                self.jira_client = temp_client # Assign only on success
                self.after(0, self._update_gui_post_login, True, {"message": "Login successful!"})
            else:
                self.after(0, self._update_gui_post_login, False, {"message": "Login failed. Check credentials or JIRA URL. See console for details."})
        except requests.exceptions.MissingSchema:
             self.after(0, self._update_gui_post_login, False, {"message": "Login error: Invalid JIRA URL format (e.g., http:// or https:// missing)."})
        except Exception as e:
            print(f"Exception during login attempt: {e}")
            self.after(0, self._update_gui_post_login, False, {"message": f"Login error: {e}"})


    def _update_gui_post_login(self, success: bool, data: dict):
        message = data.get("message", "Login failed.")
        if success:
            # Use the stored URL/Username for saving config, as entry fields might be disabled.
            temp_url_for_config = self.current_url_for_config
            temp_username_for_config = self.current_username_for_config

            # Temporarily enable to get current values if they were typed just before login
            # and remember me was off. This is a bit of a workaround for state management.
            original_url_state = self.url_entry.cget("state")
            original_user_state = self.user_entry.cget("state")
            self.url_entry.configure(state="normal")
            self.user_entry.configure(state="normal")

            self.save_config() # save_config now uses self.url_entry.get()

            self.url_entry.configure(state="disabled") # Re-disable after saving
            self.user_entry.configure(state="disabled")# Re-disable after saving

            self.status_label.configure(text=message)
            self.token_entry.configure(state="disabled")
            self.remember_me_checkbox.configure(state="disabled")

            self._fetch_and_populate_createmeta_async() # Fetch project data
            self.show_create_ticket_view() # Default view after login
        else:
            self.jira_client = None
            self.status_label.configure(text=f"Status: {message}")

        self.login_button.configure(state="normal")

    def _fetch_and_populate_createmeta_async(self):
        self.status_label.configure(text="Status: Fetching project data...")
        self.project_combobox.configure(state="disabled")
        self.issuetype_combobox.configure(state="disabled")
        self.create_ticket_button.configure(state="disabled")

        thread = threading.Thread(target=self._perform_fetch_createmeta)
        thread.daemon = True
        thread.start()

    def _perform_fetch_createmeta(self):
        if not self.jira_client:
            self.after(0, self._update_project_issue_type_fields_failure, "Not logged in.")
            return

        try:
            # Using projectKeys=[] might not be universally supported or might be slow.
            # For a production app, one might fetch projects first, then allow user to select, then fetch createmeta for that project.
            # Or, fetch createmeta for a list of known/favorite project keys.
            # For this example, fetching all accessible createmeta.
            self.createmeta_data = self.jira_client.get_create_meta(project_keys=[])

            if self.createmeta_data and self.createmeta_data.get("projects"):
                temp_projects_map = {}
                for project in self.createmeta_data["projects"]:
                    proj_key = project.get("key")
                    proj_name = project.get("name")
                    display_name = f"{proj_name} ({proj_key})"

                    issuetypes_list = []
                    for issuetype in project.get("issuetypes", []):
                        issuetypes_list.append(issuetype.get("name"))

                    if proj_key and proj_name and issuetypes_list: # Ensure valid data
                        temp_projects_map[display_name] = {
                            "key": proj_key,
                            "issuetypes": sorted(list(set(issuetypes_list))) # Sort and unique
                        }
                self.projects_map = temp_projects_map
                self.after(0, self._update_project_issue_type_fields_success)
            else:
                error_msg = "Failed to parse project data from JIRA."
                if self.createmeta_data and self.createmeta_data.get("errors"): # Check if JIRA API returned specific errors
                    error_msg = self.createmeta_data.get("errors")
                elif self.createmeta_data is None: # API call itself failed before returning JSON
                     error_msg = "Failed to fetch project data (API error, check console)."

                self.after(0, self._update_project_issue_type_fields_failure, error_msg)
        except Exception as e:
            print(f"Exception during createmeta fetch: {e}")
            self.after(0, self._update_project_issue_type_fields_failure, f"Error fetching project data: {e}")

    def _update_project_issue_type_fields_success(self):
        project_display_names = sorted(list(self.projects_map.keys()))
        self.project_combobox.configure(values=project_display_names, state="readonly" if project_display_names else "disabled")

        if project_display_names:
            self.project_combobox.set(project_display_names[0]) # Triggers _on_project_selected via command/trace
            # self._on_project_selected() # Call manually if trace/command is not reliable on first set
        else:
            self.issuetype_combobox.configure(values=[], state="disabled")
            self.issuetype_combobox.set("")

        self.status_label.configure(text="Status: Project data loaded.")
        self.create_ticket_button.configure(state="normal" if project_display_names else "disabled")
        self.issuetype_combobox.configure(state="readonly" if self.project_combobox.get() and self.projects_map.get(self.project_combobox.get(), {}).get("issuetypes") else "disabled")


    def _update_project_issue_type_fields_failure(self, error_message):
        self.status_label.configure(text=f"Status: {error_message}")
        self.project_combobox.configure(values=[], state="disabled")
        self.project_combobox.set("")
        self.issuetype_combobox.configure(values=[], state="disabled")
        self.issuetype_combobox.set("")
        # Keep create button disabled if essential data is missing
        self.create_ticket_button.configure(state="disabled")


    def _on_project_selected(self, *args): # *args handles potential event data from trace
        selected_project_display_name = self.current_project_var.get() # Use var for reliability

        if selected_project_display_name and selected_project_display_name in self.projects_map:
            project_data = self.projects_map[selected_project_display_name]
            issue_types = project_data.get("issuetypes", [])
            self.issuetype_combobox.configure(values=issue_types, state="readonly" if issue_types else "disabled")
            if issue_types:
                self.issuetype_combobox.set(issue_types[0])
            else:
                self.issuetype_combobox.set("")
        else: # Project cleared or invalid
            self.issuetype_combobox.configure(values=[], state="disabled")
            self.issuetype_combobox.set("")


    def show_login_view(self):
        # Enable login fields if they were disabled
        self.url_entry.configure(state="normal")
        self.user_entry.configure(state="normal")
        self.token_entry.configure(state="normal")
        self.remember_me_checkbox.configure(state="normal")

        self.create_ticket_frame.pack_forget()
        self.search_ticket_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)

        current_status = self.status_label.cget("text") # Get current status before potentially changing it

        # Logic to ensure "Ready - Please login" is shown appropriately
        is_error_status = "Error loading config" in current_status or \
                          "Corrupted config removed" in current_status or \
                          "Login error" in current_status or \
                          "Login failed" in current_status or \
                          "Logged out" in current_status

        is_neutral_status = "Ready - Please login" in current_status or \
                            "Loaded saved configuration" in current_status or \
                            "Status: Configuration removed" in current_status # if remember me was unchecked

        if is_error_status or not os.path.exists(CONFIG_FILE) :
            self.status_label.configure(text="Status: Ready - Please login")
        elif not is_neutral_status and "Logging in..." not in current_status and "Login successful!" not in current_status:
            # If status is something else from other views, reset to generic ready or loaded config
            if os.path.exists(CONFIG_FILE) and not self.url_entry.get() and not self.user_entry.get(): # Config exists but fields are empty
                self.load_config() # Attempt to reload if fields were cleared by other means
            elif os.path.exists(CONFIG_FILE) and (self.url_entry.get() or self.user_entry.get()):
                 self.status_label.configure(text="Status: Loaded saved configuration.")
            else:
                 self.status_label.configure(text="Status: Ready - Please login")


    def select_files_action(self):
        try:
            filenames = ctk.filedialog.askopenfilenames()
            if filenames:
                self.selected_files_for_ticket = list(filenames)
                if len(self.selected_files_for_ticket) > 3:
                    display_files = ", ".join([os.path.basename(f) for f in self.selected_files_for_ticket[:3]]) + f" ... (+{len(self.selected_files_for_ticket)-3})"
                else:
                    display_files = ", ".join([os.path.basename(f) for f in self.selected_files_for_ticket])
                self.selected_files_label.configure(text=f"Selected: {display_files if display_files else 'None'}")
            else: # User cancelled dialog
                # self.selected_files_for_ticket = [] # Keep existing if any
                # self.selected_files_label.configure(text="No new files selected.")
                pass # Do nothing if cancelled, keep previous selection
        except Exception as e:
            self.status_label.configure(text=f"Error selecting files: {e}")
            print(f"Error selecting files: {e}")

    def create_ticket_action(self):
        if self.create_ticket_button.cget("state") == "disabled":
            return

        self.create_ticket_button.configure(state="disabled")
        self.select_files_button.configure(state="disabled")
        self.status_label.configure(text="Status: Creating ticket...")

        thread = threading.Thread(target=self._perform_ticket_creation)
        thread.daemon = True
        thread.start()

    def _perform_ticket_creation(self):
        summary = self.summary_entry.get()
        description = self.description_textbox.get("1.0", "end-1c")

        selected_project_display = self.project_combobox.get()
        issue_type_name = self.issuetype_combobox.get()

        if not selected_project_display or not self.projects_map.get(selected_project_display):
            self.after(0, self._update_gui_post_ticket_creation, False, {"message": "Invalid project selected."})
            return
        project_key = self.projects_map[selected_project_display]['key']


        if not all([summary, project_key, issue_type_name]):
            self.after(0, self._update_gui_post_ticket_creation, False, {"message": "Project, Issue Type, and Summary are required."})
            return

        if not self.jira_client:
            self.after(0, self._update_gui_post_ticket_creation, False, {"message": "Not logged in. Please login first."})
            return

        try:
            created_issue_data = self.jira_client.create_issue(project_key, summary, description, issue_type_name)
            if created_issue_data and "key" in created_issue_data:
                issue_key = created_issue_data["key"]
                attachment_results = []
                if self.selected_files_for_ticket:
                    for file_path in self.selected_files_for_ticket:
                        try:
                            # Ensure file_path is valid and file exists before attempting to attach
                            if os.path.exists(file_path):
                                attach_response = self.jira_client.add_attachment(issue_key, file_path)
                                if attach_response: # Jira usually returns a list of attachments
                                    attachment_results.append(f"{os.path.basename(file_path)}: OK")
                                else:
                                    attachment_results.append(f"{os.path.basename(file_path)}: Failed")
                            else:
                                attachment_results.append(f"{os.path.basename(file_path)}: File not found locally")
                        except Exception as attach_e:
                            attachment_results.append(f"{os.path.basename(file_path)}: Error ({attach_e})")

                self.after(0, self._update_gui_post_ticket_creation, True,
                           {"message": f"Ticket {issue_key} created!",
                            "issue_key": issue_key,
                            "attachment_results": attachment_results})
            else:
                # create_issue method in JiraAPI should print details from response.text
                error_detail = created_issue_data.get("errorMessages", ["Unknown error from API"]) if isinstance(created_issue_data, dict) else "Check console for API response."
                self.after(0, self._update_gui_post_ticket_creation, False, {"message": f"Failed to create ticket. API: {error_detail}"})
        except Exception as e:
            print(f"Exception during ticket creation: {e}")
            self.after(0, self._update_gui_post_ticket_creation, False, {"message": f"Error creating ticket: {e}"})

    def _update_gui_post_ticket_creation(self, success: bool, data: dict):
        message = data.get("message", "Ticket creation process finished.")
        if success:
            self.status_label.configure(text=message)
            self.summary_entry.delete(0, "end")
            self.description_textbox.delete("1.0", "end")
            # self.project_combobox.set("") # Or set to a default?
            # self.issuetype_combobox.set("") # Or set to a default?
            self.selected_files_for_ticket = []
            self.selected_files_label.configure(text="No files selected.")

            attachment_info = data.get("attachment_results")
            if attachment_info:
                # Could display this in a more sophisticated way later
                print(f"Attachment results for {data.get('issue_key')}: {'; '.join(attachment_info)}")
                self.status_label.configure(text=f"{message} Attachments: {len(attachment_info)} processed.")

        else:
            self.status_label.configure(text=f"Status: {message}")

        self.create_ticket_button.configure(state="normal")
        self.select_files_button.configure(state="normal")

    def logout_action(self):
        self.jira_client = None
        self.token_entry.delete(0, "end") # Clear API token
        # self.url_entry.delete(0, "end")
        # self.user_entry.delete(0, "end")
        self.selected_files_for_ticket = []
        if hasattr(self, 'selected_files_label'):
            self.selected_files_label.configure(text="No files selected.")

        # Clear createmeta and project/issue type comboboxes
        self.createmeta_data = None
        self.projects_map = {}
        self.project_combobox.configure(values=[], state="disabled")
        self.project_combobox.set("")
        self.issuetype_combobox.configure(values=[], state="disabled")
        self.issuetype_combobox.set("")
        self.current_project_var.set("")


        self.title("JIRA Client")
        self.show_login_view()
        self.status_label.configure(text="Status: Logged out.")
        self.login_frame.focus_set()


    def search_ticket_action(self):
        if self.search_button.cget("state") == "disabled":
            return
        self.search_button.configure(state="disabled")
        self.status_label.configure(text="Status: Searching issues...")

        thread = threading.Thread(target=self._perform_ticket_search)
        thread.daemon = True
        thread.start()

    def _perform_ticket_search(self):
        jql_query = self.jql_query_entry.get()
        if not jql_query:
            self.after(0, self._update_gui_post_ticket_search, False, {"message": "JQL Query cannot be empty."})
            return

        if not self.jira_client:
            self.after(0, self._update_gui_post_ticket_search, False, {"message": "Not logged in. Please login first."})
            return

        try:
            issues = self.jira_client.search_issues(jql_query)
            if issues is not None: # search_issues returns [] on non-200 or error, None is not expected by my jira_api
                self.after(0, self._update_gui_post_ticket_search, True, {"issues_list": issues})
            else: # Should be caught by API client's error prints, but as fallback:
                self.after(0, self._update_gui_post_ticket_search, False, {"message": "Search failed. Check JQL or connection. See console."})
        except Exception as e:
            print(f"Exception during ticket search: {e}")
            self.after(0, self._update_gui_post_ticket_search, False, {"message": f"Error searching tickets: {e}"})

    def _update_gui_post_ticket_search(self, success: bool, data: dict):
        self.search_results_textbox.configure(state="normal") # Enable for modification
        self.search_results_textbox.delete("1.0", "end")

        message = data.get("message")
        if success:
            issues_list = data.get("issues_list", [])
            if issues_list:
                formatted_results = []
                for issue in issues_list:
                    fields = issue.get("fields", {})
                    key = issue.get("key", "N/A")
                    summary = fields.get("summary", "No Summary")
                    status = fields.get("status", {}).get("name", "N/A")
                    assignee = fields.get("assignee")
                    assignee_name = assignee.get("displayName", "Unassigned") if assignee else "Unassigned"
                    formatted_results.append(f"{key}: {summary}\n  Status: {status}, Assignee: {assignee_name}\n--------------------")
                self.search_results_textbox.insert("1.0", "\n".join(formatted_results))
                self.status_label.configure(text=f"Status: Search successful. Found {len(issues_list)} issue(s).")
            else:
                self.status_label.configure(text="Status: No issues found for your query.")
        else:
            self.status_label.configure(text=f"Status: {message if message else 'Search failed.'}")

        self.search_results_textbox.configure(state="disabled") # Back to read-only
        self.search_button.configure(state="normal")

    def clear_search_results_action(self):
        self.search_results_textbox.configure(state="normal")
        self.search_results_textbox.delete("1.0", "end")
        self.search_results_textbox.configure(state="disabled")
        self.jql_query_entry.delete(0, "end")
        self.status_label.configure(text="Status: Search results cleared.")


    def show_create_ticket_view(self):
        self.login_frame.pack_forget()
        self.search_ticket_frame.pack_forget()
        self.create_ticket_frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.status_label.configure(text="Status: Switched to Create Ticket View")
        if self.jira_client and self.jira_client.username:
             self.title(f"JIRA Client - {self.jira_client.username} - Create Ticket")


    def show_search_ticket_view(self):
        self.login_frame.pack_forget()
        self.create_ticket_frame.pack_forget()
        self.search_ticket_frame.pack(fill="both", expand=True, padx=10, pady=10) # Adjusted padding
        self.status_label.configure(text="Status: Switched to Search Tickets View")
        if self.jira_client and self.jira_client.username:
             self.title(f"JIRA Client - {self.jira_client.username} - Search Tickets")


if __name__ == '__main__':
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")

    app = JiraApp()
    app.mainloop()
