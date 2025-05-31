# Technical Requirement Plan: Python JIRA GUI Application (Client Focus)

## 1. Introduction

This document outlines the technical requirements for developing a desktop application using Python. The application will provide a graphical user interface (GUI) for interacting with a JIRA instance via its REST API, using Basic Authentication (with an API token). The primary goal is to create a visually appealing ("stunning") and functional user experience specifically tailored for **creating tickets, searching tickets, and uploading file attachments** as a client.

## 2. Scope

*   **Core Functionality:** Allow users to connect to a specified JIRA instance, authenticate, **search for existing tickets**, **create new tickets**, and **attach files** to tickets.
*   **Target Platform:** Desktop (Windows, macOS, Linux - specific target may influence framework choice).
*   **Key Technologies:** Python, JIRA REST API v3 (Cloud) or relevant Server/DC version, Basic Authentication (Username + API Token).
*   **User Interface:** Focus on a modern, visually appealing, and intuitive GUI optimized for the core tasks.

## 3. GUI Framework Selection (Python)

Achieving a "stunning" GUI in Python requires careful framework selection and potentially custom styling. Key options include:

*   **PyQt / PySide (Qt for Python):**
    *   **Pros:** Very powerful, mature, feature-rich, highly customizable via stylesheets (QSS, similar to CSS) or custom widgets. Can achieve professional, native-looking, or completely custom UIs. Good performance.
    *   **Cons:** Can have a steeper learning curve. Licensing (PyQt is GPL/Commercial, PySide is LGPL).
    *   **Aesthetics:** High potential for stunning UIs through styling.
*   **Kivy:**
    *   **Pros:** Designed for modern, touch-friendly interfaces. Uses its own graphics engine (OpenGL). Cross-platform (including mobile). Highly customizable appearance.
    *   **Cons:** Non-native look and feel (which might be desired for a "stunning" custom look). Can be less intuitive for traditional desktop app layouts.
    *   **Aesthetics:** Excellent for unique, non-standard, visually rich UIs.
*   **CustomTkinter:**
    *   **Pros:** Builds upon Python's built-in Tkinter but provides modern, customizable widgets out-of-the-box. Easier learning curve than Qt/Kivy. Actively developed.
    *   **Cons:** Less mature and potentially less feature-rich than Qt. Customization might be less flexible than Qt/Kivy for highly complex designs.
    *   **Aesthetics:** Good potential for modern, clean UIs with less effort.
*   **Flet:**
    *   **Pros:** Allows building interactive web, desktop, and mobile apps using Python. Uses Flutter for rendering, enabling beautiful UIs. Simpler API compared to Qt.
    *   **Cons:** Relatively new. Relies on Flutter, adding a dependency layer.
    *   **Aesthetics:** Leverages Flutter's rendering engine for high-quality, modern UIs.

**Recommendation:** **PyQt/PySide** offers the most power and flexibility for highly polished, custom desktop UIs if the learning curve is acceptable. **CustomTkinter** or **Flet** are good alternatives for achieving modern looks more quickly with potentially less complexity.

## 4. JIRA REST API Integration

Interaction with the JIRA API will be handled as follows:

*   **Library:** Use the `requests` library for direct HTTP calls or a dedicated JIRA client library like `jira-python` (community-maintained) to simplify interactions.
    *   **Recommendation:** Start with `requests` for simplicity and full control, especially for file uploads. `jira-python` can simplify issue creation and search.
*   **Authentication:** Implement **Basic Authentication**.
    *   The application must prompt the user for their JIRA URL, username (email address), and API Token (Note: JIRA Cloud uses API tokens, not passwords, for Basic Auth).
    *   Credentials (especially the API token) should **not** be stored in plain text. Consider secure storage options (OS keychain) or prompt the user each session.
    *   Each API request must include the `Authorization` header with the value `Basic <base64-encoded username:api_token>`.
*   **API Endpoint:** Target the appropriate JIRA REST API version (e.g., v3 for Cloud). The base URL will be configurable by the user.
*   **Data Handling:** Parse JSON responses from the API. Implement robust error handling for network issues, authentication failures, API errors (e.g., 4xx, 5xx status codes), and rate limiting.
*   **Core API Calls (Based on Permissions):**
    *   `/rest/api/3/myself` (Verify credentials upon login)
    *   `/rest/api/3/search` (Search for issues using JQL - required for viewing created/relevant tickets)
    *   `/rest/api/3/issue` (POST request to create new issues)
    *   `/rest/api/3/issue/{issueIdOrKey}/attachments` (POST request to add attachments/upload files to an existing issue. Requires the issue ID/Key, which might be obtained after creation or via search).
    *   Potentially `/rest/api/3/createmeta` (GET request to fetch metadata about fields required for creating issues in specific projects/issue types - useful for dynamic form generation).

## 5. Application Architecture & Core Features (Client Focus)

*   **Architecture:** Employ a pattern like Model-View-Controller (MVC) or Model-View-ViewModel (MVVM) to separate concerns:
    *   **Model:** Handles JIRA API interaction (create, search, attach), data processing.
    *   **View:** The GUI components (built with the chosen framework), focusing on forms and results display.
    *   **Controller/ViewModel:** Mediates between View and Model, handles user input (form data, search queries, file selections), updates the View.
*   **Core Features (Revised based on Permissions):**
    *   **Configuration:** Allow users to input and save/load their JIRA URL and username (API token likely entered per session or retrieved from secure storage).
    *   **Authentication:** Login screen/mechanism using Basic Auth (API Token).
    *   **Ticket Creation Form:** A dedicated view/form to create new JIRA issues. This should ideally dynamically fetch required fields (using `createmeta` if possible) for the selected project/issue type. Include fields for Summary, Description, Priority, etc., as permitted and required. Provide a mechanism to attach files during creation (may require creating the issue first, then attaching).
    *   **File Upload Mechanism:** Integrate a file browser/selector to allow users to choose files for attachment during or after ticket creation.
    *   **Ticket Search Interface:** A view to search for tickets using JQL. Display results in a list/table format showing key information (Key, Summary, Status). *Note: Detailed view might be limited if `GET /issue/{issueIdOrKey}` permission is restricted, but basic search results should be possible.*
    *   **Status Bar:** Display connection status, ongoing actions (creating, searching, uploading), and feedback/errors.

## 6. Non-Functional Requirements

*   **Performance:** The application should remain responsive during API calls (use background threads or asynchronous operations for creation, search, upload).
*   **Security:** Handle credentials securely (avoid plain text storage). Use HTTPS for all API communication.
*   **Usability:** Intuitive forms, clear search interface, easy file attachment process, and clear feedback.
*   **Aesthetics:** Modern, clean, and visually appealing interface, aligning with the "stunning GUI" requirement.
*   **Error Handling:** Gracefully handle API errors (e.g., insufficient permissions, invalid JQL, upload failures), network issues, and invalid user input.

## 7. Conclusion & Next Steps

This revised plan provides a focused technical foundation for the Python JIRA GUI application, tailored to client-side ticket creation, search, and file upload. The next steps involve:

1.  Finalizing the choice of Python GUI framework.
2.  Setting up the development environment.
3.  Implementing the core authentication and API interaction logic for create, search, and attach.
4.  Building the GUI components for the creation form, search interface, and file handling.
5.  Refining the UI/UX for visual appeal and usability within the defined scope.

This plan can be further detailed as development progresses.
