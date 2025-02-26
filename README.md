# Workspace ONE Autorecovery

Workspace ONE Autorecovery is a comprehensive PowerShell-based solution designed to automate health checks and recovery actions in your Workspace ONE (UEM) environment. This suite of scripts monitors critical services, assesses overall system health, and automatically re-enrolls devices when necessary to keep your environment compliant and running smoothly.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation & Initial Configuration](#installation--initial-configuration)
   - [Prerequisites](#prerequisites)
   - [Configuration File: config.json](#configuration-file-configjson)
   - [Upload to UEM](#upload-to-uem)
   - [Installation Script: install.ps1](#installation-script-installps1)
   - [Initial Detection Script: detection.ps1](#initial-detection-script-detectionps1)
3. [Main Health Evaluation](#main-health-evaluation)
   - [HubHealthEvaluation.ps1](#hubhealthevaluationps1)
4. [Supporting Functions](#supporting-functions)
   - [General_Functions.ps1](#general_functionssps1)
   - [OMA-DM_Status_Check_Functions.ps1](#oma-dm_status_check_functionssps1)
   - [SQL_Functions.ps1](#sql_functionssps1)
   - [UEM_Status_Check_Functions.ps1](#uem_status_check_functionssps1)
5. [Device Enrollment / Re-enrollment](#device-enrollment--re-enrollment)
   - [UEM_automatic_reenrollment.ps1](#uem_automatic_reenrollmentsps1)
   - [recovery.ps1](#recoveryps1)
6. [Additional Information & Troubleshooting](#additional-information--troubleshooting)
7. [License](#license)

---

## Introduction

Modern Workspace ONE environments require constant monitoring and proactive remediation to maintain service health and device compliance. This solution provides a modular, script-based approach to:

- **Detect Issues:** Regular health checks to determine the status of key services.
- **Automate Recovery:** Automatically re-enroll devices or trigger remediation actions when issues are detected.
- **Log & Report:** Record events and diagnostics for analysis and troubleshooting.

Each component is designed to be used independently or as part of a scheduled workflow, providing flexibility in deployment and management.

---

## Installation & Initial Configuration

Before running the autorecovery processes, you must prepare your environment by configuring the solution and installing necessary components.

### Prerequisites

- **PowerShell Version:**  
  - Windows PowerShell 5.1 (or higher) or PowerShell Core 7+.
- **Administrative Rights:**  
  - Run installation and remediation scripts in an elevated PowerShell session (Run as Administrator).
- **Network Requirements:**  
  - Ensure your system has access to the Workspace ONE UEM endpoints.
- **Dependencies:**  
  - Verify that any required modules (e.g., SQLite libraries) and prerequisites are installed on your system.

### Configuration File: config.json

- **Purpose:**  
  The `config.json` file contains all environment-specific settings required for operation. This includes API endpoints, authentication credentials, logging paths, thresholds, and other parameters.
- **Setup Instructions:**  
  1. Open the file in your favorite text editor.
  2. Update the following (example properties):
     - **UEMServerUrl:** URL of your Workspace ONE UEM server.
     - **APIKey:** Your API key or authentication token.
     - **LoggingPath:** Path where logs and database files will be stored.
     - **Thresholds:** Numeric values or parameters to trigger alerts or remediation.
  3. Save the file.

### Upload to UEM

- **Instructions:**
  1. Save all files in a folder - store the application folder also in the same space
  2. run the upload_to_ws1.ps1 - for example like this
    - Upload_to_ws1.ps1  -APIEndpoint "as1831.awmdm.com" -APIUser "admin" -APIPassword "password" -APIKey "ABC123" -OGID "1298"
    - This will create all required files and settings and uploads the data to Workspace ONE UEM
  3. Deploy it to a test device
  4. Deploy it to production
  5. Lean back and let the Script do the work

### Installation Script: install.ps1

- **Purpose:**  
  Automates the installation process by verifying prerequisites and installing any required dependencies.
- **Usage Instructions:**  
  1. Open an elevated PowerShell window.
  2. Run the installation script:
     ```powershell
     .\install.ps1
     ```
  3. Follow the on-screen prompts to complete the setup.

### Initial Detection Script: detection.ps1

- **Purpose:**  
  This script performs an initial assessment of your Workspace ONE environment. It detects potential issues by checking the status of various components.
- **Usage Instructions:**  
  Execute the script after installation to establish a baseline:
  ```powershell
  .\detection.ps1


## Main Health Evaluation

### HubHealthEvaluation.ps1

- **Purpose:**  
  This is the central diagnostic script that aggregates information from various checks across the Workspace ONE environment. It assesses the overall health of the Workspace ONE hub and can trigger alerts (for example, sending email notifications) when issues are detected.

- **Usage Instructions:**  
  It is recommended to schedule this script to run at regular intervals using Windows Task Scheduler or a similar automation tool:
  ```powershell
  .\HubHealthEvaluation.ps1

## Supporting Functions

These scripts provide the core functionalities that the main scripts depend on. They handle tasks such as logging, performing service status checks, and interacting with the SQLite database.

### General_Functions.ps1

- **Purpose:**  
  Contains shared helper functions for logging, error handling, and general utility operations used throughout the solution.

- **Usage:**  
  This file is automatically imported by the main scripts and does not need to be executed independently.

### OMA-DM_Status_Check_Functions.ps1

- **Purpose:**  
  Implements functions to verify the status and connectivity of the OMA-DM service—the protocol used for mobile device management.

- **Usage:**  
  Functions from this file are invoked by both the detection and health evaluation scripts to ensure that OMA-DM services are operational.

### SQL_Functions.ps1

- **Purpose:**  
  Provides functions for interacting with an SQLite database. This is used to log events, store state information, and maintain a historical record of system checks.

- **Usage:**  
  Ensure the SQLite database path is configured correctly in `config.json`. The functions here are utilized by scripts that record events or query historical data.

### UEM_Status_Check_Functions.ps1

- **Purpose:**  
  Contains functions that check the operational status of Workspace ONE UEM services. This includes connectivity tests and service health validation.

- **Usage:**  
  Called by the main health evaluation script to compile a complete and accurate status report of your UEM environment.


## Device Enrollment / Re-enrollment

Ensuring that devices remain enrolled and compliant is critical for effective management of your Workspace ONE environment. The following scripts automate the process of enrolling or re-enrolling devices when issues are detected.

### UEM_automatic_reenrollment.ps1

- **Purpose:**  
  Automatically initiates the enrollment or re-enrollment process for devices that are non-compliant or have lost their management profiles. This helps maintain device management continuity without requiring manual intervention.

- **Usage Instructions:**  
  Run this script manually or integrate it into your automated workflow to trigger re-enrollment:
  ```powershell
  .\UEM_automatic_reenrollment.ps1

### recovery.ps1
- **Purpose:**  
Acts as the orchestrator for recovery operations. It combines the results from health checks with the re-enrollment logic to restore devices to a compliant state. This script ensures that any detected issues are resolved by re-establishing proper device management.

- **Usage Instructions:**  
Execute this script when health evaluations indicate issues that require recovery actions:

powershell
.\recovery.ps1

## Additional Information & Troubleshooting

- **Scheduling & Automation:**  
  To ensure continuous monitoring and remediation, schedule the `HubHealthEvaluation.ps1` and `recovery.ps1` scripts using Windows Task Scheduler or another automation tool. This setup will help keep your environment under constant observation and ensure timely recovery actions.

- **Logging & Reporting:**  
  - Logs are generated based on the configurations set in `config.json`, with the option to store historical data in an SQLite database.  
  - Regularly review these logs to track system performance, identify recurring issues, and troubleshoot failures.

- **Extensibility:**  
  The modular design of this solution allows you to:
  - Add new service checks or custom remediation steps.
  - Integrate additional alerting mechanisms such as SMS, webhooks, or third-party monitoring tools.
  - Update configuration parameters in `config.json` to align with evolving environment requirements.

- **Common Issues & Troubleshooting Tips:**  
  - **Permission Errors:** Ensure that all scripts are run with administrative privileges.  
  - **Connectivity Problems:** Verify that your system can reach all necessary Workspace ONE UEM endpoints and external resources.  
  - **Configuration Mistakes:** Double-check the settings in `config.json` to ensure they match your environment's requirements.  
  - **Module/Dependency Issues:** Confirm that all required PowerShell modules and dependencies (e.g., SQLite libraries) are correctly installed.

- **Support:**  
  If you encounter persistent issues, consult the detailed logs for error messages, review the inline comments within each script for additional context, and ensure that all prerequisites are met. Consider reaching out to your internal support team or the community for further assistance.


## License

This project is licensed under the terms specified in the `license.md` file. Please review that file for complete details regarding usage, distribution, and modification rights.
