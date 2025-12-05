This application uses Salt (fmr. SaltStack) and requires a pre-configured salt-master server with salt-api installed.

Requirements:
* Salt Server
* Node.js

Application Configuration
If the application has never been used it must first be configured to connect to a Salt Master API server.
•	Access Settings – Click the gear icon in the top right corner of the application to open the settings modal
•	Fill in the fields: 
o	Salt API URL – determines the location of the Salt API in which the proxy server needs to connect
o	Username – the username used to login to the Salt Master server (for all functionality this must be an administrator account with sudo permissions)
o	Password – the password used to login to the Salt Master server
o	Eauth – the type of authentication used by the Salt Master server (for best results use pam)
•	Save Settings – Click “Save Settings”.  This information is then stored in a file and passed to the proxy server to handle credentials and forward requests.
Device Management
The device management modal allows the user to accept or remove minion keys to control which devices are connected to the Salt Master.
•	Pending Keys Notifications – If any new minion keys are available to connect, a red badge will appear at the top right corner of the “Manage Devices” button notifying the user of any unaccepted keys.
•	View Pending Keys – Click the “Manage Devices” button to view a list of pending and accepted keys.
•	Accept and Remove Minion Connections – Connected Minion IDs will have a red “Remove” button next to them.  Click the “Remove” button to disconnect this device from the Salt Master.  Pending keys will have a green “Accept” button next to the Minion IDS.  Click “Accept” to connect the minion device.
Script Deployment
The core functionality of the application is deploying Salt functions to connected devices via a device and script list and a “Deploy” button, but several features exist to accommodate for more complex deployments.
•	Select Target Minion Devices – The “Available Devices” list displays the device name and operating system, click a device name to select it or use CTRL + click to select multiple devices.
•	Choose the Script Type – The two radio buttons above the script list allow the user to switch between custom scripts and build in Salt modules.  Custom scripts are user defines and located in the “srv/Salt” folder on the Salt Master server.  Salt modules are Salt’s built in scripts.
•	Select Scripts – In the “Available Scripts” list, the user can choose what scripts to deploy.  Use CTRL + click to select multiple scripts.
•	Search for Scripts – To locate a desired script more quickly use the “Search scripts…” textbox above the script list.  This filters the scripts based on key words or phrases relating to the script’s name.
•	Input Script Arguments – The application automatically detects the necessary arguments for most Salt scripts and allows the user to input each argument into their respective textboxes.  Custom scripts require arguments to be deployed via a single textbox with each argument separated by a comma.  (IMPORTANT! – only one script can be selected at a time when deploying scripts with arguments, otherwise the application will throw an error.)
•	Input Append Commands – Appended commands can be attached to the end of commands using the Append commands text box.
•	Deploy the Scripts – To run the scripts on the selected devices click the “Deploy” button.  The results will appear in the console at the bottom of the screen.
System Monitoring
The System Monitoring section lets the user select a device and view critical information pertaining to the device.  Firewall Rules and Running Processes are the only diagnostics currently available.
•	Select the Device – Use the “Select a device” dropdown to select a device to display data from.
•	Select the Data to Display – Use the “Select View” dropdown menu to select the desired information to display (eg. Firewall Rules or Running Processes)
•	View the Data – The requested information will automatically populate in the System Monitoring area (All views are not available for all operating systems)
Additional Features
•	View the Contents of a Script - The contents of a script can be viewed by right clicking on a custom script and selecting “View”.  This will display the script code in a modal.  (This only works with custom scripts) 
•	Refresh Application – The “Refresh” button reloads the current connection to the Salt Master.  This can be used to update the script list or re-establish the connection.  All contents of the console will be cleared after pressing this button.
