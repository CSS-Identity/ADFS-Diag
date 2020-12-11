# ADFS-Diag


======================= IMPORTANT NOTICE =======================

The authentication script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Active Directory Federation Services.
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names.

Once the tracing and data collection has completed, the script will save the data in a subdirectory from where this script is launched, with the server name, date and time.
The directory and subdirectories will contain data collected by the Microsoft CSS AD FS scripts.
This folder and its contents are not automatically sent to Microsoft.
You can send this folder and its contents to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have.

========================= SCRIPT USAGE =========================

1. Create a folder on the machine where the tracing is going to run (the ADFS servers and the ADFS proxies/WAP servers). Example: C:\tracing;

2. Copy the attached file to that folder in all the servers. Remove the .txt extension, leaving only .ps1
Note: The script will capture multiple traces in circular buffers. It will use a temporary folder under the path you provide (Example: C:\tracing\temporary). The temporary folder will be compressed and .zip file left in the path file you selected. In worst case it will require 10-12 GB depending on the workload and the time we keep it running, but usually it's below 2GB.
Consider capturing the data in a period of time with low workload in your ADFS environment;

3. Before collecting traces, close all the applications that are not strictly needed to reproduce the problem. This will avoid capturing unneeded information;

4. Open a PowerShell console with elevated privileges in all the machines, navigate to the C:\tracing folder, and execute the ps1 file attached;
Important: Provide an absolute Path to the script (like "C:\tracing" and not just "tracing" or ".\tracing");

6. The script will prepare itself to start capturing. When you have the script in this prompt in all the servers, just hit any key to start collecting data in all of them. It will then display another message to inform you that it's collecting data. It will wait for another key to be pressed to stop the capture;

7. Perform the steps to REPRODUCE THE ISSUE we want to capture. Do it as quickly as you can;

8. When reproduced, hit any key to stop the capture. Repeat for all the servers. It will take several minutes and some popup windows will appear;

9. When the scripts finish, please upload the zip folder to the workspace;
