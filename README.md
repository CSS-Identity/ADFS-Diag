# ADFS Diagnostic Tracing

### Important notices
---
The script ( ADFS-tracing.ps1 ) is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Active Directory Federation Services or Web Application Proxy Server. 
The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; computer names and/or user names.

All data generated by the  script will be stored in a designated folder specified by the user at initialization.
Once the tracing has completed, the script will automatically generate a archive file (zip file), with the server name, date and time. Should for some reasons the archive process fail, all data is located in a subfolder (/temporary) in the specified destination folder.

> This Script does not require an Internet Connection and will at no point automatically send data to Microsoft.  
> Any data collected by this script **must only** be sent to Microsoft as part of an active Support Engagement.  
> Any data you want to send to Microsoft **must only** be transfered through a Secure File Transfer.
>  
>  Access to such transfer tools should be provided by the Microsoft support professional assigned to your support incident.
>  Please discuss this with your support professional and also any concerns you may have.
>  
>  https://privacy.microsoft.com/en-us/privacy 

### Script usage
---
##### Requirements:
- the Script supports ADFS on Windows Server 2012R2 / Windows Server 2016 / Windows Server 2019
- local administrator privileges are required to run the scripts at minimum. 
- Preferably the account is also a Domain User
- a miminum of 5GB of free diskspace on the volume for the target folder when running the tracing for a longer period
- on Windows Server 2012R2 it is recommended (but not required) to have the Windows Management Framework 5.1 (WMF) installed
  Some functions used by the script may otherwise generate some errors (These errors do not affect the overall data collection) 
  You can get the WMF from https://www.microsoft.com/en-us/download/details.aspx?id=54616

Download the script and copy the file to the servers that needed to be traced
You can run the script from Powershell ISE or from Powershell Console 

##### Running the Tracing Script interactively:
When executing the Script without any parameters the script will Render a Forms UI and providing you with the following Options:

| Options | Description 
| :--------: | :--------- |
| Configuration Only | In this mode only static data will be exported. This is the default scenario even if not enabled|
| Runtime Tracing  | In this mode the script will collect all data available in Configuration Only and enables additional debug traces for http.sys, schannel, kerberos/ntlm and ADFS and DRS Debug Event Tracing |
| include Network Traces  | This option is only available for a runtime trace and you can opt-in if you want to collect a network trace |
| include Performance Counters  | This option is only available for a runtime trace and you can opt-in to collect ADFS performance counters for the duration of the tracing |
| Textbox/Browse | Provide the path to the Destination folder or alternatively you can use the Filebrowser to select the folder where the data will be stored |


##### Running the script from console:
The script accepts four parameters similar to the UI 
| Options | Value/Description 
| :-------- | :--------- |
| -Path | The absolute path to the folder where the files should be stored. If the parameter is omitted the script will automatically run in interactive mode ignoring the other parameters |
| -TraceEnabled | $true/$false; if omitted the script will prompt you if a network trace should be captured |
| -NetTraceEnabled | $true/$false; if omitted the script will prompt you if a network trace should be captured |
| -PerfCounter | $true/$false; if omitted the script will prompt you if performance counters should be captured |


During runtime and in particular the trace scenario the script will begin pulling initial static data. 
It will Pause the execution to give you the time to configure the other servers, if tracing on multiple machines is required.

Once all servers are prepared for tracing you can resume tracing on each of the servers by following the onscreen instructions by pressing a key or  when using Powershell ISE a Dialog popup should occur. Click OK here.

The script will then display another message to inform you that the data collection/tracing is running.  
At this time perform the steps to REPRODUCE THE ISSUE you want to capture.  
//Try to reproduce the issue as fast you can to keep the size of the data as small as possible

Once the problem has been reproduced once again press a key or click OK in the Dialog to to stop the tracing.

At this point it will take some time collect the remaining data and to compile the debug traces (if Tracing was enabled).  
So **please be patient** and do not abort the script through Task Manager  
You may also see some additional popup windows appearing. Usually they occur for the MSINFO Collection


When the scripts finish, please upload the folder to the workspace provided by the support engineer
