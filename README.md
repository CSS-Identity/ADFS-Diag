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
- on Windows Server 2012R2 it is required to have the Windows Management Framework 5.1 (WMF) aka Powershell 5.0 installed
  You can get the WMF from https://www.microsoft.com/en-us/download/details.aspx?id=54616
  
  !!!A fix adding more compatibility with Powershell 4 on Server 2012R2 is being tested and will be released soon

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




##### Output File Reference:

| Filename | Description |
| ----------- | ----------- |
| AD FS Tracing-Debug.evtx | contains verbose diagnostics like claim processing details and/or exception details |
| AD FS-Admin.evtx |  ADFS Administrative logs containing high level error and informative events |
| Application.evtx | Windows OS Application eventlogs |
| DRS-Admin.evtx | Device Registration Service event logs  |
| Device Registration Service Tracing-Debug.evtx | Device Registration Service diagnostic events |
| Microsoft-Windows-CAPI2-Operational.evtx | Crypto API Events allowing to analys Certificate Validation issues |
| Security.evtx | Security Eventlogs of the Operating System. Size is limited to maximum 1hour or for the duration of a trace session |
| Microsoft-Windows-WebApplicationProxy-Session.evtx | WAP Debug Event logs* |
| Microsoft-Windows-WebApplicationProxy-Admin.evtx | WAP Admin Event logs* |
| System.evtx | System Event logs |
| Hostname-<ADFSBackEnd/ADFSProxy>-perf_<datetime>.blg | Performance Counter informations for the duration of a trace.  |
| Hostname-certutil-v-store-ca.txt | enumeration of the Intermediate Authentication Certificate Store of the computer in verbose  |
| Hostname-certutil-v-store-my.txt | enumeration of the Personal CertificateStore of the computer in Verbose |
| Hostname-certutil-v-store-root.txt | enumeration of the Root CA CertificateStore of the computer in Verbose |
| Hostname-certutil-verifystore-AdfsTrustedDevices-AFTER.txt | enumeration of the ADFSTrustedDevices Store of the computer collected after a trace |
| Hostname-certutil-verifystore-AdfsTrustedDevices-BEFORE.txt | enumeration of the ADFSTrustedDevices Store of the computer collected after a trace |
| Hostname-certutil-verifystore-ca.txt | simple enumeration of the Intermediate Authentication Certificate Store of the computer |
| Hostname-certutil-verifystore-my.txt | simple enumeration of the Personal CertificateStore of the computer |
| Hostname-certutil-verifystore-root.txt | simple enumeration of the Root CA CertificateStore of the computer in Verbose |
| Hostname-certutil-urlcache.txt | output of the Crypto API URLCache of the Admin account |
| Hostname-certutil-v-store-enterprise-ntauth.txt | output of AD NTAUTH Certificate Store |
| Hostname-environment-variables-AFTER.txt | Current System Environment Variables registered |
| Hostname-GPReport.html | Group Policies applied to the user running script and the Computer |
| Hostname-hosts.txt | list Hostfile entries |
| Hostname-ipconfig-all-AFTER.txt | contains TCP/IP  configuration of the network adapters  |
| Hostname-Microsoft.IdentityServer.ServiceHost.Exe.Config | ADFS Service Configuration file |
| Hostname-msinfo32-AFTER.nfo | MSINFO containing various informations about the OS configuration and installed modules/dlls |
| Hostname-netsh-dnsclient-show-state-AFTER.txt | informations about DNSSEC and DirectAccess configuration  |
| Hostname-netsh-http-show-cacheparam.txt | contains http configuration for caching |
| Hostname-netsh-http-show-cachestate.txt | contains http caching status |
| Hostname-netsh-http-show-iplisten.txt | contains http ip listeners if configured  |
| Hostname-netsh-http-show-servicestate.txt | contains a list of currently registered web application endpoints |
| Hostname-netsh-http-show-sslcert.txt | HTTP Binding configuration |
| Hostname-netsh-http-show-timeout.txt | HTTP driver timeout settings |
| Hostname-netsh-http-show-urlacl.txt | URL Reservations in HTTP |
| Hostname-netsh-int-advf-show-global.txt | global firewall setting |
| Hostname-netsh-int-ipv4-show-dynamicport-tcp.txt | IPv4 TCP Port range definition |
| Hostname-netsh-int-ipv4-show-dynamicport-udp.txt | IPv4 UDP Port range definition |
| Hostname-netsh-int-ipv6-show-dynamicport-tcp.txt | IPv6 TCP Port range definition |
| Hostname-netsh-int-ipv6-show-dynamicport-udp.txt | IPv6 TCP Port range definition  |
| Hostname-netsh-winhttp-proxy.txt | output of System Proxy configuration |
| Hostname-netstat-nao-AFTER.txt | contains a list of currently established network connections  |
| Hostname-network.cab | supplemental file created as part of a network trace |
| Hostname-network.etl | contains a network trace collected during a trace session  |
| Hostname-nltest-dsgetdc-USERDNSDOMAIN-AFTER.txt  | output of a domain controller location query  |
| Hostname-nltest-dsgetdc-USERDNSDOMAIN-BEFORE.txt  | output of a domain controller location query |
| Hostname-nslookup-USERDNSDOMAIN-AFTER.txt | will be deprecated ; contains name resolution of the logged on users domain  | 
| Hostname-reg-ciphers_policy_registry.txt | TLS Cipher Configuration deployed via GPOs |
| Hostname-reg-Cryptography_registry.txt | registry export of the TLS/SSL Cryptography config |
| Hostname-reg-NETLOGON-port-and-other-params.txt | export of the netlogon service registry settings  |
| Hostname-reg-NTDS-port-and-other-params.txt | an registry export of NTDS settings properties |
| Hostname-reg-RPC-ports-and-general-config.txt | export of the RPC Client registry config |
| Hostname-reg-schannel.txt | SCHannel configuration parameters; related to TLS/SSL configuration |
| Hostname-reg-schannel_NET_strong_crypto.txt | .NetFramework configuration settings  |
| Hostname-reg-schannel_NET_WOW_strong_crypto.txt | .NetFramework configuration settings |
| Hostname-route-print-AFTER.txt | ip routing configuration of the local machine  |
| Hostname-services-running-AFTER.txt | a list of all currently running services |
| Hostname-tasklist-AFTER.txt | a list of all running tasks  |
| Hostname-WindowsPatches.htm | contains informations about installed Windows Updates |
| dcloc_krb_ntlmauth.etl | contains kerberos and NTLM debug traces in a binary format |
| Get-AdfsAccessControlPolicy.txt | contains list of all Access Control Policies currently defined in ADFS |
| Get-AdfsAdditionalAuthenticationRule.txt | Contains details of global MFA claim Rules if configured |
| Get-AdfsApplicationGroup.txt | summary of configured OAUTH2/OpenID application groups |
| Get-AdfsApplicationPermission.txt | a list of configured application permissions fror Oauth2/OpenID client apps |
| Get-AdfsAttributeStore.txt | a list of configured Attribute stores (AD/LDAP/SQL or custom attribute store providers |
| Get-AdfsAuthenticationProvider.txt | a list of al installed authentication providers |
| Get-AdfsAuthenticationProviderWebContent.txt | contains web customization for Authentication providers if configured |
| Get-ADFSAzureMfaAdapterconfig.txt | an export of the Azure MFA Adaper configuration if configured |
| Get-AdfsCertificate.txt | details of the currently configured Certificates for TokenSigning/Decryption and ServiceCommunication |
| Get-AdfsCertificateAuthority.txt | contains the configuration of the ADFS Certificate Enrollment authority in WHFB scenarios |
| Get-AdfsClaimDescription.txt | a list of all Claims descriptions  |
| Get-AdfsClaimsProviderTrust.txt | detailed configuration information of configured Claims Provider |
| Get-AdfsClaimsProviderTrustsGroup.txt | lists Claims Provider trust groups if configured |
| Get-AdfsClient.txt | lists currently registered Oauth2 CLients  |
| Get-AdfsDeviceRegistration.txt | details of the Device Registration settings |
| Get-AdfsDeviceRegistrationUpnSuffix.txt | contains lists of registered Device Registration Domain Suffixes identically to Get-AdfsRegistrationHosts  |
| Get-AdfsDirectoryProperties.txt | a list of discovered UPN Suffixes/Netbios Names allowed to authenticate (with 2019+) |
| Get-AdfsEndpoint.txt | a list of ADFS endpoints enabled/disabled |
| Get-AdfsFarmInformation.txt | a list of all ADFS Farmnodes in a 2016/2019 Farm deployment |
| Get-AdfsGlobalAuthenticationPolicy.txt | Authentication Handler configuration in ADFS |
| Get-AdfsGlobalWebContent.txt | contains informations about the common ADFS Web customization settings |
| Get-AdfsLocalClaimsProviderTrust.txt | a list of local claims provider (AD builtin and LDAP claims provider) |
| Get-AdfsNativeClientApplication.txt | a list of configured OAuth2/OpenID native client apps  |
| Get-AdfsNonClaimsAwareRelyingPartyTrust.txt | a list of non-claims apps that may be published in WAP |
| Get-AdfsProperties.txt | lists the ADFS Service configuration properties |
| Get-AdfsRegistrationHosts.txt | contains lists of registered Device Registration Domain Suffixes |
| Get-AdfsRelyingPartyTrust.txt | output of all relying party trust applications currently configured |
| Get-AdfsRelyingPartyTrustsGroup.txt | lists the Relying Party Trust Group configuration |
| Get-AdfsRelyingPartyWebContent.txt | lists all Relying Party configured web content customizations  |
| Get-AdfsRelyingPartyWebTheme.txt | contains a list of Relying party associated web themes |
| Get-AdfsScopeDescription.txt | Openid Scope definitions |
| Get-AdfsServerApplication.txt | OAUTH2 Server Application configuration detauls  |
| Get-AdfsSslCertificate.txt | currently bound SSL certificates in HTTP |
| Get-AdfsSyncProperties.txt | Contains information about the ADFS Database Sync status in WID deployments |
| Get-AdfsTrustedFederationPartner.txt | * |
| Get-AdfsWebApiApplication.txt | Oauth2/OpenID web API configuration settings |
| Get-AdfsWebApplicationProxyRelyingPartyTrust.txt | output for the WAP Pre-Authentication relying party configuration  |
| Get-AdfsWebConfig.txt | shows currently active default web theme and cookie settings for HomeRealmDiscovery automation |
| Get-AdfsWebTheme.txt | a list of configured ADFS Web Themes |
| Get-ServicePrincipalNames.txt | Contains details about the ADFS Service Account configuration in AD DS |
| http_trace.etl | http driver trace in binary format |
| netlogon.bak | netlogon debug log backup file (usually created if the log file itself exceeds 100mb during a longer tracing period |
| netlogon.log | netlogon debug log informations |
| schannel.etl | schannel (TLS/SSL provider) debug file in a binary format |
| Get-WebApplicationProxyApplication.txt | Lists the published applications |
| Get-WebApplicationProxyAvailableADFSRelyingParty.txt | list of available relying parties configured on a federation server|
| Get-WebApplicationProxyConfiguration.txt | Global Web Application Proxy settings |
| Get-WebApplicationProxyHealth.txt | Health status of the Web Application Proxy server |
| Get-WebApplicationProxySslCertificate.txt | binding information for the SSL certificate for federation server proxy |
| HOSTNAME-Microsoft.IdentityServer.ProxyService.exe.config | 
| transscript_output.txt | diagnostics/telemetry about the execution of the script |
| LocaleMetaData\ AD FS Tracing-Debug_1033.MTA | ADFS Tracing eventlog in a localized format (system language) |
| LocaleMetaData\ AD FS-Admin_1033.MTA | ADFS Admin eventlog in a localized format (system language)  |
| LocaleMetaData\ Application_1033.MTA | Application eventlog in a localized format (system language)  |
| LocaleMetaData\ Device Registration Service Tracing-Debug_1033.MTA | DRS Tracing eventlog in a localized format (system language)  |
| LocaleMetaData\ DRS-Admin_1033.MTA | DRS Admin eventlog in a localized format (system language)  |
| LocaleMetaData\ Microsoft-Windows-CAPI2-Operational_1033.MTA | CAPI eventlog in a localized format (system language)  |
| LocaleMetaData\ Security_1033.MTA | Security eventlog in a localized format (system language) |
| LocaleMetaData\ System_1033.MTA | System eventlog in a localized format (system language)  |
