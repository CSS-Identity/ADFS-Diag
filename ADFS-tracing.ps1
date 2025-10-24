############################################################################################################
# ADFS troubleshooting - Data Collection
# Supported OS versions: Windows Server 2012 to Server 2025
# Supported role: ADFS on 2012 to 2022, ADFS proxy server (2012) and Web Application Proxy (2012 R2 to 2022)
############################################################################################################

param (
    [Parameter(Mandatory=$false)]
    [string] $Path,

    [Parameter(Mandatory=$false)]
    [switch]$Tracing,

    [Parameter(Mandatory=$false)]
    [switch]$NetworkTracing,

    [Parameter(Mandatory=$false)]
    [switch]$LDAPTracing,

    [Parameter(Mandatory=$false)]
    [switch]$WAPTracing,

    [Parameter(Mandatory=$false)]
    [switch]$PerfTracing
)

##########################################################################
#region Assembly Depencies
Add-Type -AssemblyName System.ServiceProcess
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.IO.Compression.FileSystem

#region Parameters
[Version]$WinVer = [System.Environment]::OSVersion.Version
$IsProxy = ((Get-WindowsFeature -name ADFS-Proxy).Installed -or (Get-WindowsFeature -name Web-Application-Proxy).Installed)

# Event logs
$ADFSDebugEvents = "Microsoft-Windows-CAPI2/Operational","AD FS Tracing/Debug","Device Registration Service Tracing/Debug"
$WAPDebugEvents  = "Microsoft-Windows-CAPI2/Operational","AD FS Tracing/Debug","Microsoft-Windows-WebApplicationProxy/Session"

$ADFSExportEvents = 'System','Application','Security','AD FS Tracing/Debug','AD FS/Admin','Microsoft-Windows-CAPI2/Operational','Device Registration Service Tracing/Debug','DRS/Admin'
$WAPExportEvents  = 'System','Application','Security','AD FS Tracing/Debug','AD FS/Admin','Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-WebApplicationProxy/Admin','Microsoft-Windows-WebApplicationProxy/Session'

#Definition Netlogon Debug Logging
$setDBFlag = 'DBFlag'
$setvaltype = [Microsoft.Win32.RegistryValueKind]::String
$setvalue = "0x2fffffff"

# Netlogon increase size to 100MB = 102400000Bytes = 0x61A8000)
$setNLMaxLogSize = 'MaximumLogFileSize'
$setvaltype2 = [Microsoft.Win32.RegistryValueKind]::DWord
$setvalue2 = 0x061A8000

# Store the original values to revert the config after collection
$orgdbflag = (get-itemproperty -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").$setDBFlag
$orgNLMaxLogSize = (get-itemproperty -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").$setNLMaxLogSize

#ETW Trace providers for SSL,kerberos,ntlm,http.sys
$LogmanOn = 'logman.exe create trace "schannel" -ow -o .\schannel.etl -p {37D2C3CD-C5D4-4587-8531-4696C44244C8} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 1024 -ets',`
'logman create trace "dcloc" -ow -o .\dcloc_krb_ntlmauth.etl -p "Microsoft-Windows-DCLocator" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 1024 -ets',`
'logman update trace "dcloc" -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -ets',`
'logman update trace "dcloc" -p {5BBB6C18-AA45-49B1-A15F-085F7ED0AA90} 0xffffffffffffffff 0xff -ets',`
'logman create trace "minio_http" -ow -o .\http_trace.etl -p "Microsoft-Windows-HttpService" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets',`
'logman update trace "minio_http" -p "Microsoft-Windows-HttpEvent" 0xffffffffffffffff 0xff -ets',`
'logman update trace "minio_http" -p "Microsoft-Windows-Http-SQM-Provider" 0xffffffffffffffff 0xff -ets',`
'logman update trace "minio_http" -p {B3A7698A-0C45-44DA-B73D-E181C9B5C8E6} 0xffffffffffffffff 0xff -ets'

$LogmanOff = 'logman stop "schannel" -ets',`
'logman stop "minio_http" -ets',`
'logman stop "dcloc" -ets'

#ldap debug traces; process filters are set in the function to enable ldap tracing
$ldapetlOn='logman create trace "adfs_ldap" -ow -o .\ldap.etl -p "Microsoft-Windows-ADSI" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets',`
'logman update trace "adfs_ldap" -p "Microsoft-Windows-LDAP-Client" 0xffffffffffffffff 0xff -ets'

$ldapetlOff= 'logman stop "adfs_ldap" -ets'

#Web Application Proxy Traces
$WAPTraceOn = 'logman create trace "WebAppProxy" -ow -o .\wap_trace.etl -p {66C13383-C691-4CF7-B404-7E172E2DC0C2} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets ',`
'logman update trace "WebAppProxy" -p {7B879E0C-83A7-4DCA-8492-063A257D4288} 0xffffffffffffffff 0xff -ets',`
'logman update trace "WebAppProxy" -p {DBD9121B-9FC9-4725-B35D-EC411FC28196} 0xffffffffffffffff 0xff -ets',`
'logman update trace "WebAppProxy" -p {2C7484EA-F1AC-4A4F-8FF0-39222A187F0D} 0xffffffffffffffff 0xff -ets',`
'logman update trace "WebAppProxy" -p {6519B1CA-2DD1-45D8-A53A-34D03B24EF58} 0xffffffffffffffff 0xff -ets'
$WapTraceOff = "logman -stop WebAppProxy -ets" 

#NetworkCapture+genericInternetTraffic
$EnableNetworkTracer = 'netsh trace start scenario=internetServer capture=yes report=disabled overwrite=yes maxsize=500 tracefile=.\%COMPUTERNAME%-network.etl'
$DisableNetworkTracer = 'netsh trace stop'

#Performance Counters
$perfcnt = @{
    ADFSMain        = @{ CounterName = "\AD FS\*";  Type = "ADFSBackend" }
    ADFSCrypto      = @{ CounterName = "\AD FS Cryptographic Counters(*)\*";  Type = "ADFSBackend"  }
    ADFSAttStore    = @{ CounterName = "\AD FS Attribute Store Counters(*)\*"; Type = "ADFSBackend" }
    ADFSDomCount    = @{ CounterName = "\AD FS Domain Connection Counters\*"; Type = "ADFSBackend" }
    ADFSExtAuth     = @{ CounterName = "\AD FS External Authentication Provider Counters\*"; Type = "ADFSBackend" }
    ADFSNode2Node   = @{ CounterName = "\AD FS Inter-node Communication Counters(*)\*"; Type = "ADFSBackend" }
    ADFSLocalClaims = @{ CounterName = "\AD FS Local Claims Provider Connections(*)\*"; Type = "ADFSBackend" }
    WIDDBCounter    = @{ CounterName = '\MSSQL$MICROSOFT##WID:Databases(*)\*'; Type = "WID" }
    ADFSProxy       = @{ CounterName = "\AD FS Proxy\*"; Type="ADFSProxy"}
    WAPPerf         = @{ CounterName = "\Web Application Proxy\*"; Type="ADFSProxy"}
    TCPCounter      = @{ CounterName = "\TCPv4\*"; Type="General"}
    Memory          = @{ CounterName = "\Memory\*"; Type="General"}
    Processor       = @{ CounterName = "\Processor(*)\*"; Type="General"}
    Process         = @{ CounterName = "\Process(*)\*"; Type="General"}
}

#Collection for Additional Files
$Filescollector = 'copy /y %windir%\debug\netlogon.*  ',`
'ipconfig /all > %COMPUTERNAME%-ipconfig-all.txt',`
'nltest /trusted_domains > %COMPUTERNAME%-nltest-trusted_domains.txt',`
'netsh dnsclient show state > %COMPUTERNAME%-netsh-dnsclient-show-state.txt',`
'route print > %COMPUTERNAME%-route-print.txt',`
'netsh advfirewall show global > %COMPUTERNAME%-netsh-int-advf-show-global.txt',`
'netsh int ipv4 show dynamicport tcp > %COMPUTERNAME%-netsh-int-ipv4-show-dynamicport-tcp.txt',`
'netsh int ipv4 show dynamicport udp > %COMPUTERNAME%-netsh-int-ipv4-show-dynamicport-udp.txt',`
'netsh int ipv6 show dynamicport tcp > %COMPUTERNAME%-netsh-int-ipv6-show-dynamicport-tcp.txt',`
'netsh int ipv6 show dynamicport udp > %COMPUTERNAME%-netsh-int-ipv6-show-dynamicport-udp.txt',`
'netsh http show cacheparam > %COMPUTERNAME%-netsh-http-show-cacheparam.txt',`
'netsh http show cachestate > %COMPUTERNAME%-netsh-http-show-cachestate.txt',`
'netsh http show sslcert > %COMPUTERNAME%-netsh-http-show-sslcert.txt',`
'netsh http show iplisten > %COMPUTERNAME%-netsh-http-show-iplisten.txt',`
'netsh http show servicestate > %COMPUTERNAME%-netsh-http-show-servicestate.txt',`
'netsh http show timeout > %COMPUTERNAME%-netsh-http-show-timeout.txt',`
'netsh http show urlacl > %COMPUTERNAME%-netsh-http-show-urlacl.txt',`
'GPResult /f /h %COMPUTERNAME%-GPReport.html',`
'systeminfo > %COMPUTERNAME%-sysinfo.txt',`
'regedit /e %COMPUTERNAME%-reg-NTDS-port-and-other-params.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\parameters',`
'regedit /e %COMPUTERNAME%-reg-NETLOGON-port-and-other-params.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\parameters',`
'regedit /e %COMPUTERNAME%-reg-schannel.txt HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL',`
'regedit /e %COMPUTERNAME%-reg-Cryptography_registry.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography',`
'regedit /e %COMPUTERNAME%-reg-ciphers_policy_registry.txt HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL'

#Enum forDotNetReleases
#https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#version_table
#https://learn.microsoft.com/de-de/lifecycle/products/microsoft-net-framework
$fxversions = @{
        ".NET Framework 4.5 (all OS)"           = 378389
        ".NET Framework 4.5.1 (2012R2)"         = 378675
        ".NET Framework 4.5.1 (Windows other)"  = 378758
        ".NET Framework 4.5.2 (all OS)"         = 379893
        ".NET Framework 4.6 (Win 10)"           = 393295
        ".NET Framework 4.6	(other OS)"         = 393297
        ".NET Framework 4.6.1 (Win 10 1511)"    = 394254
        ".NET Framework 4.6.1 (all OS)"         = 394271
        ".NET Framework 4.6.2 (RS1/2016)"       = 394802
        ".NET Framework 4.6.2 (all OS)"         = 394806
        ".NET Framework 4.7 (Win 10 1703/RS2)"  = 460798
        ".NET Framework 4.7 (all OS)"           = 460805
        ".NET Framework 4.7.1 (Win 10 1709/RS3)"= 461308
        ".NET Framework 4.7.1 (all Other)"      = 461310
        ".NET Framework 4.7.2 (Win10 1803)"     = 461808
        ".NET Framework 4.7.2 (all OS)"         = 461814
        ".NET Framework 4.8 (Win 10 19H1/19H2)" = 528040
        ".NET Framework 4.8 (Win 10 20H1-22H2)" = 528372
        ".NET Framework 4.8 (Win 11/Server22)"  = 528449
        ".NET Framework 4.8 (other OS)"         = 528049
        ".NET Framework 4.8.1 (Win11 2022)"     = 533320
        ".NET Framework 4.8.1 (other OS) "      = 533325
}

#TypeDefinition for interop with native APIs
Add-Type -TypeDefinition @"
    using System;
    using System.Text.RegularExpressions;
    using System.Runtime.InteropServices;

    public enum AccessType
    {
        DefaultProxy = 0,
        NoProxy = 1,
        NamedProxy = 3,
        AutomaticProxy = 4
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINHTTP_PROXY_INFO
    {
        public AccessType AccessType;
        public string Proxy;
        public string Bypass;
    }

    public struct WinhttpCurrentUserIeProxyConfig
    {
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public bool AutoDetect;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
        public string AutoConfigUrl;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
        public string Proxy;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
        public string ProxyBypass;
    }

    public class WinHttp
    {
        [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WinHttpGetDefaultProxyConfiguration(ref WINHTTP_PROXY_INFO config);
        [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WinHttpGetIEProxyConfigForCurrentUser(ref WinhttpCurrentUserIeProxyConfig pProxyConfig);
    }
    [Flags]
    public enum EncTypes
    {
        NULL_DEFAULTS_TO_RC4_HMAC = 0x0,
        DES_CBC_CRC = 0x01,
        DES_CBC_MD5 = 0x02,
        RC4_HMAC = 0x04,
        AES128_CTS_HMAC_SHA1_96 = 0x08,
        AES256_CTS_HMAC_SHA1_96 = 0x10,
        FAST_Supported = 0x10000,
        CompoundIdentity = 0x20000,
        Claims_Supported = 0x40000,
        Sid_Compression_Disabled = 0x80000
    }

    public class KrbEnum
    {
        public static string[] EnumerateKrb(int encType)
        {
        EncTypes  type = (EncTypes)encType;
        string[] result = type.ToString().Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries);
        return result;
        }
    }

"@
#endregion
##########################################################################
#region UI
function filepathvalidformat {
    param (
        $path
    )
    # Regular expression to match a valid filesystem path format
    $filepathreg = '^(?:[a-zA-Z]:\\|\\\\[\d\D]|\.{1,2}\\)([^<>:"\\|?*]+\\)*[^<>:"\\|?*]*$' #'^(?:[a-zA-Z]:\\|\\\\|\.{1,2}\\)([^<>:"\\|?*]+\\)*[^<>:"\\|?*]*$'
    return [regex]::IsMatch($path, $filepathreg)
}

$DisplayText = @(
@{ Text = "This ADFS Tracing script is designed to gather detailed information about your ADFS configuration and related Windows settings. `nIt also offers the ability to collect various debug logs at runtime for issues that need to be actively reproduced or that are not easily detectable through other means. 
The collected data can be provided to a Microsoft support technician for further analysis."}
@{ Text = "`nWhen performing a Debug/Runtime Trace, you have the option to include Network Traces and/or Performance Counters in the data collection if needed to troubleshoot a specific issue."}
@{ Text = "`nThe script will prepare to capture data and will notify the Administrator when the data collection process is ready to begin.`nIt will pause and you  can setup the tracing in the same way."}
@{ Text = "By pressing 'CTRL + Y' the data collecting process on the server. When Tracing multiple servers repeat the procedure and start the tracing on the other nodes as well"}
@{ Text = "The script will display another message to confirm that it is actively capturing data. `nPress 'CTRL + Y' again to stop the data capture.`n"}
@{ Text = "`nNote:"; Style="bold"}
@{ Text = "The Script is not designed to run for extended periods."}
@{ Text = "In most cases, the script will require between 4GB to 10GB of diskspace, depending on the workload and the duration of the trace and size of the eventlogs."}
@{ Text = "The script will capture multiple traces in circular buffers and will use a temporary folder at the specified path (e.g., C:\tracing\temporary)."}
@{ Text = "It's advisable to capture data during periods of low activity in your ADFS environment to minimize impact."}
@{ Text = "The temporary folder will be later compressed into a .zip file and stored at the selected path."}
)

function WriteRichBoxText {
    param (
        [Array]$textElements
    )
     $Description.text=""
    foreach ($element in $textElements) {
        $Description.SelectionStart = $Description.TextLength
        $Description.SelectionLength = 0
        if ($element.Style -eq "bold") {
          $font = New-Object System.Drawing.Font('Arial', 10, [System.Drawing.FontStyle]::Bold)
        } 
        else {
          $font = New-Object System.Drawing.Font('Arial', 10, [System.Drawing.FontStyle]::Regular)
        }
        $Description.SelectionFont = $font
        if (!$element.Color) {
            $element.Color= [System.Drawing.Color]::FromName('black')
        } 
        $Description.SelectionColor = [System.Drawing.Color]::FromName($element.Color)
        $Description.AppendText($element.Text + [Environment]::NewLine)
        $Description.SelectionStart      = 0
    }
}

Function RunDialog {
[System.Windows.Forms.Application]::EnableVisualStyles()

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '800,600'
$Form.text                       = "ADFS Trace Collector"
$Form.TopMost                    = $false
$Form.StartPosition              = 'CenterScreen'
$Form.MaximizeBox                = $false
$Form.MinimizeBox                = $false
$Form.FormBorderStyle            = [System.Windows.Forms.FormBorderStyle]::Fixed3D

# Text field
$Description                     = New-Object system.Windows.Forms.RichTextBox
$Description.Size                = new-object System.Drawing.Size(770, 360)
$Description.multiline           = $true
$Description.location            = New-Object System.Drawing.Point(15,0)
$Description.Font                = 'Arial,10'
$Description.ScrollBars          = 'Vertical'
$Description.ReadOnly            = $true
$Description.DetectUrls          = $true
WriteRichBoxText $DisplayText

$checkBoxWidth = 180 # Width for each checkbox
$xOffset = 10 # Initial X offset for checkbox
$yOffset = 20 # Y offset for aligning checkboxes

$Scenario = New-Object System.Windows.Forms.GroupBox
$Scenario.Text = "Scenario"
$Scenario.Location = New-Object System.Drawing.Point(15, 375) # Positioned below the RichTextBox
$Scenario.Size = new-object System.Drawing.Size(770, 50)
$cScenario = @("Configuration only", "Runtime Tracing")

for ($i = 0; $i -lt $cScenario.Length; $i++) {
    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Text = $cScenario[$i]
    $checkBox.AutoSize = $true
    $checkBox.Location = New-Object System.Drawing.Point(($xOffset + ($i * $checkBoxWidth)), $yOffset)

    switch -Wildcard ($cScenario[$i]) {
      "Configuration only" { Set-Variable -Name cfgonly -Value $checkBox -Force }
      "Runtime Tracing" { Set-Variable -Name TracingMode -Value $checkBox -Force }
      }
    $Scenario.Controls.Add($checkBox)
}
# Options GroupBox
$Options = New-Object System.Windows.Forms.GroupBox
$Options.Text = "Options"
$Options.Location = New-Object System.Drawing.Point(15, 430) # Positioned below the ScenarioGroup
$Options.Size = new-object System.Drawing.Size(480, 50) # Adjust the size as needed 780,50

$cOptions = @("include Network Traces", "include Performance Counter")

for ($i = 0; $i -lt $cOptions.Length; $i++) {
  $checkBox = New-Object System.Windows.Forms.CheckBox
  $checkBox.Text = $cOptions[$i]
  $checkBox.AutoSize = $true
  $checkBox.Enabled= $false
  $checkBox.Location = New-Object System.Drawing.Point(($xOffset + ($i * $checkBoxWidth)), $yOffset)

  switch -Wildcard ($cOptions[$i]) {
    "include Network Traces" { Set-Variable -Name NetTrace -Value $checkBox -Force }
    "include Performance Counter" { Set-Variable -Name perfc -Value $checkBox -Force }
    }
  $Options.Controls.Add($checkBox)
}
##### Advanced Options GroupBox
$aOptions = New-Object System.Windows.Forms.GroupBox
$aOptions.Text = if(!$IsProxy){ "advanced Options (can cause service restarts)"} else { "advanced Options" }
$aOptions.Location = New-Object System.Drawing.Point(500, 430) # Positioned below the ScenarioGroup
$aOptions.Size = new-object System.Drawing.Size(285, 50) # Adjust the size as needed

$caOptions= if(!$IsProxy){ "LDAP Traces" } else { "WAP Traces" }

for ($i = 0; $i -lt $caOptions.count; $i++) {
  $checkBox = New-Object System.Windows.Forms.CheckBox
  $checkBox.Text = $caOptions
  $checkBox.AutoSize = $true
  $checkBox.Enabled= $false
  $checkBox.Location = New-Object System.Drawing.Point(($xOffset + ($i * $checkBoxWidth)), $yOffset)

  switch -Wildcard ($caOptions) {
    "LDAP Traces" { Set-Variable -Name ldapt -Value $checkBox -Force }
    "WAP Traces" { Set-Variable -Name wapt -Value $checkBox -Force }
    }
  $aOptions.Controls.Add($checkBox)
}

#####
$label = New-Object System.Windows.Forms.GroupBox
$label.Text = 'Type a path to the Destination Folder or Click "Browse..." to select the Folder'
$label.Location = New-Object System.Drawing.Point(15,480) # Positioned below the ScenarioGroup
$label.Size = new-object System.Drawing.Size(585, 60) # Adjust the size as needed

#Text Field for the Export Path to store the results
$TargetFolder                    = New-Object system.Windows.Forms.TextBox
$TargetFolder.text               = ""
$TargetFolder.Size               = new-object System.Drawing.Size(470, 30) 
$TargetFolder.location           = New-Object System.Drawing.Point(10,20)
$TargetFolder.Font               = 'Arial,13'

$SelFolder                       = New-Object system.Windows.Forms.Button
$SelFolder.text                  = "Browse..."
$SelFolder.Size                  = new-object System.Drawing.Size(90, 29)
$SelFolder.location              = New-Object System.Drawing.Point(486,20)
$SelFolder.Font                  = 'Arial,10'

$label.Controls.AddRange(@($TargetFolder,$SelFolder))

$Okbtn                           = New-Object system.Windows.Forms.Button
$Okbtn.text                      = "OK"
$Okbtn.Size                      = new-object System.Drawing.Size(70, 30) 
$Okbtn.location                  = New-Object System.Drawing.Point(620,540)
$Okbtn.Font                      = 'Arial,10'
$Okbtn.DialogResult              = [System.Windows.Forms.DialogResult]::OK
$Okbtn.Enabled                   = $false

$cnlbtn                          = New-Object system.Windows.Forms.Button
$cnlbtn.text                     = "Cancel"
$cnlbtn.Size                     = new-object System.Drawing.Size(70, 30) 
$cnlbtn.location                 = New-Object System.Drawing.Point(700,540)
$cnlbtn.Font                     = 'Arial,10'
$cnlbtn.DialogResult             = [System.Windows.Forms.DialogResult]::Cancel

$Form.controls.AddRange(@($Description,$Scenario,$Options,$aOptions,$Okbtn,$cnlbtn,$label))

$cfgonly.Add_CheckStateChanged({ if ($cfgonly.checked) {
                                    $TracingMode.Enabled = $false; 
                                    $NetTrace.Enabled = $false; 
                                    $perfc.Enabled = $false; 
                                    if(!$IsProxy){ $ldapt.Enabled=$false}else {$wapt.Enabled = $false}
                                }
                                else {
                                    $TracingMode.Enabled = $true; $NetTrace.Enabled = $false
                                }
                              })

$TracingMode.Add_CheckStateChanged({ if ($TracingMode.checked){
                                    $cfgonly.Enabled = $false; 
                                    $NetTrace.Enabled = $true;
                                    $NetTrace.Checked = $true; 
                                    $perfc.Enabled = $true; 
                                    if(!$IsProxy){ $ldapt.Enabled=$true}else {$wapt.Enabled = $true}
                                }
                                else {
                                    $cfgonly.Enabled = $true;
                                    $NetTrace.Checked = $false;
                                    $NetTrace.Enabled = $false;
                                    $perfc.Checked = $false; 
                                    $perfc.Enabled = $false;
                                    if(!$IsProxy) { 
                                        $ldapt.Checked = $false;
                                        $ldapt.Enabled = $false;
                                    }
                                    else {
                                        $wapt.Checked = $false;
                                        $wapt.Enabled = $false;
                                    }
                                }
                              })

#For future Versions we may add addional dependencies to the Network Trace.
#$NetTrace.Add_CheckedChanged({ })
$Description.add_LinkClicked({ Start-Process -FilePath $_.LinkText })

$SelFolder.Add_Click({  $FolderDialog = New-Object windows.forms.FolderBrowserDialog
                        $FolderDialog.RootFolder = "Desktop"
                        $FolderDialog.ShowDialog()
                        $TargetFolder.text  = $FolderDialog.SelectedPath
 })

$TargetFolder.Add_TextChanged({ $Okbtn.Enabled = filepathvalidformat $TargetFolder.Text; })
$FormsCompleted = $Form.ShowDialog()

if ($FormsCompleted -eq [System.Windows.Forms.DialogResult]::OK) {
       return New-Object psobject -Property @{
            Path    = $TargetFolder.text
            TraceEnabled = $TracingMode.Checked
            NetTraceEnabled = $NetTrace.Checked
            ConfigOnly = $cfgonly.Checked
            PerfCounter =$perfc.Checked
            LdapTraceEnabled=$ldapt.Checked
            WAPTraceEnabled=$wapt.Checked
        }
        $Form.dispose()
    }
elseif($FormsCompleted -eq [System.Windows.Forms.DialogResult]::Cancel) {
    Write-host "Script was canceled by User" -ForegroundColor Red
    $Form.dispose()
    exit
    }
}

Function Pause { param([String]$Message,[String]$MessageTitle,[String]$MessageC)
   # "ReadKey" not supported in PowerShell ISE.
   If ($psISE) {
      # Show MessageBox UI instead
      $Shell = New-Object -ComObject "WScript.Shell"
      $Shell.Popup($Message, 0, $MessageTitle, 0)|Out-Null
      Return
   }
   #If not ISE we prompt for key stroke
    Write-Host -NoNewline $MessageC -ForegroundColor Yellow
    do {$keyInfo = [Console]::ReadKey($false)} until ($keyInfo.Key -eq 'Y' -and $keyInfo.Modifiers -eq 'Control')
}
#endregion
##########################################################################
#region Functions
Function IsAdminAccount {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function LDAPQuery {
  param(
	[string]$filter,
	[string[]]$att,
    [string]$conn,
    [string]$basedn
  )
    [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("System.Net")| Out-Null

    $c = New-Object System.DirectoryServices.Protocols.LdapConnection ($conn)

    $c.SessionOptions.SecureSocketLayer = $false;
    $c.SessionOptions.Sealing = $true
    $c.SessionOptions.Signing = $true
    $c.AuthType = [System.DirectoryServices.Protocols.AuthType]::Kerberos
    $c.Bind();
    #rather timeout than waiting for too long...
    $c.Timeout=[timespan]::FromSeconds(45)
    
    if([string]::IsNullOrEmpty($basedn)) { 
        $basedn = (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$conn/RootDSE")).DefaultNamingContext 
    }
    
    $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    $r = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList $basedn,$filter,$scope,$att
    
    $re = try { $c.SendRequest($r) } 
          catch { $_.Exception.InnerException }

    $c.Dispose()
    
    return $re
}

function get-Certificatesfromstore {
    param(
      [string]$StoreName
    )
  
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName,[System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $certcollection = $store.Certificates 
    $store.Close()
    
    return $certcollection
}

function Get-CertificatesByStore {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("My", "Root", "CA", "NtAuth", "ADFSTrustedDevices", "ClientAuthIssuer")]
        [string]$StoreName
    )

    $storePath = switch ($StoreName) {
        "My" { [System.Security.Cryptography.X509Certificates.StoreName]::My }
        "Root" { [System.Security.Cryptography.X509Certificates.StoreName]::Root }
        "CA" { 'CA' } # [System.Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority seems to be not working so using the Alias CA instead
        "NtAuth" { 'NtAuth' }
        "ADFSTrustedDevices" { 'ADFSTrustedDevices' }
        "ClientAuthIssuer" { 'ClientAuthIssuer' }
    }

    $certs = get-Certificatesfromstore $storePath
    $mycert = @()

    foreach ($cert in $certs) {
        $obj = New-Object -TypeName PSObject
        $obj | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $cert.Issuer
        if(($cert.FriendlyName)){$obj | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $cert.FriendlyName}
        $obj | Add-Member -MemberType NoteProperty -Name "Subject" -Value $cert.Subject
        $obj | Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $cert.NotAfter
        $obj | Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $cert.NotBefore
        $obj | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $cert.SerialNumber
        $obj | Add-Member -MemberType NoteProperty -Name "ThumbPrint" -Value $cert.Thumbprint

        # PrivateKey and related properties for MY store
        if ($StoreName -eq "My") {
            $obj | Add-Member -MemberType NoteProperty -Name "PrivateKey" -Value $cert.HasPrivateKey
            $obj | Add-Member -MemberType NoteProperty -Name "Exportable" -Value $cert.PrivateKey.CspKeyContainerInfo.Exportable
            $obj | Add-Member -MemberType NoteProperty -Name "ProviderName" -Value $cert.PrivateKey.CspKeyContainerInfo.ProviderName

            $keyspec = (($cert.PrivateKey).CspKeyContainerInfo).KeyNumber
            $keyspecName = switch ($keyspec) {
                "Exchange" { "AT_EXCHANGE" }
                "Signature" { "AT_SIGNATURE" }
                default { "CNG" }
            }
            $obj | Add-Member -MemberType NoteProperty -Name "Keyspec" -Value $keyspecName
        }

        # Root/Non-Root check and origin determination for other stores
        if ($StoreName -ne "My") {
            if ($cert.Subject -ne $cert.Issuer) {
                $obj | Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Non-Root'
            } else {
                $obj | Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Root'
            }

            # Determine the origin based on store type
            $certsrc = $null
            if ($StoreName -eq "NtAuth") {  $obj | Add-Member -MemberType NoteProperty -Name "Origin" -Value 'DirectoryService' } 
            elseif ($StoreName -eq "ADFSTrustedDevices") { $obj | Add-Member -MemberType NoteProperty -Name "Origin" -Value 'ADFS' }
            elseif ($StoreName -eq "ClientAuthIssuer") { $obj | Add-Member -MemberType NoteProperty -Name "Origin" -Value 'Registry' } 
            else {
                $ds = "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\$StoreName\Certificates\" + $cert.Thumbprint
                $gpo = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\$StoreName\Certificates\" + $cert.Thumbprint

                if ([bool](Test-Path $ds)) { $certsrc = "DirectoryService" }
                if ([bool](Test-Path $gpo)) { $certsrc = "GroupPolicy" }
                if (![string]::IsNullOrEmpty($certsrc)) { $obj | Add-Member -MemberType NoteProperty -Name "Origin" -Value $certsrc } 
                else { $obj | Add-Member -MemberType NoteProperty -Name "Origin" -Value 'Registry' }
            }
        }

        $mycert += $obj
    }

    # We check ClientAuthIssuer only if a bidning was configured. An empty store can cause issues so warn.
    if ($StoreName -eq "ClientAuthIssuer" -and $mycert.Count -eq 0) {
        $mycert = "WARNING: ClientAuthIssuers is configured on an ADFS related binding but the Certificate store is empty. This can break Certificate Based authentication for users"
    }

    return $mycert
}

function Test-IsWID {
    # Try to get the SecurityTokenService object
    $sts = Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService -ErrorAction SilentlyContinue

    # Extract the connection string
    $connectionString = $sts.ConfigurationDatabaseConnectionString

    # Determine if it's using WID or SSEE
    $result = $connectionString -match "##wid" -or $connectionString -match "##ssee"

    #if Wid do get the service status
    if ($result) {
        $svc = new-object System.ServiceProcess.ServiceController('MSSQL$MICROSOFT##WID')
    }
    # Return both values as an object
    return [PSCustomObject]@{
        IsWID                                 = $result
        ConfigurationDatabaseConnectionString = $connectionString
        IsWIDStarted                          = $svc.Status
    }
}

function Get-ADFSDBStateFromWID {
      
   $dbconfig = Test-IsWID
   $dbstates = @{}
   
   #skip if not WID exit.
   if (!$dbconfig.IsWID) {
    break
   }

   #check if service is running and if then attempt the query
   if ($dbconfig.IsWidStarted -eq [System.ServiceProcess.ServiceControllerStatus]::Running ) {

   #query on basic DB states and also retrieve the owner of the DB
   #states are:  0 = ONLINE, 1 = RESTORING; 2 = RECOVERING 1; ; 3 = RECOVERY_PENDING 1; 4 = SUSPECT ; 5 = EMERGENCY 1; 6 = OFFLINE 1; 7 = COPYING 2; 10 = OFFLINE_SECONDARY 2; 
    $query=@"
    SELECT
    d.name AS DatabaseName,
    suser_sname(d.owner_sid) AS DatabaseOwner,
    d.state_desc AS DatabaseState,
    d.recovery_model_desc AS RecoveryModel,
    d.is_read_only AS IsReadOnly,
    d.is_broker_enabled AS IsBrokerEnabled,
    d.user_access_desc AS AccessMode
    FROM sys.databases AS d
    WHERE d.name LIKE 'ADFS%'
    ORDER BY d.name;
"@
    try {
        $connection = new-object system.data.SqlClient.SqlConnection($dbconfig.ConfigurationDatabaseConnectionString);
        $connection.Open()
  
        $sqlcmd = $connection.CreateCommand();
        $sqlcmd.CommandText = $query;
        $result = $sqlcmd.ExecuteReader();
        $table = new-object "System.Data.DataTable"
        $table.Load($result)
    
        foreach ($row in $table.Rows) {
            $dbstates[$row.DatabaseName] = @{
            DatabaseState = $row.DatabaseState
            RecoveryModel = $row.RecoveryModel
            IsReadOnly    = $row.IsReadOnly
            AccessMode    = $row.AccessMode
            BrokerEnabled = $row.IsBrokerEnabled
            DBOwner       = $row.DatabaseOwner
            }
        }

    } catch {
        $errMsg = "Failed to connect to or query the ADFS database."
        $inner = $_.Exception

    # Check what kind of failure it was
        if ($inner -is [System.Data.SqlClient.SqlException]) {
            throw [System.Data.SqlClient.SqlException]::new("$errMsg SQL Error: $($inner.Message)")
        }
        elseif ($inner -is [System.InvalidOperationException]) {
            throw [System.Management.Automation.RuntimeException]::new("$errMsg Invalid operation: $($inner.Message)", $inner)
        }
        else {
            throw [System.Exception]::new("$errMsg Unexpected error: $($inner.Message)", $inner)
        }

    } finally {
      # Close and dispose the connection if it exists
        if ($connection.State -eq 'Open') {
            $connection.Close()
        }
        
        $connection.Dispose()
    }
    return $dbstates
    }
}

function get-servicesettingsfromdb {
      param(
    [Parameter(Mandatory=$true)]
    [string]$DBConnectionString
  )
  
    if ([string]::IsNullOrEmpty($DBConnectionString)) {
        $errMsg = "Error: Database connection string is null or empty."
        throw [System.ArgumentException]::new($errMsg)
    }
 
    #Create SQL Connection
    try {
    $connection = new-object system.data.SqlClient.SqlConnection($DBConnectionString);
    $connection.Open()

    $query = "SELECT * FROM IdentityServerPolicy.ServiceSettings"  
    $sqlcmd = $connection.CreateCommand();
    $sqlcmd.CommandText = $query;
    $result = $sqlcmd.ExecuteReader();
    $table = new-object "System.Data.DataTable"
    $table.Load($result)
    [XML]$SSD=  $table.ServiceSettingsData
    } catch {
        $errMsg = "Error: Failed to connect to or query from ADFS Configuration database"
        throw [System.Exception]::new($errMsg,$($_.Exception))
        
    } finally {
        if ($connection.State -eq 'Open') {
            $connection.Close()
        }
        
        $connection.Dispose()
    }

    return $SSD
}

function Get-AzureMFAConfig {
    $dbconfig = Test-IsWID
    #skip if WID is not started as it would definitely fail the query 
    if ($dbconfig.IsWID -and ($dbconfig.IsWidStarted -ne [System.ServiceProcess.ServiceControllerStatus]::Running )) { 
        $errMsg = "Error: WID (Windows Internal Database) service is not running."
        throw [System.Exception]::new($errMsg)
    }
    
    try {
        $ssd = get-servicesettingsfromdb -DBConnectionString $dbconfig.ConfigurationDatabaseConnectionString
    } catch {
        $errMsg = "Error: Reading Azure MFA Configuration failed."
        throw [System.Exception]::new($errMsg,$($_.Exception))
    }
    if(!$null -eq $ssd) { #loop through the AuthAdapters and find the config for AzureMFAAdapter; we might expand this for other adapters if necessary
        foreach ($AmD in $ssd.ServiceSettingsData.SecurityTokenService.AuthenticationMethods.AuthenticationMethodDescriptor) { 
            if ($AmD.Identifier -eq "AzureMfaAuthentication" -and (!$AmD.ConfigurationData.IsEmpty)) {
                return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($AmD.ConfigurationData))
            }
        }
    }
}     

function Get-ADFSAzureMfaAdapterconfig {
#exception format template
$excform=@"
Error: An error occured whilst attempting to read the MFA Adapter Configuration.
{0}
{1}
{2}
"@
    #try to get config and handle the exception if it occurs try to provide as much info as possible and break on error
    Try {
        $MFAraw= Get-AzureMFAConfig       
    } Catch { 
        $errstr= [string]::Format($excform,
                         $_.Exception.Message,
                         $_.Exception.InnerException.Message,
                         $_.Exception.InnerException.InnerException
                        )
        Return $errstr.TrimEnd()
        break
    }
    
    #try to process the config if it was retrieved

    if($null -ne $MFAraw) {
        $obj = [PSCustomObject]@{}
        $obj| Add-Member -MemberType NoteProperty -Name 'AdapterConfig' -Value $MFAraw
    
        if(($MFAraw -as [XML]).ChildNodes.ClientId -ne '981f26a1-7f43-403b-a875-f8b09b8cd720') {
            $obj| Add-Member -MemberType NoteProperty -Name 'Error' -Value 'The configured ClientId is incorrect and does not match the Azure AD MFA ClientId required. Re-run the MFA AdapterConfig and update the ClientID'
        }
        
        $mfacert= (get-childitem Cert:\LocalMachine\my | where-object {$_.Subject -contains "CN="+ ($MFAraw -as [XML]).ChildNodes.TenantId +", OU=Microsoft AD FS Azure MFA"})
            
        if(![string]::IsNullOrEmpty($mfacert)) { 
            $obj| Add-Member -MemberType NoteProperty -Name 'Information' -Value 'A suitable Azure MFA Certificate was found in the store. Verify that the certificate referenced below is properly registered in AzureAD'
            $obj| Add-Member -MemberType NoteProperty -Name 'Subject' -Value $mfacert.Subject
            $obj| Add-Member -MemberType NoteProperty -Name 'Thumbprint' -Value $mfacert.Thumbprint
            $obj| Add-Member -MemberType NoteProperty -Name 'NotAfter' -Value $mfacert.NotAfter
            $obj| Add-Member -MemberType NoteProperty -Name 'NotBefore' -Value $mfacert.NotBefore
        }
        else {
            $mfacert= get-childitem Cert:\LocalMachine\my | where-object { $_.Subject -match 'OU=Microsoft AD FS Azure MFA' }
            if($mfacert.count -eq '0') {
                $obj| Add-Member -MemberType NoteProperty -Name 'Critical' -Value 'There are no Azure MFA Certificates existing in the local machines store'
            }

            if($mfacert.count -eq '1') {
                $obj| Add-Member -MemberType NoteProperty -Name 'Warning' -Value 'A Certificate was found in store but it does not match the TenantId in the configuration'
                $obj| Add-Member -MemberType NoteProperty -Name 'Subject' -Value $mfacert.Subject
                $obj| Add-Member -MemberType NoteProperty -Name 'Thumbprint' -Value $mfacert.Thumbprint
            }

            if($mfacert.count -gt '1') {
                $obj| Add-Member -MemberType NoteProperty -Name 'Warning' -Value 'More than one suitable Certificate was found in store but none of them matches the TenantId in the configuration'
            }
        }
        $adfsreg= Get-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\ADFS"
        $MFAREG = 'StsUrl','SasUrl','ResourceUri'
        
        if ($adfsreg.Property -notcontains 'SasUrl' -and $adfsreg.Property -notcontains 'StsUrl' -and $adfsreg.Property -notcontains 'ResourceUri') { 
            $obj| Add-Member -MemberType NoteProperty -Name 'TenantEnvironment ' -value 'Azure MFA has not been configured for Azure Government and will use the default Public environment.'
        }
        else { 
            $obj| Add-Member -MemberType NoteProperty -Name 'TenantEnvironment ' -value 'Registry Entries for Azure Government have been found. Please review the registy'
            
            foreach ($_ in $MFAREG) {
                if($adfsreg.Property -contains $_) { 
                $obj| Add-Member -MemberType NoteProperty -Name $_ -value $adfsreg.GetValue($_) }
                else { 
                $obj| Add-Member -MemberType NoteProperty -Name $_ -value 'Key does not exist' }
                }
            }
    return $obj
    }
    else { return "Information:  AzureMFA is not configured in this ADFS Farm." }
}

function Get-ProxySettings {
    $proxycfg = [PSCustomObject]@{}

    $IEProxyConfig = New-Object WinhttpCurrentUserIeProxyConfig
    [WinHttp]::WinHttpGetIEProxyConfigForCurrentUser([ref]$IEProxyConfig) |Out-Null

    $WINHTTPPROXY = New-Object WINHTTP_PROXY_INFO
    [WinHttp]::WinHttpGetDefaultProxyConfiguration([ref]$WINHTTPPROXY) |Out-Null

    $proxycfg = @"
IE ProxySetting of current CurrentUser: [$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)]
=============================================================
AutoDetect:          $($IEProxyConfig.AutoDetect)
AutoConfigUrl:       $($IEProxyConfig.AutoConfigUrl)
ProxyName:           $($IEProxyConfig.Proxy)
ProxyBypass:         $($IEProxyConfig.ProxyBypass)

WinHTTP Proxy Setting
=============================================================
AutoDetect:          $($WINHTTPPROXY.AccessType)
ProxyName:           $($WINHTTPPROXY.Proxy)
ProxyBypass:         $($WINHTTPPROXY.Bypass)
"@

    return $proxycfg
}

Function EnableDebugEvents ($events) {
    if($TraceEnabled) {
        	ForEach ($evt in $events) {
	        	$TraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt
        		$TraceLog.IsEnabled = $false
        		$TraceLog.SaveChanges()

	        	if ($TraceLog.LogName -like "*Tracing/Debug*") {
	        		$TraceLog.ProviderLevel = 5
        			$TraceLog.IsEnabled = $true
	        		$TraceLog.SaveChanges()
        		}
        		elseif($TraceLog.IsEnabled -eq $false) {
        			$tracelog.MaximumSizeInBytes = '50000000'
	        		$TraceLog.IsEnabled = $true
	        		$TraceLog.SaveChanges()
	           	}
	        }
    }
    else
    { Write-Host "Debug Event Logging skipped due to selected scenario" -ForegroundColor DarkCyan }
}

Function LogManStart {
    if($TraceEnabled) {
        Push-Location $TraceDir
	        ForEach ($ets in $LogmanOn)
	        {
		    cmd /c $ets |Out-Null
            }
        Pop-Location
    }
    else { Write-Host "ETW Tracing skipped due to selected scenario" -ForegroundColor DarkCyan }
}

Function EnableNetlogonDebug {
    if($TraceEnabled) {
        $key = (get-item -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon")
        $subkey = $key.OpenSubKey("Parameters",$true)
        Write-host "Enabling Netlogon Debug Logging" -ForegroundColor DarkCyan

        $subkey.SetValue($setDBFlag,$setvalue,$setvaltype)

        Write-host "Increasing Netlogon Debug Size to 100 MB" -ForegroundColor DarkCyan
        $subkey.SetValue($setNLMaxLogSize,$setvalue2,$setvaltype2)

        #cleanup and close the write  handle
        $key.Close()
    }
    else { Write-Host "Netlogon Logging skipped due to scenario" -ForegroundColor DarkCyan }
}

Function LogManStop {
    if($TraceEnabled) {
        Push-Location $TraceDir
        ForEach ($log in $LogmanOff) {
	       	cmd.exe /c $log |Out-Null
	    }
        Pop-Location
    }
    else { Write-host "ETW Tracing was not enabled" -ForegroundColor DarkCyan }
}

Function DisableNetlogonDebug {
    if($TraceEnabled) {
        $key = (get-item -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon")
        $subkey = $key.OpenSubKey("Parameters",$true)
        # Configure Keys based on initial configuration; if the keys did not exist we are also removing the keys again. else we set the old value
        if ([string]::IsNullOrEmpty($orgdbflag)) { $subkey.deleteValue($setDBFlag) }
        else { $subkey.SetValue($setDBFlag,$orgdbflag,$setvaltype) }

        if ([string]::IsNullOrEmpty($orgNLMaxLogSize)) { $subkey.deleteValue($setNLMaxLogSize) }
        else { $subkey.SetValue($setNLMaxLogSize,$orgNLMaxLogSize,$setvaltype2) }
        $key.Close()
    }
    else { Write-host "Netlogon logging was not enabled" -ForegroundColor DarkCyan }
}

Function DisableDebugEvents ($events) {
    if($TraceEnabled) {
        ForEach ($evt in $events) {
		    $TraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt
		    if ($TraceLog.IsEnabled -eq $true) {
			    $TraceLog.IsEnabled = $false
			    $TraceLog.SaveChanges()
            }
        }
    }
    else { Write-host "Debug Tracing Eventlogs were not enabled" -ForegroundColor DarkCyan }
}

Function ExportEventLogs {
Param(
		[parameter(Position=0)]
		$events,
		[parameter(Position=1)]
		$RuntimeInMsec
		)

    Push-Location $TraceDir
        ForEach ($evts in $events) {
        $expfilter= '*' #default filter
        #Sec events can be very large; in tracing mode we only  care about the events whilst the trace ran
        #query filter for export is  timebased and calculated on the time the trace collection started and ended + an offset of 5 minutes
        if ($evts -eq 'Security') {
            if($TraceEnabled)
                {
                #"create export filter with : "+$RuntimeInMsec
                $expfilter= '<QueryList>' + '<Query Id="'+0+'" Path="'+$evts+'"><Select Path="'+$evts+'">'+"*[System[TimeCreated[timediff(@SystemTime) &lt;= $RuntimeInMsec]]]"+'</Select></Query></QueryList>'
                }
            else {#only export the last 60 minutes;
                $expfilter= '<QueryList>' + '<Query Id="'+0+'" Path="'+$evts+'"><Select Path="'+$evts+'">'+"*[System[TimeCreated[timediff(@SystemTime) &lt;= 3600000]]]"+'</Select></Query></QueryList>'
                }
        }
		# Replace slashes in the event filename before building the export paths
		$evtx = [regex]::Replace($evts,"/","-")
		$evttarget = $TraceDir +"\"+ $evtx+".evtx"
		$EventSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession
        $EventSession.ExportLog($evts,'Logname',$expfilter,$evttarget)
    }
    Pop-Location
}

function widlogs {
    $widlog="$env:windir\WID\Log"
    $wid = $TraceDir + "\Wid"
    #for the time being we only want to collect the error logs from wid if the cummulative size is less then 25MB was 10 initially
    if ([math]::Round(((Get-ChildItem $widlog -Filter *.log)| Measure-Object -Property Length -sum).sum / 1Mb ,1) -le 25) {
    New-Item -ItemType directory -Path $wid -Force | Out-Null
    foreach ($file in (Get-ChildItem -Path $widlog -Filter *.log) ) {
        Copy-Item ($file.fullname) -Destination $wid
        }
    }
}

Function GatherTheRest {
    Push-Location $TraceDir
    ForEach ($logfile in $Filescollector) {
		cmd.exe /c $logfile | out-null
    }
    Get-ProxySettings | out-file  $env:COMPUTERNAME-ProxySettings.txt
    Get-CertificatesByStore MY| out-file  $env:COMPUTERNAME-Certificates-My.txt
    Get-CertificatesByStore Root| out-file  $env:COMPUTERNAME-Certificates-Root.txt
    Get-CertificatesByStore CA| out-file  $env:COMPUTERNAME-Certificates-CA.txt
    Get-CertificatesByStore NTAuth| out-file  $env:COMPUTERNAME-Certificates-NTAuth.txt
    Get-CertificatesByStore ADFSTrustedDevices| out-file  $env:COMPUTERNAME-Certificates-ADFSTrustedDevices.txt
    
    if(!$IsProxy) {
        Get-Adfssslcertificate|foreach-object {if($_.CtlStoreName -eq "ClientAuthIssuer" ) {Get-CertificatesByStore ClientAuthIssuer| out-file $env:COMPUTERNAME-Certificates-CliAuthIssuer.txt }}
    
    if ( (Test-IsWID).IsWID) {
        widlogs 
        }
    }
    else {
        Get-WebApplicationProxySslCertificate|foreach-object { if($_.CtlStoreName -eq "ClientAuthIssuer" ) {Get-ClientAuthIssuerCertificates| out-file $env:COMPUTERNAME-Certificates-CliAuthIssuer.txt} } 
    }
    
    Get-DnsClientCache |Sort-Object -Property Entry |format-list |Out-File $env:COMPUTERNAME-DNSClient-Cache.txt
    Get-ChildItem env: |Format-Table Key,Value -Wrap |Out-File $env:COMPUTERNAME-environment-variables.txt
    Get-NetTCPConnection|Sort-Object -Property LocalAddress |out-file $env:COMPUTERNAME-NetTCPConnection.txt
    get-service|Sort-Object -Property Status -Descending |Format-Table DisplayName,Status,StartType -autosize | out-file $env:COMPUTERNAME-services-running.txt
    get-process |Sort-Object Id |Format-Table Name,Id, SessionId,WorkingSet -AutoSize |out-file $env:COMPUTERNAME-tasklist.txt
    Get-Content $env:windir\system32\drivers\etc\hosts |out-file $env:COMPUTERNAME-hosts.txt
    ((get-childitem $env:Windir\adfs\* -include *.dll,*.exe).VersionInfo |Sort-Object -Property FileVersion |Format-Table FileName, FileVersion) |out-file $env:COMPUTERNAME-ADFS-fileversions.txt
    VerifyNetFX |format-list | out-file $env:COMPUTERNAME-DotNetFramework.txt
    Get-WindowsUpdateHTMLReport | out-file $env:COMPUTERNAME-WindowsPatches.html

    Pop-Location
}

function Enable-ADFSPerfcounters {

Param(
		[Parameter(Mandatory=$false)]
        [ValidateSet("ADFSProxy", "ADFSBackend")]
		[string]$Scenario,

		[Parameter(Mandatory=$false)]
        [ValidateSet("Create", "Enable", "Disable", "Delete")]
		[string]$Action

		)

    #sanity checks
    if (-not $PSBoundParameters.ContainsKey('Scenario')) {
        "Missing Parameter. You must supply a Scenario. Allowed values: ADFSProxy, ADFSBackend.";
        break;
    }

    if (-not $PSBoundParameters.ContainsKey('Action')) {
        "Missing Parameter. You must supply a Scenario. Allowed values: Create, Enable, Disable, Delete";
        break;
    }

    #Action logic
    switch ($Action) {

        "Create" {  # create the perfcounter collection, we distinguish between WAP and ADFS scenario but always add general counters.
                    $joined=""
                    foreach ($Counter in $perfcnt.Keys) {
                        
                        # add role based counters    
                        if ($perfcnt[$Counter].Type -eq $Scenario) {
                        $format = [string]::Format('"{0}" ',$perfcnt[$Counter].CounterName)
                        $joined +=$format
                        }
                        
                      #add WID counters if WID is used and we are in ADFSBackend scenario
                        if ($perfcnt[$Counter].Type -eq 'WID' -and ( (Test-IsWID).IsWID ) -and ($Scenario -eq 'ADFSBackend')) {
                        $format = [string]::Format('"{0}" ',$perfcnt[$Counter].CounterName)
                        $joined +=$format
                        }

                        ## always add general perf counters
                        if ($perfcnt[$Counter].Type -eq 'General') {
                        $format = [string]::Format('"{0}" ',$perfcnt[$Counter].CounterName)
                        $joined +=$format
                        }
                    }
                    #build the string and return it
                    $result = [String]::Format('Logman.exe create counter {0} -o ".\%COMPUTERNAME%-{0}-perf.blg" -f bincirc -max 512 -v mmddhhmm -c {1} -si 00:00:05',$Scenario,$joined.TrimEnd())
                    return $result
        }
        "Enable" { #Enable the perfcounter collection setting it to running state
            return [string]::Format('Logman.exe start {0}',$Scenario)
        }

        "Disable" { #Disable the perfcounter collection setting it to stopped state
            return [string]::Format('Logman.exe stop {0}',$Scenario)
        }

        "Delete" { #Delete the perfcounter collection
            return [string]::Format('Logman.exe delete {0}',$Scenario)
        }
    }
}

Function EnablePerfCounter {
    if ($TraceEnabled -and $PerfCounter) {
                    
        Write-host "Enabling PerfCounter" -ForegroundColor DarkCyan
        
        if ($IsProxy) { $Scenario='ADFSProxy' } else {$Scenario='ADFSBackend' }

            Push-Location $TraceDir
            cmd /c $(Enable-ADFSPerfcounters $Scenario Create) |Out-Null
            cmd /c $(Enable-ADFSPerfcounters $Scenario Enable) |Out-Null
		    Pop-Location
    }
    else { Write-Host "Performance Monitoring will not be sampled due to selected scenario" -ForegroundColor DarkCyan }
}

Function DisablePerfCounter {
    if ($TraceEnabled -and $PerfCounter) { 
        
        Write-Host "Stopping Performance Monitoring" -ForegroundColor DarkCyan
        
        if ($IsProxy) { $Scenario='ADFSProxy' } else {$Scenario='ADFSBackend' }
        Push-Location $TraceDir
        cmd /c $(Enable-ADFSPerfcounters $Scenario Disable) |Out-Null
        cmd /c $(Enable-ADFSPerfcounters $Scenario Delete) |Out-Null
        Pop-Location
    }
    else { Write-Host "Performance Monitoring was not sampled due to selected scenario" -ForegroundColor DarkCyan }
}

Function EnableNetworkTrace {
    if ($TraceEnabled -and $NetTraceEnabled) {
    Write-host "Starting Network Trace" -ForegroundColor DarkCyan
    Push-Location $TraceDir
    #workaround for trace driver initialization failure on certain intel platforms
    $ns = 'netsh trace start capture=yes report=disabled maxsize=1 tracefile=.\%COMPUTERNAME%-network.etl overwrite=yes'
    cmd /c $ns |Out-Null
    cmd /c $DisableNetworkTracer |Out-Null
    #workaround ends
    cmd /c $EnableNetworkTracer |Out-Null
    Pop-Location
    }
}

Function DisableNetworkTrace {
    if ($TraceEnabled -and $NetTraceEnabled) {
        Write-host "Stopping Network Trace. It may take some time for the data to be flushed to disk. Please be patient`n" -ForegroundColor Yellow
        cmd /c $DisableNetworkTracer |Out-Null
    }
}

Function EnableLDAPTrace {
    if(!$IsProxy) {
        if ($TraceEnabled -and $LdapTraceEnabled) {
        Write-host "Starting LDAP Trace" -ForegroundColor DarkCyan
        #enable per ldap tracing for: powershell/ise; wsmprovhost and the service itself
        New-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\powershell_ise.exe' -Force | Out-Null
        New-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\powershell.exe' -Force | Out-Null
        New-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\Microsoft.IdentityServer.ServiceHost.exe' -Force | Out-Null
        New-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\wsmprovhost.exe' -Force | Out-Null
        
        Push-Location $TraceDir
            ForEach ($log in $ldapetlOn) {
	        cmd.exe /c $log |Out-Null
            }
        Pop-Location
        }
    }
}

Function DisableLDAPTrace {
    if(!$IsProxy) {
        if($TraceEnabled -and $LdapTraceEnabled) {
            Write-Host "Stopping LDAP Tracing" -ForegroundColor DarkCyan
            Push-Location $TraceDir

            ForEach ($log in $ldapetlOff) {
	    	cmd.exe /c $log |Out-Null
	    	}
            Pop-Location
            Remove-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\powershell_ise.exe' -Force | Out-Null
            Remove-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\powershell.exe' -Force | Out-Null
            Remove-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\Microsoft.IdentityServer.ServiceHost.exe' -Force | Out-Null
            Remove-Item 'HKLM:\System\CurrentControlSet\Services\ldap\Tracing\wsmprovhost.exe' -Force | Out-Null
        }
        else { Write-host "LDAP Tracing was not enabled" -ForegroundColor DarkCyan }
    }
}

Function EnableWAPTrace {
    if($IsProxy) {
        if ($TraceEnabled -and $WAPTraceEnabled) {
            Write-host "Starting WAP Tracing" -ForegroundColor DarkCyan
            Push-Location $TraceDir
            ForEach ($log in $WAPTraceOn) {
	        cmd.exe /c $log |Out-Null
            }

            Pop-Location
        }
    }
}

Function DisableWAPTrace {
    if($IsProxy) {
        if($TraceEnabled -and $WAPTraceEnabled) {
            Write-Host "Stopping WAP Tracing" -ForegroundColor DarkCyan
            Push-Location $TraceDir

            ForEach ($log in $WapTraceOff) {
	    	cmd.exe /c $log |Out-Null
	    	}

            Pop-Location
        }
        else { Write-host "WAP Tracing was not enabled" -ForegroundColor DarkCyan }
    }
}

function  Test-KRBEncTypePolicy {
    # Specify the registry key path and the value name
    $keyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"
    $valueName = "SupportedEncryptionTypes"
    #by default all Enctypes are enabled .This may change in future we assume defaults unless a policy is configured
    $EncType = 31

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($keyPath)

    #if policy key exists try to get the value
    if (($key.Name)) {
        if ($key.GetValueNames() -icontains $valueName) {
            try {
                [int]$EncType= $key.GetValue($valueName);
                #close key handle when done
                $key.Close()
                }
            catch { 
                #regvalue is not defined only thing we want to do is to close key handle
                $key.Close()
            }  
        }
    }

    #do we still need to look into the classic path  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters ? 
    #if yes we will loop it in here.
    
    #desktop GPO allows to configure ETypes only and FutureFlags. if the value is greater than 0x1f in GPO we must expect that Futureflags had been set
    #remove the futureflag from enumeration

    if ($EncType -gt 31) {
        $EncType = $EncType - 2147483616
    }
    #watch out if there is someone configuring the regkeys manually instead via GPO then it might be they use wrong or negative values
    #we add error handling for such cases if we get reports such a misconfig is placed. Maybe we simply add the raw regkey exports
    # finally convert to enum and return
   return ([KrbEnum]::EnumerateKrb($EncType))

}

function Get-ServiceAccountDetails {
    #initialize  object to store the result: gsad is the accronym of the function name ( g = get, sa = service account, d = details )
    $gsad = New-Object -TypeName PSObject

    #only execute if we are not on proxy/wap
    if (!$IsProxy) {
        #get currently config service account if this fails
        try {
            $SVCACC = ((get-wmiobject win32_service -Filter "Name='adfssrv'").startname)
        } catch {
            $gsad | Add-Member -MemberType NoteProperty -Name "ADFS Service Account" -Value "Error: Failed to retrieve ADFS Service Account from Service Controll Manager. The AD FS Role may not be installed. Skipping Service Account checks."
            return $gsad
        }

        if (!$SVCACC) {
            #this would be unexpected as the service account is mandatory for a service to run unless someone deleted the service account from service config/registry
            $gsad | Add-Member -MemberType NoteProperty -Name "ADFS Service Account" -Value "Error: No ADFS Service Account configured. This is unexpected and could mean the service account was removed from the service configuration in Windows(Registry)."
            return $gsad
        } else {
            $gsad | Add-Member -MemberType NoteProperty -Name "ADFS Service Account" -Value $SVCACC 
        }

        #detect name format UPN vs Legacy
        if ($SVCACC.contains('@')) {
            $filter ="(userprincipalname="+$SVCACC+")"
            $domain = $SVCACC.Split('@')[1]
        }
        
        if ($SVCACC.contains('\')) {
            $filter ="(samaccountname="+$SVCACC.Split('\')[1]+")"
            $domain = $SVCACC.Split('\')[0]
        }
        
    $conn= (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain/RootDSE")).dnshostname
    [string]$att = "*"

    #Performing LDAP Lookup of ADFS Service Account
    $re= LDAPQuery -filter $filter -att $att -conn $conn
    #1st test if its a GMSA 
    $gmsa =$false

    if(($re.GetType().Name -eq 'SearchResponse') -and ($re.Entries.Count -eq 1)) {
        $gmsa = [Bool]($re.Entries.Attributes.objectclass.GetValues('string') -eq 'msDS-GroupManagedServiceAccount')
        $gsad | Add-Member -MemberType NoteProperty -Name "IsManagedServiceAccount" -Value $gmsa

        if($gmsa -eq $true) {
            $adl = new-object System.DirectoryServices.ActiveDirectorySecurity
            $adl.SetSecurityDescriptorBinaryForm($re.Entries[0].Attributes.'msds-groupmsamembership'[0])
            $gsad | Add-Member -MemberType NoteProperty -Name "GMSA allowed Hosts" -value ($adl.AccessToString)
        }
        #try reading the SPN configuration from the service account
        try { 
           $gsad | Add-Member -MemberType NoteProperty -Name "OnAccountRegisteredSPN" -Value ($re.Entries.Attributes.serviceprincipalname.GetValues('string'))
        } catch { 
            #we failed to read the SPN value and must assume there is no SPN configured for this service account
            if ($_.FullyQualifiedErrorID -eq 'InvokeMethodOnNull' ) {
                $gsad | Add-Member -MemberType NoteProperty -Name "OnAccountRegisteredSPN" -Value "ERROR: No SPNs are configured for this Service Account."
            }
        }

        #whilst we are at it try and get the kerberos encryption type value if there is one configured
        Try { 
            $EncType= [int]::Parse($re.Entries[0].Attributes.'msds-supportedencryptiontypes'.GetValues('string')) 
        } Catch { 
        #if we dont find a configured value we must assume its not set so lets use -1 explicitly
            $EncType=-1
        }

    } else {
        if ($re.Response.ResultCode -eq "NoSuchObject") {
            $gsad | Add-Member -MemberType NoteProperty -Name "ServiceAccount query failed" -value "Service Account not found. Ldap Error:`r`n$($re.Response.ErrorMessage)"
        } else {
            $gsad | Add-Member -MemberType NoteProperty -Name "ServiceAccount query failed" -value "Unable to resolve the Service Account. Use AD tools like 'setspn' or 'dsa.msc' to verify the Account exists in AD."
        }
        # if we failed to find the account use -2 so we later dont call enum but log appropropriate message
        $EncType=-2
    }
    
    #refined the Dupe SPN check to not only rely on get-ADFSProperties alone for building the SPN query...this may not work in all cases
    #we now go by the order: http hostname binding -> ADFS Properties -> lastly directly from database
    $hostname = Get-Adfssslcertificate | foreach-object { 
                $temphost = @()
                #we filter out the localhost, classic CBA endpoing on 49443,so should  end up with only one hostname. 
                if( ($_.PortNumber -eq 443) -and ($_.AppId -eq '5d89a20c-beab-4389-9447-324788eb944a') -and ($_.HostName -inotlike 'localhost') ) { 
                    $temphost += ($_.HostName)
                }
        
                if ($temphost.count -eq 1 ) { 
                    return $temphost
                }
               }
    
    #hostname may still be empty so we may have failed to find the bindings.
    #let assume ADFS service is running and we can query adfsproperties from powershell
    if ($null -eq $hostname ) {
        try {  
            $hostname = (get-adfsproperties).hostname 
        } catch { }
    }

    # if still no hostname last attempt to get the farmname is from DB 
    # this is best effort here since we may not be able to connect to DB if SQL is used and account has no logon rights/is not a DBA
    # or if WID but we are not local admin respectively WID may not be started or no DB exists like on initial setup
    if ($null -eq $hostname ) {
        try {
            $hostname = (get-servicesettingsfromdb).ServiceSettingsData.SecurityTokenService.Host.Name
        } catch {}
    }

    #if we have a hostname lets attempt to perform a check for duplicate SPNs
    #first check create the connection object. Use GlobalCatalog as we may have a dupe in a child domain of the forest
    if (!($null -eq $hostname )) {
        $gconn= (New-Object System.DirectoryServices.DirectoryEntry("GC://$domain/RootDSE")).dnshostname
        $filter= [string]::format("(serviceprincipalname=*/{0})", $hostname ) 
        [string]$att = "*"
    }
    
    #if we dont have a hostname we dont create the ldap connection and filter so we dont need to run the query after all
    if (!($null -eq $gconn)) {
        
        $re= LDAPQuery -filter $filter -att $att -conn $gconn
    
        if ($re.GetType().Name -eq 'SearchResponse' -And ($re.entries.count -ge 1)) {
            $obj= $re.Entries | ForEach-Object { 
                                [String]::Format("`r`nAccount: {0}`r`nSPNs : {1}`n",
                                            $_.distinguishedName ,  
                                            ($_.Attributes.'serviceprincipalname'.GetValues('string') -join " ; ") )
                                            }
            $gsad | Add-Member -MemberType NoteProperty -Name "Duplicate SPN" -Value $obj
        } else {
            $gsad | Add-Member -MemberType NoteProperty -Name "Duplicate SPN" -Value "Warning: Duplicate SPN check failed.`r`nThe query may have timed-out or may have returned no results.`r`nYou can use 'setspn.exe -f -q */$($hostname)' to query for duplicate SPN's in the forest.`r`n."
        }

    }

    #Finally validate that Kerberos Etype Config is sound and we have a matching config between OS and Service Account
    #some message strings
    $RC4NotSetMsg="The Service Account is not configured for AES support. Service tickets will be RC4 encrypted!
    `r`nWe recommend configuring the ADFS Service Account for AES Support.`r`nIn Active Directory configure the attribute 'msds-supportedencryptiontypes' for the ADFS ServiceAccount with a value of:`r`n24(decimal) => AES only `n or `n28(decimal) => AES & RC4" 
    
    $RC4NoPolicysupMsg="The ADFS service account is not configured properly. Local policy/registry for KerberosEncryptionTypes disabled RC4 support,`r`nbut the service account has not been configured for AES support.
    `r`nThis configuration can lead to authentication failures and other erroneous behavior and MUST be corrected.
    `r`nWe recommend configuring the ADFS Service Account for AES Support.`r`nIn Active Directory configure the attribute 'msds-supportedencryptiontypes' for the ADFS ServiceAccount with a value of:`r`n24(decimal) => AES only `n or `n28(decimal) => AES & RC4" 

    
    #get KrbConfig from OS Policy
    $HostKrbCfg = Test-KRBEncTypePolicy 

    #theoretically this cannot be null unless the module failed
    if (!($null -eq $HostKrbCfg)) {
         $gsad | Add-Member -MemberType NoteProperty -Name "KrbEtype from OS (Policy)" -Value $($HostKrbCfg -join " | ") 
    }

    #check etypes from ServiceAccountQuery if not set or explicitly 0 default to RC4
    #if we failed to find service account previously..skip etype config evaluation

    switch ($EncType) {   
        0  { $SvcKrbCfg = "RC4_HMAC"; 
             $gsad | Add-Member -MemberType NoteProperty -Name "KrbEtype from ServiceAccount" -Value "explicitly set to 0. Defaulting to RC4_HMAC"  
           } 
        -1 { $SvcKrbCfg = "RC4_HMAC";
             $gsad | Add-Member -MemberType NoteProperty -Name "KrbEType from ServiceAccount" -Value "not configured. Defaulting to RC4_HMAC"  
           }
        -2 { #we failed to find service account previously..nothing to evaluate here
             $gsad | Add-Member -MemberType NoteProperty -Name "KrbEType from ServiceAccount" -Value "Failed to enumerate ServiceAccount"  
           }  
        default { $SvcKrbCfg = [KrbEnum]::EnumerateKrb($EncType) 
                  $gsad | Add-Member -MemberType NoteProperty -Name "KrbEType from ServiceAccount" -Value $($SvcKrbCfg -join " | ")
                } 
    }

    if (!($null -eq $HostKrbCfg) -and !($null -eq $SvcKrbCfg)) {
        $commonItems = [System.Linq.Enumerable]::Intersect(
                       [System.Collections.Generic.List[object]]@($SvcKrbCfg),
                       [System.Collections.Generic.List[object]]@($HostKrbCfg)
                       )
    }
    
    #we have intersection and AES is listed --> AES is used
    if ($commonItems.Count -gt 0 -and $commonItems -like "*AES*") {
        $gsad | Add-Member -MemberType NoteProperty -Name "Kerberos EncryptionType expected" -Value "AES"

    #we have intersection but not AES but RC4 or maybe even weaker ..log warning and recommend AES
    } elseif ( $commonItems.Count -gt 0 -and ($commonItems -notlike "*AES*") ) {
        $gsad | Add-Member -MemberType NoteProperty -Name "KrbEType expected" -Value "RC4"
        $gsad | Add-Member -MemberType NoteProperty -Name "Warning" -Value $RC4NotSetMsg
    
    #no intersection at all. This does not look good and auth will break . log error
    } elseif ( $null -eq $commonItems.Count -and ($SvcKrbCfg -like "*RC4*") -and ($HostKrbCfg -notlike "*RC4*") ) {
        $gsad | Add-Member -MemberType NoteProperty -Name "KrbEType expected" -Value "RC4"
        $gsad | Add-Member -MemberType NoteProperty -Name "Error" -Value $RC4NoPolicysupMsg

    #we should only get here if we have no Service Account queried (notFound/NotExisting)
    }  else  {
        $gsad | Add-Member -MemberType NoteProperty -Name "KrbEType expected" -Value "Cannot predict KrbEType usage. A previous query failed"

    }

   }

   Return $gsad
}

Function GetADFSConfig {
    
    Push-Location $TraceDir
    if ($IsProxy) { # ADFS proxy 2012
	    if ($WinVer -eq [Version]"6.2.9200" ) {
		    Get-AdfsProxyProperties | format-list * | Out-file "Get-AdfsProxyProperties.txt"
	    }
	    else { # ADFS 2012 R2 or ADFS 2016 or 2019
		    Get-WebApplicationProxyApplication | format-list * | Out-file "Get-WebApplicationProxyApplication.txt"
		    Get-WebApplicationProxyAvailableADFSRelyingParty | format-list * | Out-file "Get-WebApplicationProxyAvailableADFSRelyingParty.txt"
		    Get-WebApplicationProxyConfiguration | format-list * | Out-file "Get-WebApplicationProxyConfiguration.txt"
		    Get-WebApplicationProxyHealth | format-list * | Out-file "Get-WebApplicationProxyHealth.txt"
		    Get-WebApplicationProxySslCertificate | format-list * | Out-file "Get-WebApplicationProxySslCertificate.txt"
            copy-item -path "$env:windir\ADFS\Config\Microsoft.IdentityServer.ProxyService.exe.config" -Destination $TraceDir
		}
    }
    else {
  	    # Common ADFS commands to all version
        if ((Get-AdfsSyncProperties).Role -eq 'PrimaryComputer') {
        Get-AdfsAttributeStore | format-list * | Out-file "Get-AdfsAttributeStore.txt"
	    Get-AdfsCertificate | format-list * | Out-file "Get-AdfsCertificate.txt"
	    Get-AdfsClaimDescription | format-list * | Out-file "Get-AdfsClaimDescription.txt"
	    Get-AdfsClaimsProviderTrust | format-list * | Out-file "Get-AdfsClaimsProviderTrust.txt"
	    Get-AdfsEndpoint | format-list * | Out-file "Get-AdfsEndpoint.txt"
	    Get-AdfsProperties | format-list * | Out-file "Get-AdfsProperties.txt"
	    Get-AdfsRelyingPartyTrust | format-list * | Out-file "Get-AdfsRelyingPartyTrust.txt"
        }

	    Get-AdfsSyncProperties | format-list * | Out-file "Get-AdfsSyncProperties.txt"
	    Get-AdfsSslCertificate | format-list * | Out-file "Get-AdfsSslCertificate.txt"
        Get-ServiceAccountDetails | format-list * | Out-file "Get-ServiceAccountDetails.txt"

	if ($WinVer -ge [Version]"10.0.14393") 
	    {# ADFS commands specific to ADFS 2016,2019,2022
        if((Get-AdfsSyncProperties).Role -eq 'PrimaryComputer')
        {
        Get-AdfsAccessControlPolicy | format-list * | Out-file "Get-AdfsAccessControlPolicy.txt"
		Get-AdfsApplicationGroup | format-list * | Out-file "Get-AdfsApplicationGroup.txt"
		Get-AdfsApplicationPermission | format-list * | Out-file "Get-AdfsApplicationPermission.txt"
		Get-AdfsCertificateAuthority | format-list * | Out-file "Get-AdfsCertificateAuthority.txt"
		Get-AdfsClaimsProviderTrustsGroup | format-list * | Out-file "Get-AdfsClaimsProviderTrustsGroup.txt"
		Get-AdfsFarmInformation | format-list * | Out-file "Get-AdfsFarmInformation.txt"
		Get-AdfsLocalClaimsProviderTrust | format-list * | Out-file "Get-AdfsLocalClaimsProviderTrust.txt"
		Get-AdfsNativeClientApplication | format-list * | Out-file "Get-AdfsNativeClientApplication.txt"
		Get-AdfsRegistrationHosts | format-list * | Out-file "Get-AdfsRegistrationHosts.txt"
		Get-AdfsRelyingPartyTrustsGroup | format-list * | Out-file "Get-AdfsRelyingPartyTrustsGroup.txt"
		Get-AdfsScopeDescription | format-list * | Out-file "Get-AdfsScopeDescription.txt"
		Get-AdfsServerApplication | format-list * | Out-file "Get-AdfsServerApplication.txt"
		Get-AdfsTrustedFederationPartner | format-list * | Out-file "Get-AdfsTrustedFederationPartner.txt"
		Get-AdfsWebApiApplication | format-list * | Out-file "Get-AdfsWebApiApplication.txt"
		Get-AdfsAdditionalAuthenticationRule | format-list * | Out-file "Get-AdfsAdditionalAuthenticationRule.txt"
		Get-AdfsAuthenticationProvider | format-list * | Out-file "Get-AdfsAuthenticationProvider.txt"
		Get-AdfsAuthenticationProviderWebContent | format-list * | Out-file "Get-AdfsAuthenticationProviderWebContent.txt"
		Get-AdfsClient | format-list * | Out-file "Get-AdfsClient.txt"
		Get-AdfsGlobalAuthenticationPolicy | format-list * | Out-file "Get-AdfsGlobalAuthenticationPolicy.txt"
		Get-AdfsGlobalWebContent | format-list * | Out-file "Get-AdfsGlobalWebContent.txt"
		Get-AdfsNonClaimsAwareRelyingPartyTrust | format-list * | Out-file "Get-AdfsNonClaimsAwareRelyingPartyTrust.txt"
		Get-AdfsRelyingPartyWebContent | format-list * | Out-file "Get-AdfsRelyingPartyWebContent.txt"
		Get-AdfsWebApplicationProxyRelyingPartyTrust | format-list * | Out-file "Get-AdfsWebApplicationProxyRelyingPartyTrust.txt"
		Get-AdfsWebConfig | format-list * | Out-file "Get-AdfsWebConfig.txt"
		Get-AdfsWebTheme | format-list * | Out-file "Get-AdfsWebTheme.txt"
        Get-AdfsRelyingPartyWebTheme | format-list * | Out-file "Get-AdfsRelyingPartyWebTheme.txt"
        }
        copy-item -path "$env:windir\ADFS\Microsoft.IdentityServer.ServiceHost.Exe.Config" -Destination $TraceDir
        Get-ADFSAzureMfaAdapterconfig |format-list | Out-file "Get-ADFSAzureMfaAdapterconfig.txt"

        ##comming soon: WHFB Cert Trust Informations
        if ($WinVer -ge [Version]"10.0.17763") { #ADFS command specific to ADFS 2019+
            if((Get-AdfsSyncProperties).Role -eq 'PrimaryComputer') {
            Get-AdfsDirectoryProperties | format-list * | Out-file "Get-AdfsDirectoryProperties.txt"
            }
        }

		}
	    if ($WinVer -eq [Version]"6.3.9600") {# ADFS commands specific to ADFS 2012 R2/consolidate this in next release
	        Get-AdfsAdditionalAuthenticationRule | format-list * | Out-file "Get-AdfsAdditionalAuthenticationRule.txt"
		    Get-AdfsAuthenticationProvider | format-list * | Out-file "Get-AdfsAuthenticationProvider.txt"
		    Get-AdfsAuthenticationProviderWebContent | format-list * | Out-file "Get-AdfsAuthenticationProviderWebContent.txt"
		    Get-AdfsClient | format-list * | Out-file "Get-AdfsClient.txt"
		    Get-AdfsGlobalAuthenticationPolicy | format-list * | Out-file "Get-AdfsGlobalAuthenticationPolicy.txt"
		    Get-AdfsGlobalWebContent | format-list * | Out-file "Get-AdfsGlobalWebContent.txt"
		    Get-AdfsNonClaimsAwareRelyingPartyTrust | format-list * | Out-file "Get-AdfsNonClaimsAwareRelyingPartyTrust.txt"
		    Get-AdfsRelyingPartyWebContent | format-list * | Out-file "Get-AdfsRelyingPartyWebContent.txt"
		    Get-AdfsWebApplicationProxyRelyingPartyTrust | format-list * | Out-file "Get-AdfsWebApplicationProxyRelyingPartyTrust.txt"
		    Get-AdfsWebConfig | format-list * | Out-file "Get-AdfsWebConfig.txt"
		    Get-AdfsWebTheme | format-list * | Out-file "Get-AdfsWebTheme.txt"
            copy-item -path "$env:windir\ADFS\Microsoft.IdentityServer.ServiceHost.Exe.Config" -Destination $TraceDir
	    }
	    elseif ($WinVer -eq [Version]"6.2.9200") { # No specific cmdlets for this version 
        }
    }
    Pop-Location
}

Function EndOfCollection {
    $date = get-date -Format yyyy-dd-MM_hh-mm
    $computername = (Get-Childitem env:computername).value
    $zip = $computername + "_ADFS_traces_"+$date
    $datafile = "$(Join-Path -Path $path -ChildPath $zip).zip"
    Stop-Transcript |Out-Null
    Write-host "Creating Archive File" -ForegroundColor Green

    [System.IO.Compression.ZipFile]::CreateFromDirectory($TraceDir, $datafile)

    Write-host "Archive File created in $datafile" -ForegroundColor Green

    # Cleanup the Temporary Folder (if error retain the temp files)
    if(Test-Path -Path $Path) {
		Write-host "Removing Temporary Files" -ForegroundColor Green
		Remove-Item -Path $TraceDir -Force -Recurse | Out-Null
    }
    else {
		Write-host "The Archive could not be created. Keeping Temporary Folder $TraceDir" -ForegroundColor Yellow
		New-Item -ItemType directory -Path $Path -Force | Out-Null
    }
}

Function GetDRSConfig {
    if ((-Not $IsProxy) -And ($WinVer -gt [Version]"6.2.9200"))	{
		Push-Location $TraceDir
		Get-AdfsDeviceRegistrationUpnSuffix | format-list * | Out-file "Get-AdfsDeviceRegistrationUpnSuffix.txt"
		Try { $drs= Get-AdfsDeviceRegistration; $drs| Out-file "Get-AdfsDeviceRegistration.txt" }  Catch { $_.Exception.Message | Out-file "Get-AdfsDeviceRegistration.txt" }

            $dse = (New-Object System.DirectoryServices.DirectoryEntry("LDAP://"+(Get-WmiObject -Class Win32_ComputerSystem).Domain+"/RootDSE"))
            $conn= $dse.dnsHostName
            $basednq = "CN=DeviceRegistrationService,CN=Device Registration Services,CN=Device Registration Configuration,CN=Services," +$dse.configurationNamingContext
            $filter= "(objectClass=*)"
            $re= LDAPQuery -filter $filter -att $att -conn $conn -basedn $basednq
            if($re.GetType().Name -eq 'SearchResponse') {
             $DScloudissuerpubliccert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
              $DSissuerpubliccert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
              try{$DScloudissuerpubliccert.Import($re.Entries.Attributes.'msds-cloudissuerpubliccertificates'.GetValues('byte[]')[0])}catch{}
              try{$DSissuerpubliccert.Import($re.Entries.Attributes.'msds-issuerpubliccertificates'.GetValues('byte[]')[0]) }catch{}

              "DRS Cloud Issuer Certificate`nThumbprint:"+ $DScloudissuerpubliccert.Thumbprint + "`nIssuer:" +$DScloudissuerpubliccert.Issuer |Out-File Get-AdfsDeviceRegistration.txt -Append
              "`nDRS Onprem Issuer Certificate`nThumbprint:"+ $DSissuerpubliccert.Thumbprint + "`nIssuer:" +$DSissuerpubliccert.Issuer |Out-File Get-AdfsDeviceRegistration.txt -Append
		    }
            else { "DRS Service Object search failed: "+$re.Message |Out-File Get-AdfsDeviceRegistration.txt -Append }

		pop-location
	}
}

function netfxversion {
    $fx=[PSCustomObject]@{};
    $fx| Add-Member -MemberType NoteProperty -Name 'Release' -Value ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release)
    foreach ($fxver in ($fxversions.GetEnumerator() | Sort-Object -Property Value )) { 
        if (($fx.Release -eq $fxver.Value) -ne 0) { 
            $fx | Add-Member -MemberType NoteProperty -Name 'Version' -Value ($fxver.Key.ToString()) 
        } 
    }

    if ($fx.Release -ilt [int]394802) { 
        $fx | Add-Member -MemberType NoteProperty -Name 'Lifecyclestate' -Value 'no longer supported. Please Update to at minimum .Net 4.6.2' 
    }
    else { $fx | Add-Member -MemberType NoteProperty -Name 'Lifecyclestate' -Value 'supported' }
  return $fx
}

function VerifyNetFX {
    $nfx = [PSCustomObject]@{}
    $cSP = [Net.ServicePointManager]::SecurityProtocol
    $SUSC= switch ((get-itemproperty -PATH "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SchUseStrongCrypto)
    {   $null {"not configured"} 0 {" explicitly disabled by registry value (0)"} 1 {"explictly enabled by registry"}  }
    $SDTV= switch ((get-itemproperty -PATH "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SystemDefaultTlsVersions)
    {   $null {"not configured"} 0 {" explicitly disabled by registry value (0)"} 1 {"explictly enabled by registry"}  }

    $fxr = netfxversion

$nfx | Add-Member -MemberType NoteProperty -Name '.Net-Release' -Value ([String]::Format([CultureInfo]::InvariantCulture, "{0} {1} is {2}.", $fxr.Release,$fxr.Version,$fxr.Lifecyclestate))
    if (($cSP -split ', ' ) -contains 'TLS12' -or ($cSP -split ', ' ) -contains 'SystemDefault') {
        $nfx | Add-Member -MemberType NoteProperty -Name 'ServicePoint' -Value ("SSL/TLS Protocols available: " + $cSP)
        $nfx | Add-Member -MemberType NoteProperty -Name 'Information' -Value ("The Script detected that StrongCrypto is enabled`neither by default (2019 or higher) or by Registry")
        $nfx | Add-Member -MemberType NoteProperty -Name 'SchUseStrongCrypto' -Value $SUSC
        $nfx | Add-Member -MemberType NoteProperty -Name 'SystemDefaultTlsVersions' -Value $SDTV
    }
    else {
        $nfx | Add-Member -MemberType NoteProperty -Name 'ServicePoint' -Value ("SSL/TLS Protocols available: " + $cSP)
        $nfx | Add-Member -MemberType NoteProperty -Name 'Critical' -Value ("Current Configuration implies TLS1.2 is NOT enabled for .Net Framework`n")
        $nfx | Add-Member -MemberType NoteProperty -Name 'SchUseStrongCrypto' -Value $SUSC
        $nfx | Add-Member -MemberType NoteProperty -Name 'SystemDefaultTlsVersions' -Value $SDTV
    }
  return $nfx
}

function Get-NetframeworkInstalledUpdates {
    $updates = New-Object -ComObject "Microsoft.Update.Session"
    $searcher = $updates.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    $updateHistory = $searcher.QueryHistory(0,$historyCount ) 

    # This will return a list of all updates installed over the existence of this system including Defender, Malicious Software Removal Tool etc..
    # We only care about Framework Cumulative Updates here (the last 5x) that got successfully installed
    try {
        $updatelist =  ($updateHistory | Where-Object { ($_.Title.Contains('Cumulative Update for .NET Framework')) -and $_.ResultCode -eq 2})[0..4] |
        Select-Object -Property @{Name='Installation time'; Expression={$_.Date}},
        @{Name='Title (KB)'; Expression={$_.Title}},
        @{Name='KB Number'; Expression={
                                    [regex]::replace($_.Title, '.*\(KB(\d+)\).*', 'KB$1')
                                    } },
        @{Name='Support Url'; Expression={
                                    [regex]::replace($_.Title, '.*\(KB(\d+)\).*', 'https://support.microsoft.com/help/$1')
                                    } }|
        Sort-Object -Property 'Title (KB)' -Unique |
        Sort-Object -Property 'Installation time' -Descending
    } catch {}

    if ($null -eq $updatelist) {
        $htmlTable = "<p><b>Windows Update history returned no results.</b><br>.NET Framework Updates may not have been installed to date.</p>"
        
    } else {
        $htmlTable = $updatelist | convertto-html -Property 'Installation time','KB Number', 'Title (KB)', 'Support Url' -Fragment
    }
    return $htmlTable
}

function Get-InstalledWindowsUpdates {
    #we use get-hotfix to get the classic output of installed updates it will not return optional updates though
    $htmlTable = get-hotfix | 
    Sort-Object -Descending InstalledOn | 
    select-object @{Name='Support Url'; Expression={$_.Caption}}, 
    @{Name='Update type'; Expression={$_.Description}}, 
    @{Name='KB Number'; Expression={$_.HotFixId}},
    @{Name='Installation time'; Expression={$_.InstalledOn}},
    InstalledBy | 
    convertto-html -Property 'Installation time','Update type','KB Number',InstalledBy,'Support Url' -Fragment

    return $htmlTable
}

function Get-WindowsUpdateHTMLReport {
$htmlTemplate = @"
    <html>
        <head>
        <style>
            body {
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: 10pt;
                background-color: #fafafa;
                color: #333;
                margin: 20px;
            }

            table {
                border-collapse: separate;
                border-spacing: 0;
                width: 100%;
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }

            th {
                background-color: #4f6ef7;
                color: #fff;
                text-align: left;
                padding: 10px;
                font-weight: 600;
                border-right: 1px solid #3e57cc;
            }

            td {
                background-color: #f9f9f9;
                padding: 8px 10px;
                border: 1px solid #e0e0e0;
            }

            tr:hover td {
                background-color: #eef3ff;
            }

            th:first-child, td:first-child {
                border-left: none;
            }

            th:last-child, td:last-child {
                border-right: none;
            }    
</style>
</head>
<body>
<h2>Hotfix Information for: $env:COMPUTERNAME</h2>
    $(Get-InstalledWindowsUpdates)
<h2>.Net Framework Cumulative Updates Installed</h2>
    $(Get-NetframeworkInstalledUpdates)
</body>
</html>
"@

return $htmlTemplate
}
#endregion
##########################################################################
#region Execution

if (IsAdminAccount){
Write-host "Script is executed as Administrator. Resuming execution" -ForegroundColor Green

if ([string]::IsNullOrEmpty($Path)) {
    $RunProp = RunDialog
    $Path = $RunProp.Path.ToString()
    $TraceEnabled = $RunProp.TraceEnabled
    $NetTraceEnabled = $RunProp.NetTraceEnabled
    $ConfigOnly = $RunProp.ConfigOnly
    $PerfCounter = $RunProp.PerfCounter
    $LdapTraceEnabled= $RunProp.LdapTraceEnabled
    $WAPTraceEnabled= $RunProp.WAPTraceEnabled
}
elseif (![string]::IsNullOrEmpty($Path)) {
    if($Tracing.IsPresent -eq $false){ $TraceEnabled=$false;$NetTraceEnabled=$false;$PerfCounter=$false;$LdapTraceEnabled=$false;$ConfigOnly=$true;$WAPTraceEnabled=$false }
    else {
        $TraceEnabled=$true;
        $ConfigOnly=$false;
        $LdapTraceEnabled=$false
        $WAPTraceEnabled=$false
        $PerfCounter=$false
        if($NetworkTracing.IsPresent -eq $true){ $NetTraceEnabled=$true } else { $NetTraceEnabled=$false }
        if($PerfTracing.IsPresent -eq $true) { $PerfCounter=$true } 
        if(($LDAPTracing.IsPresent -eq $true) -and (!$isproxy)) {  $LdapTraceEnabled=$true }  
        if(($WAPTracing.IsPresent -eq $true) -and ($isproxy))  { $WAPTraceEnabled=$true } 
    }
}

if(Test-Path -Path $Path) { Write-host "Your folder: $Path already exists. Starting Data Collection..." -ForegroundColor DarkCyan }
else {
    Write-host "Your Logfolder: $Path does not exist. Creating Folder" -ForegroundColor DarkCyan
    New-Item -ItemType directory -Path $Path -Force | Out-Null
 }
$FEL=$Global:FormatEnumerationLimit  ##secure current EnumLimit.Script should revert to this value at the end of execution
$Global:FormatEnumerationLimit=-1

$TraceDir = $Path +"\temporary"
# Save execution output to file
Write-host "Creating Temporary Folder in $path" -ForegroundColor DarkCyan
New-Item -ItemType directory -Path $TraceDir -Force | Out-Null
if($PSVersionTable.PSVersion -le [Version]'4.0') { Start-Transcript -Path "$TraceDir\transscript_output.txt" -Append |out-null} else { Start-Transcript -Path "$TraceDir\transscript_output.txt" -Append -IncludeInvocationHeader |out-null}
Write-Host "Debug logs will be saved in: " $Path -ForegroundColor DarkCyan
Write-Host "Options selected:  TracingEnabled:"$TraceEnabled "NetworkTrace:" $NetTraceEnabled " ConfigOnly:" $ConfigOnly " PerfCounter:" $PerfCounter " LDAPTrace:" $LdapTraceEnabled "WAPTrace:" $WAPTraceEnabled -ForegroundColor DarkCyan
Write-Progress -Activity "Preparation" -Status 'Setup Data Directory' -percentcomplete 5

if ($TraceEnabled) {
$MessageTitle = "Initialization completed`n"
$MessageIse = "Data Collection is ready to start.`nPrepare other computers to start collecting data.`n`nWhen ready, Click OK to start the collection...`n"
$MessageC = "`nData Collection is ready to start.`nPrepare other computers to start collecting data.`n`nWhen ready, press CTRL+Y to start the collection...`n"
Pause $MessageIse $MessageTitle $MessageC
}

Write-Progress -Activity "Gathering Configuration Data" -Status 'Getting ADFS Configuration' -percentcomplete 7
    GetADFSConfig
    GetDRSConfig
    Clear-DnsClientCache


Write-Progress -Activity "Enable Logging" -Status 'Eventlogs' -percentcomplete 15
$starttime = (get-date)

Write-host "Configuring Event Logging" -ForegroundColor DarkCyan
if ($IsProxy) 	{ EnableDebugEvents $WAPDebugEvents  }
else 			{ EnableDebugEvents $ADFSDebugEvents }

Write-Progress -Activity "Enable Logging" -Status 'Netlogon Debug Logging' -percentcomplete 30
EnableNetlogonDebug

Write-Progress -Activity "Enable Logging" -Status 'Additional ETL Logging' -percentcomplete 40
LogManStart
EnableNetworkTrace
EnablePerfCounter
EnableLDAPTrace
EnableWAPTrace

if($TraceEnabled) {
Write-Progress -Activity "Ready for Repro" -Status 'Waiting for Repro' -percentcomplete 50
$MessageTitle = "Data Collection Running"
$MessageIse = "Data Collection is currently running`nProceed  reproducing the problem now or`n`nPress OK to stop the collection...`n"
$MessageC = "Data Collection is currently running`nProceed  reproducing the problem now or `n`nPress CTRL+Y to stop the collection...`n"
Pause $MessageIse $MessageTitle $MessageC
}

Write-Progress -Activity "Collecting" -Status 'Stop Event logging' -percentcomplete 55
if ($IsProxy) 	{ DisableDebugEvents $WAPDebugEvents }
else 			{ DisableDebugEvents $ADFSDebugEvents }

Write-Progress -Activity "Collecting" -Status 'Stop additional logs' -percentcomplete 65
    LogManStop
    DisableNetworkTrace
    DisablePerfCounter
    DisableNetlogonDebug
    DisableLDAPTrace
    DisableWAPTrace

Write-Progress -Activity "Collecting" -Status 'Getting otherlogs' -percentcomplete 70
GatherTheRest

Write-Progress -Activity "Collecting" -Status 'Exporting Eventlogs' -percentcomplete 85
[int]$endtimeinmsec= (New-TimeSpan -start $starttime -end (get-date).AddMinutes(5)).TotalMilliseconds

if ($IsProxy) 	{ ExportEventLogs $WAPExportEvents $endtimeinmsec }
else 			{ ExportEventLogs $ADFSExportEvents $endtimeinmsec }
$Global:FormatEnumerationLimit=$FEL
Write-Progress -Activity "Saving" -Status 'Compressing Files - This may take some moments to complete' -percentcomplete 95
Write-host "Almost done. We are compressing all Files. Please wait" -ForegroundColor Green
EndOfCollection

}
else {
Write-Host "You do not have Administrator rights!`nPlease re-run this script as an Administrator!" -ForegroundColor Red
Break
}
#endregion