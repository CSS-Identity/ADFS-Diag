############################################################################################################
# ADFS troubleshooting - Data Collection
# Supported OS versions: Windows Server 2012 to Server 2022
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
    [switch]$PerfTracing
)

##########################################################################
#region Parameters
[Version]$WinVer = (Get-WmiObject win32_operatingsystem).version
$IsProxy = ((Get-WindowsFeature -name ADFS-Proxy).Installed -or (Get-WindowsFeature -name Web-Application-Proxy).Installed)

# Event logs
$ADFSDebugEvents = "Microsoft-Windows-CAPI2/Operational","AD FS Tracing/Debug","Device Registration Service Tracing/Debug"
$WAPDebugEvents  = "Microsoft-Windows-CAPI2/Operational","AD FS Tracing/Debug","Microsoft-Windows-WebApplicationProxy/Session"

$ADFSExportEvents = 'System','Application','Security','AD FS Tracing/Debug','AD FS/Admin','Microsoft-Windows-CAPI2/Operational','Device Registration Service Tracing/Debug','DRS/Admin'
$WAPExportEvents  = 'System','Application','Security','AD FS Tracing/Debug','AD FS/Admin','Microsoft-Windows-CAPI2/Operational','Microsoft-Windows-WebApplicationProxy/Admin','Microsoft-Windows-WebApplicationProxy/Session'

#Import Modules
If ([Bool]$psISE) {
    if ([string]::IsNullOrEmpty($PSScriptRoot)) {$hm = split-path ($psISE.CurrentFile.FullPath)}
    else {$hm=$PSScriptRoot}
}
else {
    if (![string]::IsNullOrEmpty($PSScriptRoot)){$hm=$PSScriptRoot}
    else {$hm=$pwd.Path}
}

import-Module $hm\helpermodules\proxysettings.psm1
import-Module $hm\helpermodules\certificates.psm1
if($PSVersionTable.PSVersion -le [Version]'4.0') {
    Import-Module $hm\helpermodules\krbtype_enum_v4.psm1 } 
else {
    Import-Module $hm\helpermodules\krbtype_enum_v5.psm1 }

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

#NetworkCapture+genericInternetTraffic
$EnableNetworkTracer = 'netsh trace start scenario=internetServer capture=yes report=disabled overwrite=yes maxsize=500 tracefile=.\%COMPUTERNAME%-network.etl'
$DisableNetworkTracer = 'netsh trace stop'

#Performance Counter
$CreatePerfCountProxy = 'Logman.exe create counter ADFSProxy -o ".\ADFSProxy-perf.blg" -f bincirc -max 512 -v mmddhhmm -c "\AD FS Proxy\*" "\LogicalDisk(*)\*" "\Memory\*" "\PhysicalDisk(*)\*" "\Process(*)\*" "\Processor(*)\*" "\TCPv4\*" -si 0:00:05'
$EnablePerfCountProxy = 'Logman.exe start ADFSProxy'

$DisablePerfCountProxy = 'Logman.exe stop ADFSProxy'
$RemovePerfCountProxy = 'Logman.exe delete ADFSProxy'

$CreatePerfCountADFS = 'Logman.exe create counter ADFSBackEnd -o ".\%COMPUTERNAME%-ADFSBackEnd-perf.blg" -f bincirc -max 512 -v mmddhhmm -c "\AD FS\*" "\LogicalDisk(*)\*" "\Memory\*" "\PhysicalDisk(*)\*" "\Process(*)\*" "\Processor(*)\*" "\Netlogon(*)\*" "\TCPv4\*" "Netlogon(*)\*" -si 00:00:05'
$EnablePerfCountADFS = 'Logman.exe start ADFSBackEnd'

$DisablePerfCountADFS = 'Logman.exe stop ADFSBackEnd'
$RemovePerfCountADFS = 'Logman.exe delete ADFSBackEnd'

$others = 'nltest /trusted_domains > %COMPUTERNAME%-nltest-trusted_domains.txt',`
'ipconfig /flushdns'

#Collection for Additional Files
$Filescollector = 'copy /y %windir%\debug\netlogon.*  ',`
'ipconfig /all > %COMPUTERNAME%-ipconfig-all.txt',`
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
'wmic qfe list full /format:htable > %COMPUTERNAME%-WindowsPatches.htm',`
'GPResult /f /h %COMPUTERNAME%-GPReport.html',`
'systeminfo > %COMPUTERNAME%-sysinfo.txt',`
'regedit /e %COMPUTERNAME%-reg-NTDS-port-and-other-params.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\parameters',`
'regedit /e %COMPUTERNAME%-reg-NETLOGON-port-and-other-params.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\parameters',`
'regedit /e %COMPUTERNAME%-reg-schannel.txt HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL',`
'regedit /e %COMPUTERNAME%-reg-Cryptography_registry.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography',`
'regedit /e %COMPUTERNAME%-reg-ciphers_policy_registry.txt HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL'

#Enum forDotNetReleases
#https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#version_table
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
Add-Type -AssemblyName System.Windows.Forms
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
$Description.Size               = [System.Drawing.Size]::new(780, 360)
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
$Scenario.Location = [System.Drawing.Point]::new(15, 375) # Positioned below the RichTextBox
$Scenario.Size = [System.Drawing.Size]::new(780, 50)
$cScenario = @("Configuration only", "Runtime Tracing")

for ($i = 0; $i -lt $cScenario.Length; $i++) {
    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Text = $cScenario[$i]
    $checkBox.AutoSize = $true
    $checkBox.Location = [System.Drawing.Point]::new($xOffset + ($i * $checkBoxWidth), $yOffset)

    switch -Wildcard ($cScenario[$i]) {
      "Configuration only" { Set-Variable -Name cfgonly -Value $checkBox -Force }
      "Runtime Tracing" { Set-Variable -Name TracingMode -Value $checkBox -Force }
      }
    $Scenario.Controls.Add($checkBox)
}

$Options = New-Object System.Windows.Forms.GroupBox
$Options.Text = "Options"
$Options.Location = [System.Drawing.Point]::new(15, 430) # Positioned below the ScenarioGroup
$Options.Size = [System.Drawing.Size]::new(480, 50) # Adjust the size as needed 780,50

$cOptions = @("include Network Traces", "include Performance Counter")

for ($i = 0; $i -lt $cOptions.Length; $i++) {
  $checkBox = New-Object System.Windows.Forms.CheckBox
  $checkBox.Text = $cOptions[$i]
  $checkBox.AutoSize = $true
  $checkBox.Enabled= $false
  $checkBox.Location = [System.Drawing.Point]::new($xOffset + ($i * $checkBoxWidth), $yOffset)

  switch -Wildcard ($cOptions[$i]) {
    "include Network Traces" { Set-Variable -Name NetTrace -Value $checkBox -Force }
    "include Performance Counter" { Set-Variable -Name perfc -Value $checkBox -Force }
    #"LDAP Traces (if requested by Engineer)" { Set-Variable -Name ldapt -Value $checkBox -Force }
    }
  $Options.Controls.Add($checkBox)
}
#####
$aOptions = New-Object System.Windows.Forms.GroupBox
$aOptions.Text = "advanced Options (can cause service restarts)"
$aOptions.Location = [System.Drawing.Point]::new(500, 430) # Positioned below the ScenarioGroup
$aOptions.Size = [System.Drawing.Size]::new(295, 50) # Adjust the size as needed

$caOptions = @("LDAP Traces (if requested by Engineer)")

for ($i = 0; $i -lt $caOptions.Length; $i++) {
  $checkBox = New-Object System.Windows.Forms.CheckBox
  $checkBox.Text = $caOptions[$i]
  $checkBox.AutoSize = $true
  $checkBox.Enabled= $false
  $checkBox.Location = [System.Drawing.Point]::new($xOffset + ($i * $checkBoxWidth), $yOffset)

  switch -Wildcard ($caOptions[$i]) {
    "LDAP Traces (if requested by Engineer)" { Set-Variable -Name ldapt -Value $checkBox -Force }
    }
  $aOptions.Controls.Add($checkBox)
}

#####
$label = New-Object System.Windows.Forms.GroupBox
$label.Text = 'Type a path to the Destination Folder or Click "Browse..." to select the Folder'
$label.Location = [System.Drawing.Point]::new(15,480) # Positioned below the ScenarioGroup
$label.Size = [System.Drawing.Size]::new(585, 60) # Adjust the size as needed

#Text Field for the Export Path to store the results
$TargetFolder                    = New-Object system.Windows.Forms.TextBox
$TargetFolder.text               = ""
$TargetFolder.Size               = [System.Drawing.Size]::new(470, 30) 
$TargetFolder.location           = New-Object System.Drawing.Point(10,20)
$TargetFolder.Font               = 'Arial,13'

$SelFolder                       = New-Object system.Windows.Forms.Button
$SelFolder.text                  = "Browse..."
$SelFolder.Size                  = [System.Drawing.Size]::new(90, 29)
$SelFolder.location              = New-Object System.Drawing.Point(486,20)
$SelFolder.Font                  = 'Arial,10'

$label.Controls.AddRange(@($TargetFolder,$SelFolder))

$Okbtn                           = New-Object system.Windows.Forms.Button
$Okbtn.text                      = "OK"
$Okbtn.Size                      = [System.Drawing.Size]::new(70, 30) 
$Okbtn.location                  = New-Object System.Drawing.Point(620,540)
$Okbtn.Font                      = 'Arial,10'
$Okbtn.DialogResult              = [System.Windows.Forms.DialogResult]::OK
$Okbtn.Enabled                   = $false

$cnlbtn                          = New-Object system.Windows.Forms.Button
$cnlbtn.text                     = "Cancel"
$cnlbtn.Size                      = [System.Drawing.Size]::new(70, 30) 
$cnlbtn.location                 = New-Object System.Drawing.Point(700,540)
$cnlbtn.Font                     = 'Arial,10'
$cnlbtn.DialogResult              = [System.Windows.Forms.DialogResult]::Cancel

$Form.controls.AddRange(@($Description,$Scenario,$Options,$aOptions,$Okbtn,$cnlbtn,$label))

$cfgonly.Add_CheckStateChanged({ if ($cfgonly.checked)
                                {$TracingMode.Enabled = $false; $NetTrace.Enabled = $false; $perfc.Enabled = $false; $ldapt.Enabled = $false}
                                else
                                {$TracingMode.Enabled = $true; $NetTrace.Enabled = $false}
                              })

$TracingMode.Add_CheckStateChanged({ if ($TracingMode.checked)
                                {$cfgonly.Enabled = $false; $NetTrace.Enabled = $true;$NetTrace.Checked = $true; $perfc.Enabled = $true; if(!$IsProxy){ $ldapt.Enabled=$true}}
                                else
                                {$cfgonly.Enabled = $true; $NetTrace.Checked = $false; $NetTrace.Enabled = $false;$perfc.Checked = $false; $perfc.Enabled = $false;$ldapt.Checked = $false; $ldapt.Enabled = $false;  }
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

##########################################################################
#region Functions
Function IsAdminAccount {
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
return $true
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
$c.Timeout=[timespan]::FromSeconds(45)
if([string]::IsNullOrEmpty($basedn)){ $basedn = (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$conn/RootDSE")).DefaultNamingContext}
$scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
$r = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList $basedn,$filter,$scope,$att
$re = try { $c.SendRequest($r)}catch{$_.Exception.InnerException }
$c.Dispose()
return $re
}

function get-servicesettingsfromdb () {
    $stsWMIObject = (Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService)
    #Create SQL Connection
    $connection = new-object system.data.SqlClient.SqlConnection($stsWMIObject.ConfigurationDatabaseConnectionString);
    $connection.Open()

    $query = "SELECT * FROM IdentityServerPolicy.ServiceSettings"  
    $sqlcmd = $connection.CreateCommand();
    $sqlcmd.CommandText = $query;
    $result = $sqlcmd.ExecuteReader();
    $table = new-object "System.Data.DataTable"
    $table.Load($result)
    [XML]$SSD=  $table.ServiceSettingsData
    return $SSD
}

function AzureMFAConfig () {   
$ssd = get-servicesettingsfromdb
if(!$null -eq $ssd) { #loop through the AuthAdapters and find the config for AzureMFAAdapter; we might expand this for other adapters if necessary
        foreach ($AmD in $ssd.ServiceSettingsData.SecurityTokenService.AuthenticationMethods.AuthenticationMethodDescriptor) { 
            if ($AmD.Identifier -eq "AzureMfaAuthentication" -and (!$AmD.ConfigurationData.IsEmpty)) {
                return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($AmD.ConfigurationData))
            }
        }
    }
}       

function Get-ADFSAzureMfaAdapterconfig {
    $MFAraw= AzureMFAConfig       
    if($null -eq $MFAraw) {
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

Function AllOtherLogs {
    Push-Location $TraceDir
	ForEach ($o in $others)	{		
		cmd.exe /c $o |Out-Null		
	}
    Pop-Location
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
    else { Write-host "Net Logging logging was not enabled" -ForegroundColor DarkCyan }
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
    else { Write-host "Debug Tracing Eventlogs where not enabled" -ForegroundColor DarkCyan }
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
        #"Exporting Eventlog : "+ $evts + " using filter :" + $expfilter
		$EventSession.ExportLogAndMessages($evts,'Logname',$expfilter,$evttarget)
    }
    Pop-Location
}

function widlogs {
    $widlog="$env:windir\WID\Log"
    $wid = $TraceDir + "\Wid"
    #for the time being we only want to collect the error logs from wid if the cummulative size is less then 10MB
    if ([math]::Round(((Get-ChildItem $widlog -Filter *.log)| Measure-Object -Property Length -sum).sum / 1Mb ,1) -le 10) {
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
    GetProxySettings | out-file  $env:COMPUTERNAME-ProxySettings.txt
    Get-LocalMachineCerts| out-file  $env:COMPUTERNAME-Certificates-My.txt
    Get-RootCACertificates| out-file  $env:COMPUTERNAME-Certificates-Root.txt
    Get-IntermediateCACertificates| out-file  $env:COMPUTERNAME-Certificates-CA.txt
    Get-NTauthCertificates| out-file  $env:COMPUTERNAME-Certificates-NTAuth.txt
    Get-ADFSTrustedDevicesCertificates| out-file  $env:COMPUTERNAME-Certificates-ADFSTrustedDevices.txt
    
    if(!$IsProxy) {
    Get-Adfssslcertificate|foreach-object {if($_.CtlStoreName -eq "ClientAuthIssuer" ) {Get-ClientAuthIssuerCertificates| out-file $env:COMPUTERNAME-Certificates-CliAuthIssuer.txt }}
    
    if((Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService).ConfigurationDatabaseConnectionString -match "##wid" -or $ConnectionString -match "##ssee"){
        widlogs}
    }
    else {
        Get-WebApplicationProxySslCertificate|foreach-object {if($_.CtlStoreName -eq "ClientAuthIssuer" ){Get-ClientAuthIssuerCertificates| out-file $env:COMPUTERNAME-Certificates-CliAuthIssuer.txt}} }
        Get-DnsClientCache |Sort-Object -Property Entry |format-list |Out-File $env:COMPUTERNAME-DNSClient-Cache.txt
        Get-ChildItem env: |Format-Table Key,Value -Wrap |Out-File $env:COMPUTERNAME-environment-variables.txt
        Get-NetTCPConnection|Sort-Object -Property LocalAddress |out-file $env:COMPUTERNAME-NetTCPConnection.txt
        get-service|Sort-Object -Property Status -Descending |Format-Table DisplayName,Status,StartType -autosize | out-file $env:COMPUTERNAME-services-running.txt
        get-process |Sort-Object Id |Format-Table Name,Id, SessionId,WorkingSet -AutoSize |out-file $env:COMPUTERNAME-tasklist.txt
        Get-Content $env:windir\system32\drivers\etc\hosts |out-file $env:COMPUTERNAME-hosts.txt
        ((get-childitem $env:Windir\adfs\* -include *.dll,*.exe).VersionInfo |Sort-Object -Property FileVersion |Format-Table FileName, FileVersion) |out-file $env:COMPUTERNAME-ADFS-fileversions.txt
        VerifyNetFX |format-list | out-file $env:COMPUTERNAME-DotNetFramework.txt
    Pop-Location
}

Function EnablePerfCounter {
    if ($TraceEnabled -and $PerfCounter) {
            if ($IsProxy) {
            Write-host "Enabling PerfCounter" -ForegroundColor DarkCyan
            Push-Location $TraceDir
            cmd /c $CreatePerfCountProxy |Out-Null
		    cmd /c $EnablePerfCountProxy |Out-Null
		    Pop-Location
            }
            else {
            Push-Location $TraceDir
            Write-host "Configuring PerfCounter" -ForegroundColor DarkCyan
            cmd /c $CreatePerfCountADFS |Out-Null
		    cmd /c $EnablePerfCountADFS |Out-Null
            Pop-Location
            }
    }
    else { Write-Host "Performance Monitoring will not be sampled due to selected scenario" -ForegroundColor DarkCyan }
}

Function DisablePerfCounter {
    if ($TraceEnabled -and $PerfCounter) { Write-Host "Stopping Performance Monitoring" -ForegroundColor DarkCyan
            if ($IsProxy) {
		    cmd /c $DisablePerfCountProxy |Out-Null
            #we need to remove the counter created during enablement
            cmd /c $RemovePerfCountProxy |Out-Null
            }
            else {
		    cmd /c $DisablePerfCountADFS |Out-Null
            #we need to remove the counter created during enablement
            cmd /c $RemovePerfCountADFS |Out-Null
            }
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

function GetServiceAccountDetails {
if (!$IsProxy) {
    $SVCACC = ((get-wmiobject win32_service -Filter "Name='adfssrv'").startname)
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

"Performing LDAP Lookup of ADFS Service Account: " + $SVCACC | out-file Get-ServicePrincipalNames.txt -Append

$re= LDAPQuery -filter $filter -att $att -conn $conn
$gmsa =$false

if($re.GetType().Name -eq 'SearchResponse') {
        $gmsa = [Bool]($re.Entries.Attributes.objectclass.GetValues('string') -eq 'msDS-GroupManagedServiceAccount')
        "Service Account is GMSA: " + $gmsa | out-file Get-ServicePrincipalNames.txt -Append

    if($gmsa -eq $true) {
        $adl = new-object System.DirectoryServices.ActiveDirectorySecurity
        $adl.SetSecurityDescriptorBinaryForm($re.Entries[0].Attributes.'msds-groupmsamembership'[0])
        "`nGMSA allowed Hosts: `n" + $adl.AccessToString | Format-Table |out-file Get-ServicePrincipalNames.txt -Append
    }
    else {"`nService Account used is a generic User"| out-file Get-ServicePrincipalNames.txt -Append}

    "`nServicePrincipalNames registered: " |out-file Get-ServicePrincipalNames.txt -Append
    $re.Entries.Attributes.serviceprincipalname.GetValues('string') |out-file Get-ServicePrincipalNames.txt -Append

    $EncType=$null
    Try { $EncType= [int]::Parse($re.Entries[0].Attributes.'msds-supportedencryptiontypes'.GetValues('string')) }
    Catch { "We handled an exception when reading msds-supportedencryptiontypes, which implies the attribute is not configured. This is not a critical error"; }

    $KRBflags=$null
    if(![string]::IsNullOrEmpty($EncType)) {
        $KRBflags = enumerateKrb $EncType
    }
    else { $KRBflags ="`n`tmsds-supportedencryptiontypes is not configured on the service account, Service tickets would be RC4 only!`n`tFor AES Support configure the msds-supportedencryptiontypes on the ADFS Service Account with a value of either:`n`t24(decimal) == AES only `n`t or `n`t28(decimal) == AES & RC4" }
    "`nKerberos Encryption Types supported by Service Account: " + $KRBflags |Out-File Get-ServicePrincipalNames.txt -Append
}
else { "Service Account query failed with error: "+$re.Message |Out-File Get-ServicePrincipalNames.txt -Append }

    "`nChecking for Duplicate SPNs( current ServiceAccount will be included in this check):`n" |out-file Get-ServicePrincipalNames.txt -Append

    $conn= (New-Object System.DirectoryServices.DirectoryEntry("GC://$domain/RootDSE")).dnshostname
    $filter= "(serviceprincipalname="+('*/'+(get-servicesettingsfromdb).ServiceSettingsData.SecurityTokenService.Host.Name)+")"
    [string]$att = "*"
    $re= LDAPQuery -filter $filter -att $att -conn $conn
if ($re.GetType().Name -eq 'SearchResponse') {
    $re.Entries |foreach { $_.distinguishedName |out-file Get-ServicePrincipalNames.txt -Append ; 
        $_.Attributes.'serviceprincipalname'.GetValues('string')|out-file Get-ServicePrincipalNames.txt -Append }
}
else {"Duplicate SPN Query failed with error: "+$re.Message |Out-File Get-ServicePrincipalNames.txt -Append}
}
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
        GetServiceAccountDetails


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
    Add-Type -Assembly "System.IO.Compression.FileSystem" ;
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
}
elseif (![string]::IsNullOrEmpty($Path)) {
    if($Tracing.IsPresent -eq $false){ $TraceEnabled=$false;$NetTraceEnabled=$false;$PerfCounter=$false;$LdapTraceEnabled=$false;$ConfigOnly=$true }
    else {
        $TraceEnabled=$true;
        $ConfigOnly=$false;
        if($NetworkTracing.IsPresent -eq $true){ $NetTraceEnabled=$true } else { $NetTraceEnabled=$false }
        if($PerfTracing.IsPresent -eq $true) { $PerfCounter=$true } else { $PerfCounter=$false }
        if($LDAPTracing.IsPresent -eq $true) { if(!$IsProxy) { $LdapTraceEnabled=$true } } else { $LdapTraceEnabled=$false }
    }
}

if(Test-Path -Path $Path) { Write-host "Your folder: $Path already exists. Starting Data Collection..." -ForegroundColor DarkCyan }
else {
    Write-host "Your Logfolder: $Path does not exist. Creating Folder" -ForegroundColor DarkCyan
    New-Item -ItemType directory -Path $Path -Force | Out-Null
 }
$FEL=$Global:FormatEnumerationLimit
$Global:FormatEnumerationLimit=-1

$TraceDir = $Path +"\temporary"
# Save execution output to file
Write-host "Creating Temporary Folder in $path" -ForegroundColor DarkCyan
New-Item -ItemType directory -Path $TraceDir -Force | Out-Null

Start-Transcript -Path "$TraceDir\transscript_output.txt" -Append -IncludeInvocationHeader |out-null
Write-Host "Debug logs will be saved in: " $Path -ForegroundColor DarkCyan
Write-Host "Options selected:  TracingEnabled:"$TraceEnabled "NetworkTrace:" $NetTraceEnabled " ConfigOnly:" $ConfigOnly " PerfCounter:" $PerfCounter " LDAPTrace:" $LdapTraceEnabled -ForegroundColor DarkCyan
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

Write-Progress -Activity "Gathering Configuration Data" -Status 'Gathering Logfiles' -percentcomplete 10
AllOtherLogs

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

if($TraceEnabled) {
Write-Progress -Activity "Ready for Repro" -Status 'Waiting for Repro' -percentcomplete 50
$MessageTitle = "Data Collection Running"
$MessageIse = "Data Collection is currently running`nProceed  reproducing the problem now or`n`nPress OK to stop the collection...`n"
$MessageC = "Data Collection is currently running`nProceed  reproducing the problem now or `n`nPress press CTRL+Y to stop the collection...`n"
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
