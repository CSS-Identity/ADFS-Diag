############################################################################################################
# ADFS troubleshooting - Data Collection
# Supported OS versions: Windows Server 2012 to Server 2025
# Supported role: ADFS on 2012 to 2022, ADFS proxy server (2012) and Web Application Proxy (2012 R2 to 2022)
############################################################################################################

param (
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if ([string]::IsNullOrEmpty($_)) { return $true }
        $pattern = '^(?:[a-zA-Z]:\\|\\\\[\d\D]|\.{1,2}\\)([^<>:"\\|?*]+\\)*[^<>:"\\|?*]*$'
        if ($_ -notmatch $pattern) {
            throw "The path '$_' is not a valid filesystem path. Use a local (C:\folder), UNC (\\server\share), or relative (.\folder) path."
        }
        return $true
    })]
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
    [switch]$PerfTracing,

    [Parameter(Mandatory=$false)]
    [switch]$AcceptEula
)


##########################################################################
#region Assembly Depencies
Add-Type -AssemblyName System.ServiceProcess
#Add-Type -AssemblyName System.Windows.Forms  #deprecated in favor of WPF-based UI components, remove with future release
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

#region Parameters
[Version]$WinVer = [System.Environment]::OSVersion.Version
$scriptversion = "v26.02"
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
    
    public class ServiceConfigHelper
    {
  
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct QUERY_SERVICE_CONFIG
    {
        public int dwServiceType;
        public int dwStartType;
        public int dwErrorControl;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpBinaryPathName;
        public int dwTagId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpLoadOrderGroup;
        public int dwDependencies;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string lpServiceStartName; // This is the service account name
        public IntPtr lpDisplayName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, int cbBufSize, out int pcbBytesNeeded);

    const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    const uint SERVICE_QUERY_CONFIG = 0x0001;

    // Method to get the service account name
    public static string GetServiceAccount(string serviceName)
    {
        IntPtr scmHandle = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
        if (scmHandle == IntPtr.Zero)
        {
            return "OpenSCManager_failed";
        }

        IntPtr serviceHandle = OpenService(scmHandle, serviceName, SERVICE_QUERY_CONFIG);
        if (serviceHandle == IntPtr.Zero)
        {
            CloseServiceHandle(scmHandle);
                return "OpenService_failed";
        }

        int bytesNeeded = 0;
        QueryServiceConfig(serviceHandle, IntPtr.Zero, 0, out bytesNeeded); // Find out how much memory is needed

        IntPtr queryConfigBuffer = Marshal.AllocHGlobal(bytesNeeded);
        bool success = QueryServiceConfig(serviceHandle, queryConfigBuffer, bytesNeeded, out bytesNeeded);
        if (!success)
        {
            Marshal.FreeHGlobal(queryConfigBuffer);
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return "QueryServiceConfig_failed";
        }

        QUERY_SERVICE_CONFIG qsc = (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(queryConfigBuffer, typeof(QUERY_SERVICE_CONFIG));
        string serviceAccount = qsc.lpServiceStartName;

        Marshal.FreeHGlobal(queryConfigBuffer);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);

        return serviceAccount;
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

#region Folder Browser Dialog
function Show-FolderBrowserDialog {
    <#
    .SYNOPSIS
        WPF TreeView-based folder browser using System.IO.
        Works on Server Core where FolderBrowserDialog fails.
    #>
    param([string]$InitialPath)

    $fbXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Select Folder" Width="440" Height="400"
        WindowStartupLocation="CenterOwner" ShowInTaskbar="False"
        ResizeMode="CanResizeWithGrip" Background="#F3F3F3"
        FontFamily="Segoe UI" FontSize="13">
    <Window.Resources>
        <!-- Folder icon geometry -->
        <StreamGeometry x:Key="FolderIcon">M2,4 L2,18 L22,18 L22,7 L12,7 L10,4 Z</StreamGeometry>

        <!-- Primary button style (OK) — matches Run Dialog -->
        <Style x:Key="FBPrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="24,5"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}"
                                BorderThickness="0">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#106EBE"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#005A9E"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Background" Value="#CCE4F7"/>
                                <Setter Property="Foreground" Value="#99BFDF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- TreeViewItem style with folder icon -->
        <Style TargetType="TreeViewItem">
            <Style.Resources>
                <!-- Override system selection colours so highlighted items stay readable -->
                <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#CCE4F7"/>
                <SolidColorBrush x:Key="{x:Static SystemColors.HighlightTextBrushKey}" Color="#1A1A1A"/>
                <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightBrushKey}" Color="#E5E5E5"/>
                <SolidColorBrush x:Key="{x:Static SystemColors.InactiveSelectionHighlightTextBrushKey}" Color="#1A1A1A"/>
            </Style.Resources>
            <Setter Property="Padding" Value="2,1"/>
            <Setter Property="Margin" Value="0,1"/>
            <Setter Property="HeaderTemplate">
                <Setter.Value>
                    <DataTemplate>
                        <StackPanel Orientation="Horizontal">
                            <Path Data="{StaticResource FolderIcon}" Fill="#FFD75E" Stroke="#C4A63A"
                                  StrokeThickness="0.8" Width="18" Height="14" Stretch="Uniform"
                                  Margin="0,0,6,0" VerticalAlignment="Center"/>
                            <TextBlock Text="{Binding}" VerticalAlignment="Center"/>
                        </StackPanel>
                    </DataTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Grid Margin="12">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Select a destination folder:" FontWeight="SemiBold"
                   Foreground="#1A1A1A" Margin="0,0,0,8"/>
        <Border Grid.Row="1" Background="White" CornerRadius="4"
                BorderBrush="#E1E1E1" BorderThickness="1" Margin="0,0,0,8">
            <TreeView x:Name="FolderTree" Background="Transparent"
                      BorderThickness="0" Padding="4"/>
        </Border>
        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right">
            <Button x:Name="OkBtn" Content="OK" Width="90" Height="30" Margin="0,0,8,0"
                    IsEnabled="False" Style="{StaticResource FBPrimaryButton}"/>
            <Button x:Name="CancelBtn" Content="Cancel" Width="90" Height="30" FontSize="13"
                    Background="White" BorderBrush="#E1E1E1"/>
        </StackPanel>
    </Grid>
</Window>
"@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($fbXaml))
    $fbWindow = [System.Windows.Markup.XamlReader]::Load($reader)
    $reader.Close()

    $tree       = $fbWindow.FindName("FolderTree")
    $okBtn      = $fbWindow.FindName("OkBtn")
    $cancelBtn  = $fbWindow.FindName("CancelBtn")

    $script:fbResult = $null

    # --- Helper: create a TreeViewItem with a hidden dummy child for the expand arrow ---
    function New-FolderNode([string]$folderPath, [string]$displayName) {
        $node = New-Object System.Windows.Controls.TreeViewItem
        $node.Header = $displayName
        $node.Tag    = $folderPath
        # Invisible placeholder so the expander arrow appears
        $dummy = New-Object System.Windows.Controls.TreeViewItem
        $dummy.Visibility = [System.Windows.Visibility]::Collapsed
        [void]$node.Items.Add($dummy)
        return $node
    }

    # --- Populate drive roots ---
    foreach ($drv in [System.IO.DriveInfo]::GetDrives()) {
        if ($drv.IsReady) {
            $label = if ($drv.VolumeLabel) {
                "$($drv.Name.TrimEnd('\\'))  [$($drv.VolumeLabel)]"
            } else { $drv.Name.TrimEnd('\\') }
            [void]$tree.Items.Add((New-FolderNode $drv.Name $label))
        }
    }

    # --- Lazy-load subfolders on expand ---
    $tree.AddHandler(
        [System.Windows.Controls.TreeViewItem]::ExpandedEvent,
        [System.Windows.RoutedEventHandler]{
            param($sender, $e)
            $item = $e.OriginalSource
            if ($item -isnot [System.Windows.Controls.TreeViewItem]) { return }
            # Check if first child is the collapsed dummy placeholder
            if ($item.Items.Count -eq 1 -and
                $item.Items[0] -is [System.Windows.Controls.TreeViewItem] -and
                $item.Items[0].Visibility -eq [System.Windows.Visibility]::Collapsed) {

                $item.Items.Clear()
                try {
                    foreach ($dir in [System.IO.Directory]::GetDirectories($item.Tag)) {
                        $attr = [System.IO.File]::GetAttributes($dir)
                        if ($attr -band [System.IO.FileAttributes]::Hidden)   { continue }
                        if ($attr -band [System.IO.FileAttributes]::System)   { continue }
                        $name = [System.IO.Path]::GetFileName($dir)
                        [void]$item.Items.Add((New-FolderNode $dir $name))
                    }
                } catch {
                    # Access denied or other I/O error — leave node empty
                }
            }
        }
    )

    $tree.Add_SelectedItemChanged({
        param($sender, $e)
        $sel = $e.NewValue
        if ($sel -is [System.Windows.Controls.TreeViewItem] -and $sel.Tag) {
            $script:fbSelectedPath = $sel.Tag
            $okBtn.IsEnabled       = $true
        }
    })

    $okBtn.Add_Click({
        $script:fbResult = $script:fbSelectedPath
        $fbWindow.DialogResult = $true
    })
    $cancelBtn.Add_Click({
        $fbWindow.DialogResult = $false
    })

    if ($InitialPath -and (Test-Path $InitialPath -PathType Container)) {
        $script:fbSelectedPath = $InitialPath
        $okBtn.IsEnabled       = $true
    }

    $fbWindow.Owner = $Window
    $result = $fbWindow.ShowDialog()
    if ($result) { return $script:fbResult } else { return $null }
}
#endregion

#region Hyperlink Helper
function New-ClickableHyperlink {
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$DisplayText
    )
    if ([string]::IsNullOrEmpty($DisplayText)) { $DisplayText = $Url }
    $run = New-Object System.Windows.Documents.Run($DisplayText)
    $hyperlink = New-Object System.Windows.Documents.Hyperlink($run)
    $hyperlink.NavigateUri = [Uri]$Url
    $hyperlink.Foreground  = [System.Windows.Media.Brushes]::Blue
    $hyperlink.Add_RequestNavigate({
        param($s, $e)
        Start-Process $e.Uri.AbsoluteUri
        $e.Handled = $true
    })
    return $hyperlink
}

function Add-TextBlockInlines {
    <#
    .SYNOPSIS
        Adds Run/Hyperlink inlines to a TextBlock, supporting:
        - URLs              → clickable Hyperlinks
        - ***text***        → Bold + Italic
        - **text**          → Bold
        - *text*            → Italic
        The -Bold switch sets the baseline weight for the entire part.
    #>
    param(
        [Parameter(Mandatory)][System.Windows.Controls.TextBlock]$TextBlock,
        [Parameter(Mandatory)][string]$Text,
        [switch]$Bold
    )

    # Helper: emit Runs for a text fragment, applying *-based formatting + optional underline
    $emitRuns = {
        param([string]$fragment, [bool]$isBold, [bool]$isUnderline)
        # Split on  ***bold+italic***  **bold**  *italic*
        $parts = [regex]::Split($fragment, '(\*{1,3})(.+?)\1')
        $idx = 0
        while ($idx -lt $parts.Count) {
            if ($idx + 2 -lt $parts.Count -and $parts[$idx + 1] -match '^\*{1,3}$') {
                # plain text before the marker
                if ($parts[$idx].Length -gt 0) {
                    $run = New-Object System.Windows.Documents.Run($parts[$idx])
                    if ($isBold) { $run.FontWeight = [System.Windows.FontWeights]::Bold }
                    if ($isUnderline) { $run.TextDecorations = [System.Windows.TextDecorations]::Underline }
                    [void]$TextBlock.Inlines.Add($run)
                }
                # formatted content
                $marker  = $parts[$idx + 1]
                $content = $parts[$idx + 2]
                $run = New-Object System.Windows.Documents.Run($content)
                if ($isUnderline) { $run.TextDecorations = [System.Windows.TextDecorations]::Underline }
                switch ($marker.Length) {
                    3 { $run.FontWeight = [System.Windows.FontWeights]::Bold
                        $run.FontStyle  = [System.Windows.FontStyles]::Italic }
                    2 { $run.FontWeight = [System.Windows.FontWeights]::Bold }
                    1 { $run.FontStyle  = [System.Windows.FontStyles]::Italic
                        if ($isBold) { $run.FontWeight = [System.Windows.FontWeights]::Bold } }
                }
                [void]$TextBlock.Inlines.Add($run)
                $idx += 3
            }
            else {
                if ($parts[$idx].Length -gt 0) {
                    $run = New-Object System.Windows.Documents.Run($parts[$idx])
                    if ($isBold) { $run.FontWeight = [System.Windows.FontWeights]::Bold }
                    if ($isUnderline) { $run.TextDecorations = [System.Windows.TextDecorations]::Underline }
                    [void]$TextBlock.Inlines.Add($run)
                }
                $idx++
            }
        }
    }

    # Step 1: split on URLs
    $urlSegments = [regex]::Split($Text, '(https?://[^\s]+)')
    foreach ($seg in $urlSegments) {
        if ($seg -match '^https?://') {
            [void]$TextBlock.Inlines.Add((New-ClickableHyperlink -Url $seg))
        }
        elseif ($seg.Length -gt 0) {
            # Step 2: split on _underline_ (outer layer — content may contain * markup)
            $uParts = [regex]::Split($seg, '(?<!\w)_(.+?)_(?!\w)')
            # produces: [plain, underlinedContent, plain, underlinedContent, ...]
            for ($u = 0; $u -lt $uParts.Count; $u++) {
                if ($uParts[$u].Length -eq 0) { continue }
                $isUnderline = ($u % 2 -eq 1)
                & $emitRuns $uParts[$u] $Bold.IsPresent $isUnderline
            }
        }
    }
}

function Build-TextBlockPanel {

    param(
        [Parameter(Mandatory)][System.Windows.Controls.StackPanel]$Panel,
        [Parameter(Mandatory)][array]$Parts
    )
    $Panel.Children.Clear()

    # --- Detect header block (leading Bold parts) ---
    $headerCount = 0
    foreach ($p in $Parts) { if ($p.Bold) { $headerCount++ } else { break } }

    if ($headerCount -ge 2) {
        # Title + subtitle in one TextBlock
        $headerBlock = New-Object System.Windows.Controls.TextBlock
        $headerBlock.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $titleRun = New-Object System.Windows.Documents.Run($Parts[0].Text)
        $titleRun.FontWeight = [System.Windows.FontWeights]::Bold
        $titleRun.FontSize = 15
        [void]$headerBlock.Inlines.Add($titleRun)
        for ($h = 1; $h -lt $headerCount; $h++) {
            [void]$headerBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
            $subRun = New-Object System.Windows.Documents.Run($Parts[$h].Text)
            $subRun.FontWeight = [System.Windows.FontWeights]::Bold
            [void]$headerBlock.Inlines.Add($subRun)
        }
        [void]$Panel.Children.Add($headerBlock)

        # Separator line
        $sep = New-Object System.Windows.Controls.Border
        $sep.Height = 1
        $sep.Background = New-Object System.Windows.Media.SolidColorBrush(
            [System.Windows.Media.Color]::FromRgb(0xE1, 0xE1, 0xE1))
        $sep.Margin = [System.Windows.Thickness]::new(0, 10, 0, 6)
        [void]$Panel.Children.Add($sep)

        $startIndex = $headerCount
    }
    else {
        $startIndex = 0
    }

    # --- Body parts ---
    for ($i = $startIndex; $i -lt $Parts.Count; $i++) {
        $part = $Parts[$i]
        $numMatch = [regex]::Match($part.Text, '^(\d+\.)\s+')

        if ($part.Indent -and $numMatch.Success) {
            # Numbered item with hanging indent
            $grid = New-Object System.Windows.Controls.Grid
            $col0 = New-Object System.Windows.Controls.ColumnDefinition
            $col0.Width          = [System.Windows.GridLength]::Auto
            $col0.SharedSizeGroup = "BulletNum"
            $col1 = New-Object System.Windows.Controls.ColumnDefinition
            $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            [void]$grid.ColumnDefinitions.Add($col0)
            [void]$grid.ColumnDefinitions.Add($col1)
            $grid.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)

            $numBlock = New-Object System.Windows.Controls.TextBlock
            $numBlock.Text   = $numMatch.Groups[1].Value
            $numBlock.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
            [System.Windows.Controls.Grid]::SetColumn($numBlock, 0)
            [void]$grid.Children.Add($numBlock)

            $textBlock = New-Object System.Windows.Controls.TextBlock
            $textBlock.TextWrapping = [System.Windows.TextWrapping]::Wrap
            Add-TextBlockInlines -TextBlock $textBlock -Text $part.Text.Substring($numMatch.Length) -Bold:$part.Bold
            [System.Windows.Controls.Grid]::SetColumn($textBlock, 1)
            [void]$grid.Children.Add($textBlock)

            [void]$Panel.Children.Add($grid)
        }
        elseif ($part.Indent) {
            # Indented continuation (no number)
            $grid = New-Object System.Windows.Controls.Grid
            $col0 = New-Object System.Windows.Controls.ColumnDefinition
            $col0.Width          = [System.Windows.GridLength]::Auto
            $col0.SharedSizeGroup = "BulletNum"
            $col1 = New-Object System.Windows.Controls.ColumnDefinition
            $col1.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
            [void]$grid.ColumnDefinitions.Add($col0)
            [void]$grid.ColumnDefinitions.Add($col1)
            $grid.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)

            $spacer = New-Object System.Windows.Controls.TextBlock
            $spacer.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
            [System.Windows.Controls.Grid]::SetColumn($spacer, 0)
            [void]$grid.Children.Add($spacer)

            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
            Add-TextBlockInlines -TextBlock $tb -Text $part.Text -Bold:$part.Bold
            [System.Windows.Controls.Grid]::SetColumn($tb, 1)
            [void]$grid.Children.Add($tb)

            [void]$Panel.Children.Add($grid)
        }
        else {
            # Regular paragraph
            $tb = New-Object System.Windows.Controls.TextBlock
            $tb.TextWrapping = [System.Windows.TextWrapping]::Wrap
            $tb.Margin = [System.Windows.Thickness]::new(0, 8, 0, 0)
            Add-TextBlockInlines -TextBlock $tb -Text $part.Text -Bold:$part.Bold
            [void]$Panel.Children.Add($tb)
        }
    }
}
#endregion

#region EULA
$EULARegPath = "HKCU:\Software\Microsoft\CESDiagnosticTools"
$EULARegName = "AdfsEULAAccept"

function Test-EULAAccepted {
    try {
        $val = Get-ItemPropertyValue -Path $EULARegPath -Name $EULARegName -ErrorAction Stop
        return [bool]$val
    } catch {
        return $false
    }
}

function Set-EULAAccepted {
    param([bool]$Accepted)
    if (!(Test-Path $EULARegPath)) {
        New-Item -Path $EULARegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $EULARegPath -Name $EULARegName -Value ([int]$Accepted) -Type DWord
}

function Show-EULADialog {

$eulaParts = @(
    @{ Text = "MICROSOFT SOFTWARE LICENSE TERMS"; Bold = $true }
    @{ Text = "Microsoft Diagnostic Scripts and Utilities"; Bold = $true }
    @{ Text = "These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS."; Bold = $false }
    @{ Text = "1. INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (`"Microsoft`") grants you (`"Customer`" or `"you`") a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the `"Software`"), solely for Customer's internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). `"Use`" means to copy, install, execute, access, display, run or otherwise interact with the Software."; Bold = $false; Indent = $true }
    @{ Text = "You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft's IT systems or impair anyone else's use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above."; Bold = $false; Indent = $true }
    @{ Text = "2. DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at https://aka.ms/privacy . Your use of the Software operates as your consent to these practices."; Bold = $false; Indent = $true }
    @{ Text = "3. FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose. You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation."; Bold = $false; Indent = $true }
    @{ Text = "4. EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit https://aka.ms/exporting ."; Bold = $false; Indent = $true }
    @{ Text = "5. REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party's intellectual property to any other license terms or require the other party to distribute source code to any of its technologies."; Bold = $false; Indent = $true }
    @{ Text = "6. DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED `"AS IS,`" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."; Bold = $false; Indent = $true }
    @{ Text = "7. LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. `$5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages."; Bold = $false; Indent = $true }
    @{ Text = "8. BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States. If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can't, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (`"FAA`"), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at https://aka.ms/arb-agreement-4 . You and Microsoft agree to these terms."; Bold = $false; Indent = $true }
    @{ Text = "9. LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration)."; Bold = $false; Indent = $true }
    @{ Text = "10. ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software."; Bold = $false; Indent = $true }
)

[xml]$eulaXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ADFS Diagnostic Tools - License Agreement"
        Height="800" Width="860" 
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        Background="#F3F3F3">
    <Window.Resources>
        <SolidColorBrush x:Key="AccentBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="AccentHoverBrush" Color="#106EBE"/>
        <SolidColorBrush x:Key="AccentPressedBrush" Color="#005A9E"/>
        <SolidColorBrush x:Key="CardBrush" Color="#FFFFFF"/>
        <SolidColorBrush x:Key="BorderBrush" Color="#E1E1E1"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#1A1A1A"/>
        <FontFamily x:Key="AppFont">Segoe UI</FontFamily>

        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource AccentBrush}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontFamily" Value="{StaticResource AppFont}"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="24,5"/>
            <Setter Property="MinWidth" Value="100"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}" BorderThickness="0">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="{StaticResource AccentHoverBrush}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="{StaticResource AccentPressedBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource CardBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontFamily" Value="{StaticResource AppFont}"/>
            <Setter Property="Padding" Value="24,5"/>
            <Setter Property="MinWidth" Value="100"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                BorderBrush="{TemplateBinding BorderBrush}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#E8E8E8"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#D0D0D0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <StackPanel Grid.Row="0" Margin="0,0,0,8">
            <TextBlock Text="License Agreement" FontSize="20" FontWeight="Bold"
                       FontFamily="{StaticResource AppFont}" Foreground="{StaticResource AccentBrush}"/>
            <Rectangle Height="2" Fill="{StaticResource AccentBrush}" Margin="0,6,0,0"
                       HorizontalAlignment="Left" Width="50" RadiusX="1" RadiusY="1"/>
            <TextBlock Text="Please read the following license agreement carefully before continuing."
                       FontSize="13" FontFamily="{StaticResource AppFont}" Foreground="{StaticResource TextPrimary}"
                       Margin="0,8,0,0"/>
        </StackPanel>

        <Border Grid.Row="1" Background="White" CornerRadius="6"
                BorderBrush="{StaticResource BorderBrush}" BorderThickness="1" Margin="0,4,0,0">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="12,8">
                <StackPanel x:Name="EulaPanel" Grid.IsSharedSizeScope="True"
                            TextBlock.FontSize="13" TextBlock.FontFamily="{StaticResource AppFont}"
                            TextBlock.Foreground="{StaticResource TextPrimary}" TextBlock.LineHeight="20"/>
            </ScrollViewer>
        </Border>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,12,0,0">
            <Button x:Name="AcceptBtn" Content="Accept" Style="{StaticResource PrimaryButton}" Margin="0,0,10,0"/>
            <Button x:Name="DeclineBtn" Content="Decline" Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
    </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $eulaXaml
    $eulaWindow = [Windows.Markup.XamlReader]::Load($reader)

    $eulaPanel  = $eulaWindow.FindName("EulaPanel")
    $acceptBtn  = $eulaWindow.FindName("AcceptBtn")
    $declineBtn = $eulaWindow.FindName("DeclineBtn")

    Build-TextBlockPanel -Panel $eulaPanel -Parts $eulaParts

    $acceptBtn.Add_Click({
        $eulaWindow.Tag = "Accept"
        $eulaWindow.Close()
    })

    $declineBtn.Add_Click({
        $eulaWindow.Tag = "Decline"
        $eulaWindow.Close()
    })

    $null = $eulaWindow.ShowDialog()
    return $eulaWindow.Tag
}
#endregion EULA

Function RunDialog {

$advancedHeader = if (!$IsProxy) { "Advanced Options (can cause service restarts)" } else { "Advanced Options" }
$advancedLabel  = if (!$IsProxy) { "LDAP Traces" } else { "WAP Traces" }

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ADFS Trace Collector"
        Width="860" Height="680"
        WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize"
        Background="#F3F3F3">

    <Window.Resources>
        <!-- Accent color -->
        <SolidColorBrush x:Key="AccentBrush" Color="#0078D4"/>
        <SolidColorBrush x:Key="AccentHoverBrush" Color="#106EBE"/>
        <SolidColorBrush x:Key="AccentPressedBrush" Color="#005A9E"/>
        <SolidColorBrush x:Key="CardBrush" Color="#ffffff"/>
        <SolidColorBrush x:Key="BorderBrush" Color="#E1E1E1"/>
        <SolidColorBrush x:Key="SubtleBrush" Color="#f9f9f9"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#1A1A1A"/>
        <SolidColorBrush x:Key="TextSecondary" Color="#616161"/>
        <SolidColorBrush x:Key="DisabledText" Color="#A0A0A0"/>

        <!-- App Font -->
        <FontFamily x:Key="AppFont">Segoe UI</FontFamily>

        <!-- Modern GroupBox Style -->
        <Style x:Key="ModernGroupBox" TargetType="GroupBox">
            <Setter Property="Margin" Value="0,4,0,0"/>
            <Setter Property="Padding" Value="10,4,10,6"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Background" Value="{StaticResource CardBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="GroupBox">
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <Border Grid.Row="0" Background="{StaticResource SubtleBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="1,1,1,0"
                                    CornerRadius="6,6,0,0" Padding="12,5">
                                <ContentPresenter ContentSource="Header"
                                    TextBlock.FontWeight="SemiBold" TextBlock.FontSize="13"
                                    TextBlock.Foreground="{StaticResource TextPrimary}"/>
                            </Border>
                            <Border Grid.Row="1" Background="{StaticResource CardBrush}"
                                    BorderBrush="{StaticResource BorderBrush}" BorderThickness="1,0,1,1"
                                    CornerRadius="0,0,6,6" Padding="{TemplateBinding Padding}">
                                <ContentPresenter/>
                            </Border>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
                </Setter>
        </Style>

        <!-- Modern CheckBox Style -->
        <Style TargetType="CheckBox">
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontFamily" Value="{StaticResource AppFont}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="Margin" Value="0,4,20,4"/>
            <Setter Property="VerticalContentAlignment" Value="Center"/>
            <Style.Triggers>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Foreground" Value="{StaticResource DisabledText}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- Primary Button Style (OK) -->
        <Style x:Key="PrimaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource AccentBrush}"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontFamily" Value="{StaticResource AppFont}"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="24,5"/>
            <Setter Property="MinWidth" Value="100"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}"
                                BorderThickness="0">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="{StaticResource AccentHoverBrush}"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="{StaticResource AccentPressedBrush}"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Background" Value="#CCE4F7"/>
                                <Setter Property="Foreground" Value="#99BFDF"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Secondary Button Style (Cancel / Browse) -->
        <Style x:Key="SecondaryButton" TargetType="Button">
            <Setter Property="Background" Value="{StaticResource CardBrush}"/>
            <Setter Property="Foreground" Value="{StaticResource TextPrimary}"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontFamily" Value="{StaticResource AppFont}"/>
            <Setter Property="Padding" Value="24,5"/>
            <Setter Property="MinWidth" Value="100"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                BorderBrush="{TemplateBinding BorderBrush}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#E8E8E8"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Background" Value="#D0D0D0"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Modern TextBox Style -->
        <Style TargetType="TextBox">
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontFamily" Value="{StaticResource AppFont}"/>
            <Setter Property="Padding" Value="10,5"/>
            <Setter Property="BorderBrush" Value="{StaticResource BorderBrush}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Background" Value="White"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="border" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="0"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="#ABABAB"/>
                            </Trigger>
                            <Trigger Property="IsFocused" Value="True">
                                <Setter TargetName="border" Property="BorderBrush" Value="{StaticResource AccentBrush}"/>
                                <Setter TargetName="border" Property="BorderThickness" Value="2"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="16">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Title Bar -->
        <StackPanel Grid.Row="0" Margin="0,0,0,8">
            <TextBlock FontWeight="Bold" FontFamily="{StaticResource AppFont}" Foreground="{StaticResource AccentBrush}">
                <Run Text="ADFS Trace Collector" FontSize="20"/>
                <Run Text=" $scriptversion" FontSize="13"/>
            </TextBlock>
            <Rectangle Height="2" Fill="{StaticResource AccentBrush}" Margin="0,6,0,0"
                       HorizontalAlignment="Left" Width="50" RadiusX="1" RadiusY="1"/>
        </StackPanel>

        <!-- Description Area -->
        <Border Grid.Row="1" Background="White" CornerRadius="6"
                BorderBrush="{StaticResource BorderBrush}" BorderThickness="1"
                Margin="0,0,0,4">
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="16,12">
                <StackPanel x:Name="DescriptionPanel" Grid.IsSharedSizeScope="True"
                            TextBlock.FontSize="13" TextBlock.FontFamily="{StaticResource AppFont}"
                            TextBlock.Foreground="{StaticResource TextPrimary}" TextBlock.LineHeight="20"/>
            </ScrollViewer>
        </Border>

        <!-- Scenario Group -->
        <GroupBox Grid.Row="2" Header="Scenario" Style="{StaticResource ModernGroupBox}">
            <Canvas Height="22" Margin="0,2,0,0">
                <CheckBox x:Name="cfgonly" Content="Configuration only" Canvas.Left="0" Canvas.Top="2"/>
                <CheckBox x:Name="TracingMode" Content="Runtime Tracing" Canvas.Left="240" Canvas.Top="2"/>
            </Canvas>
        </GroupBox>

        <!-- Options Row -->
        <Grid Grid.Row="3" Margin="0,4,0,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <GroupBox Grid.Column="0" Header="Options" Style="{StaticResource ModernGroupBox}"
                      Margin="0,0,8,0">
                <Canvas Height="22" Margin="0,2,0,0">
                    <CheckBox x:Name="NetTrace" Content="Include Network Traces" IsEnabled="False" Canvas.Left="0" Canvas.Top="2"/>
                    <CheckBox x:Name="perfc" Content="Include Performance Counter" IsEnabled="False" Canvas.Left="240" Canvas.Top="2"/>
                </Canvas>
            </GroupBox>

            <GroupBox Grid.Column="1" x:Name="AdvancedGroup" Style="{StaticResource ModernGroupBox}"
                      MinWidth="260" Margin="0">
                <WrapPanel Orientation="Horizontal" Margin="0,2,0,0">
                    <CheckBox x:Name="advancedCheck" IsEnabled="False"/>
                </WrapPanel>
            </GroupBox>
        </Grid>

        <!-- Destination Folder -->
        <GroupBox Grid.Row="4" Style="{StaticResource ModernGroupBox}"
                  Header="Destination Folder">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <TextBox x:Name="TargetFolder" Grid.Column="0" Margin="0,4,8,0"
                         VerticalContentAlignment="Center"/>
                <Button x:Name="SelFolder" Grid.Column="1" Content="Browse..."
                        Style="{StaticResource SecondaryButton}" Margin="0,4,0,0"
                        MinWidth="90" Padding="16,5"/>
            </Grid>
        </GroupBox>

        <!-- Action Buttons -->
        <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right"
                    Margin="0,12,0,0">
            <Button x:Name="Okbtn" Content="OK" Style="{StaticResource PrimaryButton}"
                    IsEnabled="False" Margin="0,0,10,0"/>
            <Button x:Name="cnlbtn" Content="Cancel" Style="{StaticResource SecondaryButton}"/>
        </StackPanel>
    </Grid>
</Window>
"@

# Parse XAML
$reader = New-Object System.Xml.XmlNodeReader $xaml
$Window = [Windows.Markup.XamlReader]::Load($reader)

# Get named controls
$DescriptionPanel  = $Window.FindName("DescriptionPanel")
$cfgonly           = $Window.FindName("cfgonly")
$TracingMode       = $Window.FindName("TracingMode")
$NetTrace          = $Window.FindName("NetTrace")
$perfc             = $Window.FindName("perfc")
$AdvancedGroup     = $Window.FindName("AdvancedGroup")
$advancedCheck     = $Window.FindName("advancedCheck")
$TargetFolder      = $Window.FindName("TargetFolder")
$SelFolder         = $Window.FindName("SelFolder")
$Okbtn             = $Window.FindName("Okbtn")
$cnlbtn            = $Window.FindName("cnlbtn")

# Set dynamic header and label for the advanced options
$AdvancedGroup.Header  = $advancedHeader
$advancedCheck.Content = $advancedLabel

# Build the description with inline formatting (Bold support via Runs)
$descriptionParts = @(
    @{ Text = "This script collects diagnostic data from your ADFS environment, including configuration details and related Windows settings."; Bold = $false; Indent = $false }
    @{ Text = "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses; PC names; and user names."; Bold = $false; Indent = $false }
    @{ Text = "When sharing data with Microsoft CSS, a **Secure File Transfer** tool must be used - Discuss this with your support professional and also any concerns you may have."; Bold = $false; Indent = $false }
    @{ Text = "The script supports two scenario:  **Configuration only** and **Runtime tracing**."; Bold = $false; Indent = $false }
    @{ Text = "**Configuration only** collects static configuration information and relevant event logs and is primarily used for port-mortem scenarios and when validating existing configurations."; Bold = $false; Indent = $true }
    @{ Text = "**Runtime tracing** allows for troubleshooting problems that can be actively reproduced. The data collection in Runtime tracing is furthermore extensible through the following options:
`t-***Network Traces*** : *enabled by default* 
`t-***Performance Counters*** : *disabled by default; only need for performance related issues*
`t-***LDAP traces*** : *ADFS servers only; disabled by default - DO NOT enable this option unless required by Microsoft CSS*
`t-***WAP Traces*** : *WAP servers only; disabled by default - use when troubleshooting app publishing*"; Bold = $false; Indent = $true }
    @{ Text = "*unless otherwise instructed we recommend to keep the default options"; Bold = $false; Indent = $true }
    @{ Text = "Type a file path or click Browse to select a destination folder for the collected data. Ensure that the selected location has sufficient free space (expect between **4 GB** and **10 GB**) and that you have write permissions to it."; Bold = $false; Indent = $true }
    @{ Text = "Once you click **OK**, the script collects the configuration informations and prepares the trace logs it. It will pause when preparations are completed awaiting further input. This pause let's you set up tracing on additional farm nodes."; Bold = $false; Indent = $true }
    @{ Text = "When all systems are setup for tracing press '**CTRL + Y**' to start capturing data. Repeat this step on each node you want to run the traces on."; Bold = $false; Indent = $true }
    @{ Text = "The script will confirm when tracing is active and you can then reproduce the problem.
Press '**CTRL + Y**' again to stop the tracing."; Bold = $false; Indent = $true }
    @{ Text = "At compleption, the temporary folder will be compressed into a single **.zip** file at the specified destination folder."; Bold = $false; Indent = $true }
    @{ Text = "**Important:**
`t- try to run the capture during periods of low authentication activity.
`t- the script is intended for short diagnostic sessions - do not leave it running for extended periods.
`t- Security Events: limited to the duration of the runtime trace; last 60 minutes when using configuration only
`t- traces are written to circular buffers inside a temporary folder at the selected path (e.g. C:\tracing\temporary)."; Bold = $false; Indent = $true }
)

Build-TextBlockPanel -Panel $DescriptionPanel -Parts $descriptionParts

# ---- Event Handlers ----

# "Configuration only" checked/unchecked
$cfgonly.Add_Checked({
    $TracingMode.IsEnabled  = $false
    $NetTrace.IsEnabled     = $false
    $perfc.IsEnabled        = $false
    $advancedCheck.IsEnabled = $false
})
$cfgonly.Add_Unchecked({
    $TracingMode.IsEnabled = $true
    $NetTrace.IsEnabled    = $false
})

# "Runtime Tracing" checked/unchecked
$TracingMode.Add_Checked({
    $cfgonly.IsEnabled       = $false
    $NetTrace.IsEnabled      = $true
    $NetTrace.IsChecked      = $true
    $perfc.IsEnabled         = $true
    $advancedCheck.IsEnabled = $true
})
$TracingMode.Add_Unchecked({
    $cfgonly.IsEnabled       = $true
    $NetTrace.IsChecked      = $false
    $NetTrace.IsEnabled      = $false
    $perfc.IsChecked         = $false
    $perfc.IsEnabled         = $false
    $advancedCheck.IsChecked = $false
    $advancedCheck.IsEnabled = $false
})

# Browse button (WPF folder browser — works on Server Core)
$SelFolder.Add_Click({
    $selected = Show-FolderBrowserDialog -InitialPath $TargetFolder.Text
    if ($selected) {
        $TargetFolder.Text = $selected
    }
})

# Validate path on text change
$TargetFolder.Add_TextChanged({
    $Okbtn.IsEnabled = filepathvalidformat $TargetFolder.Text
})

# OK button
$Okbtn.Add_Click({
    $Window.Tag = "OK"
    $Window.Close()
})

# Cancel button
$cnlbtn.Add_Click({
    $Window.Tag = "Cancel"
    $Window.Close()
})

# Show the window
$null = $Window.ShowDialog()

if ($Window.Tag -eq "OK") {
    return New-Object psobject -Property @{
        Path             = $TargetFolder.Text
        TraceEnabled     = $TracingMode.IsChecked
        NetTraceEnabled  = $NetTrace.IsChecked
        ConfigOnly       = $cfgonly.IsChecked
        PerfCounter      = $perfc.IsChecked
        LdapTraceEnabled = if (!$IsProxy) { $advancedCheck.IsChecked } else { $false }
        WAPTraceEnabled  = if ($IsProxy)  { $advancedCheck.IsChecked } else { $false }
    }
}
else {
    Write-Host "Script was canceled by User" -ForegroundColor Red
    exit
}
}

Function Pause { param([String]$Message,[String]$MessageTitle,[String]$MessageC)
   # "ReadKey" is not supported in PowerShell ISE.
   If ($psISE) {
    # Show MessageBox
    [void][System.Windows.MessageBox]::Show($Message, $MessageTitle, 'OK')
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

    # We check ClientAuthIssuer only if a binding was configured. An empty store can cause issues so warn.
    if ($StoreName -eq "ClientAuthIssuer" -and $mycert.Count -eq 0) {
        $mycert = "WARNING: ClientAuthIssuers is configured on an ADFS related binding but the Certificate store is empty. This can break Certificate Based authentication for users"
    }

    return $mycert
}

function Test-IsWID {
    # Try to get the SecurityTokenService object and its configuration DB connection string
    $sts = Get-WmiObject -Namespace root\ADFS -Class SecurityTokenService -ErrorAction SilentlyContinue
    $connectionString = $sts.ConfigurationDatabaseConnectionString
    # Determine if it's using WID or SSEE
    $result = $connectionString -match "##wid" -or $connectionString -match "##ssee"
    #if Wid  get the service status and service account name
    if ($result) {
        $svc = new-object System.ServiceProcess.ServiceController('MSSQL$MICROSOFT##WID')
        $widaccount = [ServiceConfigHelper]::GetServiceAccount($svc.Name)
    }

    return [PSCustomObject]@{
        IsWID                                 = $result
        ConfigurationDatabaseConnectionString = $connectionString
        IsWIDStarted                          = $svc.Status
        WIDServiceAccount                     = $widaccount
    }
}

function Get-ADFSDBStateFromWID {
      
   $dbconfig = Test-IsWID
   $dbstates = @{}
   
   #skip if not WID exit.we shouldnt get this ever since we check before calling this function
    if (!$dbconfig.IsWID) {
        break
    }

    #Verify Service Account for WIDService 
$svcstatustmpl= @'
================ WID Service - Status =================
  Service Status       : {0}
  WID Service Account  : {1}
'@
    $expectedAccount = 'NT SERVICE\MSSQL$MICROSOFT##WID'
    if (!($dbconfig.WIDServiceAccount.IndexOf('_failed') -eq -1)){
        $serviceacc=[string]::Format("Error: An error occurred whilst querying the ServiceAccountName for the Windows Internal Database service. Error Code: {0}`r`n", $dbconfig.WIDServiceAccount)
    } elseif ([string]::Compare($expectedAccount, $dbconfig.WIDServiceAccount, $true) -eq 0  ) {
        $serviceacc=[string]::Format("{0} - Test passed`r`n", $dbconfig.WIDServiceAccount)
    } else {
        $serviceacc=[string]::Format("{0} - Test failed. Expected Account is: {1}`r`n", $dbconfig.WIDServiceAccount, $expectedAccount)
    }
    
    [string]::Format($svcstatustmpl,
                    $(switch ([int]$dbconfig.IsWIDStarted) {
                        ([int][System.ServiceProcess.ServiceControllerStatus]::Running)        { "Running - Test passed" }
                        ([int][System.ServiceProcess.ServiceControllerStatus]::Stopped)        { "Stopped - Test failed" }
                        ([int][System.ServiceProcess.ServiceControllerStatus]::Paused)         { "Paused - Test failed" }
                        ([int][System.ServiceProcess.ServiceControllerStatus]::StartPending)   { "Start Pending - Test failed" }
                        ([int][System.ServiceProcess.ServiceControllerStatus]::StopPending)    { "Stop Pending - Test failed" }
                        default                                                                { "Unknown Status - Test failed" }
                    }),
                    $serviceacc
                    )

   #check if service is running and if then attempt the query
    if ($dbconfig.IsWIDStarted -eq [System.ServiceProcess.ServiceControllerStatus]::Running ) {

    #query basic DB states also retrieve the owner of the DB.
    #general reference on the properties https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-databases-transact-sql?view=sql-server-ver17
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

$dbstatustemplate= @'
============= {0} - Status ============
  Database Access      : {1}
  Database State       : {2}
  Broker enabled       : {3}
  Database Owner       : {4}

'@

    $failed = "Test failed"
    $success= "Test passed"
    $padding=16

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
            return [string]::Format($errtemplate, $_.Exception.InnerException)
        } finally {
            # Close and dispose the connection if it exists
            if ($connection.State -eq 'Open') {
                $connection.Close()
            }
            $connection.Dispose()
        }
        } else {

$errtemplate= @"
Error: Failed to query ADFS database informations from WID.
Details: {0}
"@
            return $([string]::Format($errtemplate, 'WID (Windows Internal Database) service is not running.'))
        }
    
    #loop through the results and format the output
    foreach ($dbname in $dbstates.keys) {
    #access mode is expected to be MULTI_USER. if SINGLE_USER or RESTRICTED_USER is found we show it as failed
        $accmode= switch ($dbstates[$dbname].AccessMode) { 
                 MULTI_USER      { "$($dbstates[$dbname].AccessMode.PadRight($padding)) - $($success)"} 
                 SINGLE_USER     { "$($dbstates[$dbname].AccessMode.PadRight($padding)) - $($failed)" } 
                 RESTRICTED_USER { "$($dbstates[$dbname].AccessMode.PadRight($padding)) - $($failed)" } 
                 }
    # we expect the DB to be online. if any other value is found we show it as failed test
        $dbstate= switch ($dbstates[$dbname].DatabaseState -eq "Online" ) { 
                 true  {"$($dbstates[$dbname].DatabaseState.PadRight($padding)) - $($success)"} 
                 false {"$($dbstates[$dbname].DatabaseState.PadRight($padding)) - $($failed)" } 
                 }
    #broker is expected to be enabled. Else the service may not reload its config after a change was detected (eg after sync)
        $broker = switch ([bool]$dbstates[$dbname].BrokerEnabled) { 
                 true  {"$($dbstates[$dbname].BrokerEnabled.tostring().PadRight($padding)) - $($success)"} 
                 false {"$($dbstates[$dbname].BrokerEnabled.tostring().PadRight($padding)) - $($failed)"} 
                 }

    #format the output
        [string]::Format($dbstatustemplate,
                        ($dbname.PadRight(19)),
                        $accmode,
                        $dbstate,
                        $broker,
                        $dbstates[$dbname].DBOwner
                        )
    }
}

function get-servicesettingsfromdb {
      param(
    [Parameter(Mandatory=$true)]
    [string]$DBConnectionString
    )
    # Validate input
    if ([string]::IsNullOrEmpty($DBConnectionString)) {
        $errMsg = "Error: Database connection string is null or empty."
        throw [System.ArgumentException]::new($errMsg)
    }
    
    #basic validation of the connection string format
    try {
        # Attempt to parse the connection string
        $dbstring = New-Object System.Data.SqlClient.SqlConnectionStringBuilder $DBConnectionString
    }
    catch {
        $errMsg = "Error: Invalid connection string format"
        throw [System.ArgumentException]::new($errMsg,$($_.Exception))
    }
    #Create SQL Connection
    try {
        $connection = new-object system.data.SqlClient.SqlConnection($dbstring.ConnectionString);
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

Function Test-WiaSupportedUseragents {
    # Unsupported user agents may cause issues with WIA authentication on various platforms if internal. In particular mobile apps using webview controls or devices that dont support wia per se
    # usually this is due to using too generic user agents. Update the list as needed. We will extend this list as needed
    $unsupported=@("Mozilla/5.0","Mozilla/4.0","Chrome","FireFox","Safari","Opera","Vivaldi","Brave","OPR","Edg/*","Edge/*","Edg/","Edge/","Edge/12","Webkit/","=~Windows\s*NT.*Edge")
    $agents = (get-adfsproperties).WiasupportedUseragents
    $commonItems=@()
    
    if (!($null -eq $agents) -and !($null -eq $unsupported)) {
        $commonItems = [System.Linq.Enumerable]::Intersect(
                       [System.Collections.Generic.List[object]]@($unsupported),
                       [System.Collections.Generic.List[object]]@($agents)
                       )
     }
     
    if ($commonItems.Count -gt 0) {
        $commonItemsArray = [System.Linq.Enumerable]::ToArray(
                            [System.Collections.Generic.IEnumerable[object]]$commonItems
                            )

        $sb = New-Object System.Text.StringBuilder
        for ($i = 0; $i -lt $commonItemsArray.Length; $i++) {
            [void]$sb.Append("   - ")
            [void]$sb.AppendLine([string]$commonItemsArray[$i])
        }
    
        $msgvalue = [String]::Format(
"Warning: The following WiaSupportUseragents are known to cause unexpected signin issues with certain device platforms:`r`n{0}`The agent string(s) listed are either too generic, lacking device platforms identifiers
or are generally outdated and no longer applicable",$sb)
    
        $message = New-Object -TypeName PSObject
        $message | Add-Member -NotePropertyName 'WiaUserAgentTestResult' -NotePropertyValue $msgvalue
     } else {
        
        $msgvalue = [String]::Format("Informational: WiasupportedUseragents seems to be configured correctly.
If a misconfiguration exists it is currently not known by this script.")
        $message = New-Object -TypeName PSObject
        $message | Add-Member -NotePropertyName 'WiaUserAgentTestResult' -NotePropertyValue $msgvalue
    }
    
    return $message
}

function Get-AzureMFAConfig {
    $dbconfig = Test-IsWID
    #skip if WID is not started as it would definitely fail the query 
    if ($dbconfig.IsWID -and ($dbconfig.IsWIDStarted -ne [System.ServiceProcess.ServiceControllerStatus]::Running )) { 
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
$errmsgformatter=@"
Error: An error occurred whilst attempting to read the MFA Adapter Configuration.
{0}
{1}
{2}
"@
    #try to get config and handle the exception if it occurs try to provide as much info as possible and break on error
    Try {
        $MFAraw= Get-AzureMFAConfig       
    } Catch { 
        #cycle through the exception chain to provide as much info as possible
        $errstr= [string]::Format($errmsgformatter,
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
        
        $adfsreg = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\ADFS")
        
        if ($null -ne $adfsreg) {
            $MFAREG = @('StsUrl','SasUrl','ResourceUri')
            $foundKeys = @()
            
            foreach ($key in $MFAREG) {
            if ($null -ne $adfsreg.GetValue($key)) {
                $foundKeys += $key
            }
            }
            
            if ($foundKeys.Count -eq 0) { 
                $obj | Add-Member -MemberType NoteProperty -Name 'TenantEnvironment' -Value 'Azure MFA has not been configured for Azure Government and will use the default Public environment.'
            }
            else { 
                $obj | Add-Member -MemberType NoteProperty -Name 'TenantEnvironment' -Value 'Registry Entries for Azure Government have been found. Please review the registry'
            
            foreach ($key in $MFAREG) {
                $value = $adfsreg.GetValue($key)
                $obj | Add-Member -MemberType NoteProperty -Name $key -Value $(if ($null -ne $value) { $value } else { 'Key/Value not found' })
            }
            }
            #never forget to close the registry handle
            $adfsreg.Close()
        }
        else {
            $obj | Add-Member -MemberType NoteProperty -Name 'TenantEnvironment' -Value 'Error: ADFS registry key not found'
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

function Get-Widlogs {
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
        Get-Widlogs
        Get-ADFSDBStateFromWID | out-file $env:COMPUTERNAME-ADFS-DatabaseStatus.txt 
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

    if (-not $PSBoundParameters.ContainsKey('Scenario')) {
        "Missing Parameter. You must supply a Scenario. Allowed values: ADFSProxy, ADFSBackend.";
        break;
    }

    if (-not $PSBoundParameters.ContainsKey('Action')) {
        "Missing Parameter. You must supply a Scenario. Allowed values: Create, Enable, Disable, Delete";
        break;
    }

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
    #remove the futureflag from enumeration
    if ($EncType -gt 31) {
        $EncType = $EncType - 2147483616
    }
    #watch out if there is someone configuring the regkeys manually instead via GPO, it might be they use wrong or negative values
   return ([KrbEnum]::EnumerateKrb($EncType))
}

Function Test-ADFSComputerNameEqFarmName {
    param(
    [Parameter(Mandatory=$true)]
    [string]$farmName
    )

$errortmpl=@"
Error: The host computer name '{0}' is identical to the configured ADFS Farmname '{1}'.
This configuration is unsupported and is known to cause the following issues:
    - windows integrated authentication will fail since the kerberos SPN cannot be registered on the service account without causing conflicts
    - failure to perform Remote Management (WinRM)
    - cause WID synchronization issues
    - preventing the setup/use of additional farmnodes
"@
    try
    {
        $netprop = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $computerName = [string]::Format("{0}.{1}",$netprop.HostName,$netprop.Domainname)

        if ($computerName -eq $farmName)
        {
            $testResult = [string]::Format($errortmpl,$computerName.ToUpper(),$farmName.ToUpper())
            return $testResult
        }

        $testResult = "Test passed"
        return $testResult
    }
    catch [Exception]
    {
        return  [string]::format("Error: Failed to verify the computer name and ADFS Farmname are not overlapping. Error {0}", $_.Exception.Message)  
    }
}

Function Test-ADFSFarmnameIsNotCNAME {
    param(
    [Parameter(Mandatory=$true)]
    [string]$farmName
    )  
    try {
        $resolutionResult = [System.Net.Dns]::GetHostEntry($farmname)
        $resolvedHostName = $resolutionResult.HostName

        if ($resolvedHostName -ne $farmname) {
                $testResult = [String]::format("Warning: The ADFS Farm Name '{0}' is resolved as host '{1}'. This might break windows integrated authentication scenarios.`n",$farmname,$resolvedHostName)
                return $testResult
        }
      
        $testResult = "Test passed"
        return $testResult
    } catch [System.Net.Sockets.SocketException] {
        return [string]::format("Error: Could not resolve the farm name {0} with exception '{1}'",$farmname, $_.Exception.Message)
    }
}

function Get-ADFSFarmNameFromSSLBinding {
    try {
        # Get all SSL certificate bindings first
        $sslCertificates = Get-AdfsSslCertificate
        # Find the first valid hostname
        foreach ($cert in $sslCertificates) {
            if (($cert.PortNumber -eq 443) -and 
                ($cert.AppId -eq '5d89a20c-beab-4389-9447-324788eb944a') -and 
                ($cert.HostName -inotlike 'localhost') -and 
                ($cert.HostName -inotlike 'enterpriseregistration*') -and 
                ($cert.HostName -inotlike 'certauth*')) {
                
                # Return the first valid hostname immediately
                return $cert.HostName
            }
        }
        # If no valid hostname found, return $null
        return $null
    }
    catch {
        Write-Warning "Failed to retrieve ADFS SSL certificate bindings: $($_.Exception.Message)"
        return $null
    }
}

function Get-ServiceAccountDetails {
    #initialize  object to store the result: gsad is the accronym of the function name ( g = get, sa = service account, d = details )
    $gsad = New-Object -TypeName PSObject

    #only execute if we are not on proxy/wap
    if (!$IsProxy) {
        #get currently config service account if this fails
        try {
            $svc = new-object System.ServiceProcess.ServiceController('adfssrv')
            $SVCACC = [ServiceConfigHelper]::GetServiceAccount($svc.Name)
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
    $farmname = Get-ADFSFarmNameFromSSLBinding
    
    #hostname may still be empty so we may have failed to find the bindings.
    #let assume ADFS service is running and we can query adfsproperties from powershell
    if ($null -eq $farmname ) {
        try {  
            $farmname = (get-adfsproperties).hostname 
        } catch { }
    }

    # if still no hostname last attempt to get the farmname from DB 
    # this is best effort here and limited to WID. The user may not be a DBA or have access to the SQL server 
    if ($null -eq $farmname ) {
        try {
            $dbconfig = Test-IsWID
            if ($dbconfig.IsWID -and ($dbconfig.IsWIDStarted -ne [System.ServiceProcess.ServiceControllerStatus]::Running )) { 
                $errMsg = "Error: WID (Windows Internal Database) service is not running."
                throw [System.Exception]::new($errMsg)
            }
            if ($null -ne $dbconfig.ConfigurationDatabaseConnectionString) {
            $farmname = (get-servicesettingsfromdb -DBConnectionString $dbconfig.ConfigurationDatabaseConnectionString ).ServiceSettingsData.SecurityTokenService.Host.Name
            }
        } catch {}
    }

    #if we have a hostname lets attempt to perform a check for duplicate SPNs
    #first check create the connection object. Use GlobalCatalog as we may have a dupe in a child domain of the forest
    if (!($null -eq $farmname )) {
        $gconn= (New-Object System.DirectoryServices.DirectoryEntry("GC://$domain/RootDSE")).dnshostname
        $filter= [string]::format("(serviceprincipalname=*/{0})", $farmname ) 
        [string]$att = "*"
    }

    #if we dont have a hostname we didnt cannot create the ldap connection and filter so we dont need to run the query after all
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
            $gsad | Add-Member -MemberType NoteProperty -Name "Duplicate SPN" -Value "Warning: Duplicate SPN check failed.`r`nThe query may have timed-out or may have returned no results.`r`nYou can use 'setspn.exe -f -q */$($farmname)' to query for duplicate SPN's in the forest.`r`n."
        }
    }

    #test for DNS Cname since it can break kerberos auth
    if (!($null -eq $farmname )) {
        $adfscnamecheck = Test-ADFSFarmnameIsNotCNAME -farmName $farmname
        if ($adfscnamecheck -ne "Test passed") { 
            $gsad | Add-Member -MemberType NoteProperty -Name "DNSAliasTestResult" -Value $adfscnamecheck
        } else {
            $gsad | Add-Member -MemberType NoteProperty -Name "DNSAliasTestResult" -Value ( [String]::Format("Success: The ADFS Farmname '{0}' resolves correctly without CNAME indirection.", $farmname) )
        }
    } else {
        $gsad | Add-Member -MemberType NoteProperty -Name "DNSAliasTestResult" -Value "Test skipped. Could not retrieve ADFS farmname from configuration. The service may not be running or is not yet configured"
    }

    #computername must not be identical to farmname else breaks kerberos auth and farm management
    if (!($null -eq $farmname )) {
        $adfseqhostres = Test-ADFSComputerNameEqFarmName -farmName $farmname
        if ($adfseqhostres -ne "Test passed") {
            $gsad | Add-Member -MemberType NoteProperty -Name "Farmname-Computername Check" -Value $adfseqhostres
        } else {
            $gsad | Add-Member -MemberType NoteProperty -Name "Farmname-Computername Check" -Value "Success: ADFS Farmname and Computername are different."
        }
    } else {
        $gsad | Add-Member -MemberType NoteProperty -Name "Farmname-Computername Check" -Value "Test skipped. Could not retrieve ADFS farmname from configuration. The service may not be running or is not yet configured"
    }

    #Finally validate that Kerberos Etype Config is sound and we have a matching config between OS and Service Account
    $RC4NotSetMsg="The Service Account is not configured for AES support. Service tickets will be RC4 encrypted!
    `r`nWe recommend configuring the ADFS Service Account for AES Support.`r`nIn Active Directory configure the attribute 'msds-supportedencryptiontypes' for the ADFS ServiceAccount with a value of:`r`n24(decimal) => AES only `n or `n28(decimal) => AES & RC4" 
    
    $RC4NoPolicysupMsg="The ADFS service account is not configured properly. Local policy/registry for KerberosEncryptionTypes disabled RC4 support,`r`nbut the service account has not been configured for AES support.
    `r`nThis configuration can lead to authentication failures and other erroneous behavior and MUST be corrected.
    `r`nWe recommend configuring the ADFS Service Account for AES Support.`r`nIn Active Directory configure the attribute 'msds-supportedencryptiontypes' for the ADFS ServiceAccount with a value of:`r`n24(decimal) => AES only `n or `n28(decimal) => AES & RC4" 
    
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
            Test-WiaSupportedUseragents | format-list * | Out-file "Get-ADFSproperties.txt" -Append
	        Get-AdfsRelyingPartyTrust | format-list * | Out-file "Get-AdfsRelyingPartyTrust.txt"
        }

	        Get-AdfsSyncProperties | format-list * | Out-file "Get-AdfsSyncProperties.txt"
	        Get-AdfsSslCertificate | format-list * | Out-file "Get-AdfsSslCertificate.txt"
            Get-ServiceAccountDetails | format-list * | Out-file "Get-ServiceAccountDetails.txt"

	if ($WinVer -ge [Version]"10.0.14393") {# ADFS commands specific to ADFS 2016,2019,2022
        if((Get-AdfsSyncProperties).Role -eq 'PrimaryComputer') {
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
	
    if ($WinVer -eq [Version]"6.3.9600") { # ADFS commands specific to ADFS 2012 R2/consolidate this in next release
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
    {   $null {"not configured"} 0 {" explicitly disabled by registry value (0)"} 1 {"explicitly enabled by registry"}  }
    $SDTV= switch ((get-itemproperty -PATH "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319").SystemDefaultTlsVersions)
    {   $null {"not configured"} 0 {" explicitly disabled by registry value (0)"} 1 {"explicitly enabled by registry"}  }

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
    #Queryhistory will fail if HistoryCount returned is 0 so check this before calling QueryHistory to avoid errors in case there is no update history at all on the system
    $updateHistory = if ($historyCount -gt 0 ) { $searcher.QueryHistory(0,$historyCount ) }

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
<h2>.Net Framework Cumulative Updates - History (last 5)</h2>
    $(Get-NetframeworkInstalledUpdates)
</body>
</html>
"@

return $htmlTemplate
}
#endregion
##########################################################################
#region Execution
# EULA check - verify acceptance before proceeding
if ($AcceptEula) {
    Set-EULAAccepted -Accepted $true
    Write-Host "EULA accepted via -AcceptEula parameter" -ForegroundColor Green
}
elseif (!(Test-EULAAccepted)) {
    $eulaResult = Show-EULADialog
    if ($eulaResult -eq "Accept") {
        Set-EULAAccepted -Accepted $true
        Write-Host "EULA accepted" -ForegroundColor Green
    } else {
        Write-Host "EULA declined. Exiting." -ForegroundColor Red
        exit
    }
}

if (IsAdminAccount){
    Write-host "`n`n`n`n`n`n`nScript is executed as Administrator. Resuming execution" -ForegroundColor Green

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
            if(($LDAPTracing.IsPresent -eq $true) -and (!$IsProxy)) {  $LdapTraceEnabled=$true }  
            if(($WAPTracing.IsPresent -eq $true) -and ($IsProxy))  { $WAPTraceEnabled=$true } 
        }
    }

    if(Test-Path -Path $Path) { Write-host "Destinationfolder: '$($Path)' already exists. Starting Data Collection..." -ForegroundColor DarkCyan }
    else {
        Write-host "Destinationfolder: '$($Path)' does not exist. Creating Folder" -ForegroundColor DarkCyan
        New-Item -ItemType directory -Path $Path -Force | Out-Null
    }
    $FEL=$Global:FormatEnumerationLimit  ##secure current EnumLimit.Script should revert to this value at the end of execution
    $Global:FormatEnumerationLimit=-1

    $TraceDir = $Path +"\temporary"
# Save execution output to file
    Write-host "Creating Temporary Folder" -ForegroundColor DarkCyan
    New-Item -ItemType directory -Path $TraceDir -Force | Out-Null
    if($PSVersionTable.PSVersion -le [Version]'4.0') { Start-Transcript -Path "$TraceDir\transscript_output.txt" -Append |out-null} else { Start-Transcript -Path "$TraceDir\transscript_output.txt" -Append -IncludeInvocationHeader |out-null}
    Write-Host "Script version             : "  -ForegroundColor DarkCyan -NoNewline; Write-Host "$($scriptversion)" -ForegroundColor Yellow;
    Write-Host "Debug logs will be saved in: "  -ForegroundColor DarkCyan -NoNewline; Write-Host "$($Path)" -ForegroundColor Yellow;
    Write-Host "Options selected:  TracingEnabled:"$TraceEnabled "NetworkTrace:" $NetTraceEnabled " ConfigOnly:" $ConfigOnly " PerfCounter:" $PerfCounter " LDAPTrace:" $LdapTraceEnabled "WAPTrace:" $WAPTraceEnabled -ForegroundColor DarkCyan
    Write-Progress -Activity "Preparation" -Status 'Setup Data Directory' -percentcomplete 5

    if ($TraceEnabled) {
        $MessageTitle = "Initialization completed`n"
        $MessageIse = "Data Collection is ready to start.`nPrepare other computers to start collecting data.`n`nWhen ready, Click OK to start the collection...`n"
        $MessageC = "`nData Collection is ready to start.`nPrepare other computers to start collecting data.`n`nWhen ready, press CTRL+Y to start the collection...`n"
        Pause $MessageIse $MessageTitle $MessageC
    }

    Write-Host "Tracing started. Current UTC time: "-ForegroundColor DarkCyan -NoNewline; Write-Host "$([DateTime]::UtcNow)" -ForegroundColor Yellow
    Write-Host "Timezone: " -ForegroundColor DarkCyan -NoNewline; Write-Host "$([System.TimeZoneInfo]::Local.DisplayName)" -ForegroundColor Yellow

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

    Write-Host "Tracing ended. Current UTC time: " -ForegroundColor DarkCyan -NoNewline; Write-host "$([DateTime]::UtcNow)" -ForegroundColor Yellow
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
