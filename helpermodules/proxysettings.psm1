##This Module will enumerate Winhttp SystemProxy Settings
##and the Proxy Settings of the currently logged on User

$MethodDefinition = @'
    using System.Runtime.InteropServices;
    public enum AccessType
    {
        DefaultProxy = 0,
        NamedProxy = 3,
        NoProxy = 1,
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
'@
    $asm = Add-Type -TypeDefinition $MethodDefinition -PassThru -ErrorAction SilentlyContinue

function GetProxySettings
    {
    $proxycfg = [PSCustomObject]@{}
    $IEProxyConfig = New-Object WinhttpCurrentUserIeProxyConfig
    [WinHttp]::WinHttpGetIEProxyConfigForCurrentUser([ref]$IEProxyConfig) |Out-Null

    $WINHTTPPROXY = New-Object WINHTTP_PROXY_INFO
    [WinHttp]::WinHttpGetDefaultProxyConfiguration([ref]$WINHTTPPROXY) |Out-Null

    $proxycfg| Add-Member -MemberType NoteProperty -Name 'IE_ProxySetting_CurrentUser' -Value '------------------'
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'IE_ProxySetting_AutoDetect' -Value $IEProxyConfig.AutoDetect
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'IE_ProxySetting_AutoConfigUrl' -Value $IEProxyConfig.AutoConfigUrl
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'IE_ProxySetting_ProxName' -Value $IEProxyConfig.Proxy
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'IE_ProxySetting_ProxyBypass' -Value $IEProxyConfig.ProxyBypass
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'WinHTTP_Proxy_Setting' -Value '------------------'
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'WinHTTP_Proxy_AutoDetect' -Value $WINHTTPPROXY.AccessType
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'WinHTTP_Proxy_ProxName' -Value $WINHTTPPROXY.Proxy
    $proxycfg| Add-Member -MemberType NoteProperty -Name 'WinHTTP_Proxy_ProxyBypass' -Value $WINHTTPPROXY.Bypass

    return $proxycfg
    }
       
