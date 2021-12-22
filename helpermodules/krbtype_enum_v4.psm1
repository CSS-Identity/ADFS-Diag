#HelperModule for Kerberos EncryptionType enumerations
#this Module is used on Windows Servers without Powershell 5.x
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919

$EncTypes = @{
        "DES-CBC-CRC"             = 1
        "DES-CBC-MD5"             = 2
        "RC4-HMAC"                = 4
        "AES128-CTS-HMAC-SHA1-96" = 8
        "AES256-CTS-HMAC-SHA1-96" = 16
        "FAST_Supported"          = 65536
        "CompoundIdentity"        = 131072
        "Claims_Supported"        = 262144
        "Sid_Compression_Disabled"  = 524288
        }

function enumerateKrb ([int]$EncType)
{
        $KRBflags = [System.Collections.ArrayList]@()
        foreach ($etype in ($EncTypes.GetEnumerator() | Sort-Object -Property Value ))
        { if (($EncType -band $etype.Value) -ne 0) { $KRBflags.Add($etype.Key.ToString()) |out-null } }
        return $KRBflags -join " | "
}
