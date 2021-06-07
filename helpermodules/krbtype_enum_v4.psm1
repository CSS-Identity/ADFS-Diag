#HelperModule for Kerberos EncryptionType enumerations
#this Module is used on Windows Servers without Powershell 5.x

$EncTypes = @{
        "DES-CBC-CRC"             = 1
        "DES-CBC-MD5"             = 2
        "RC4-HMAC"                = 4
        "AES128-CTS-HMAC-SHA1-96" = 8
        "AES256-CTS-HMAC-SHA1-96" = 16
        }
$KRBflags = [System.Collections.ArrayList]@()
function enumerateKrb ([int]$EncType)
{
        

        foreach ($etype in ($EncTypes.GetEnumerator() | Sort-Object -Property Value ))
        { if (($EncType -band $etype.Value) -ne 0) { $KRBflags.Add($etype.Key.ToString()) |out-null } }
        return $KRBflags -join " | "
}