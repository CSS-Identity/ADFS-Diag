#HelperModule for Kerberos EncryptionType enumeration
#this Module is used on Windows Servers with Powershell 5.x
#https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919


[flags()] Enum EncTypes
{
        DES_CBC_CRC             = 0x01
        DES_CBC_MD5             = 0x02
        RC4_HMAC                = 0x04
        AES128_CTS_HMAC_SHA1_96 = 0x08
        AES256_CTS_HMAC_SHA1_96 = 0x10
        FAST_Supported          = 0x10000
        CompoundIdentity        = 0x20000
        Claims_Supported        = 0x40000
        Sid_Compression_Disabled  = 0x80000
}
function enumerateKrb ([int]$EncType)
{
  [string]$ety = ([EncTypes]$EncType)
  # | ForEach-Object { $_.Trim() }
  return $ety.Split(",").TrimEnd().TrimStart() 
}
