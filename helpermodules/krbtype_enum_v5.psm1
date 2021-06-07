#HelperModule for Kerberos EncryptionType enumeration
#this Module is used on Windows Servers with Powershell 5.x



[flags()] Enum EncTypes
{
        DES_CBC_CRC             = 0x01
        DES_CBC_MD5             = 0x02
        RC4_HMAC                = 0x04
        AES128_CTS_HMAC_SHA1_96 = 0x08
        AES256_CTS_HMAC_SHA1_96 = 0x10
}
function enumerateKrb ([int]$EncType)
{
  return [regex]::replace(([EncTypes]$EncType), ", "," | ")}

