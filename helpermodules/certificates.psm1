function Get-LocalMachineCerts
{
$certs = @()
Get-ChildItem -Path Cert:\LocalMachine\My -recurse `
| Where-Object {$_.PSISContainer -eq $false} `
| foreach-object ({ `
    $obj = New-Object -TypeName PSObject
    $obj |Add-Member -MemberType NoteProperty -Name "PSPath" -Value $_.PSPath
    $obj |Add-Member -MemberType NoteProperty -Name "Issuer" -Value $_.Issuer
    $obj |Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $_.FriendlyName
    $obj |Add-Member -MemberType NoteProperty -Name "Subject" -Value $_.Subject
    $obj |Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $_.NotAfter
    $obj |Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $_.NotBefore
    $obj |Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $_.SerialNumber
    $obj |Add-Member -MemberType NoteProperty -Name "ThumbPrint" -Value $_.Thumbprint
    $obj |Add-Member -MemberType NoteProperty -Name "PrivateKey" -Value $_.HasPrivateKey
    $obj |Add-Member -MemberType NoteProperty -Name "Exportable" -Value $_.PrivateKey.CspKeyContainerInfo.Exportable
    $obj |Add-Member -MemberType NoteProperty -Name "ProviderName" -Value $_.PrivateKey.CspKeyContainerInfo.ProviderName
    $keyspec = (($_.PrivateKey).CspKeyContainerInfo).KeyNumber
    switch ($keyspec) {
        "Exchange"{
            $obj |Add-Member -MemberType NoteProperty -Name "Keyspec" -Value "AT_EXCHANGE"
            break;}
        "Signature"{
            $obj |Add-Member -MemberType NoteProperty -Name "Keyspec" -Value "AT_SIGNATURE"
            break;}
        default{
            $obj |Add-Member -MemberType NoteProperty -Name "Keyspec" -Value "CNG"
            break;}
            }    
            
    $certs += $obj
    $obj = $null
    $keyspec = $null

    })

    return $certs
 }

 function Get-RootCACertificates
{
$certs = @()
Get-ChildItem -Path Cert:\LocalMachine\Root -recurse `
| Where-Object {$_.PSISContainer -eq $false} `
| foreach-object ({ `
    $obj = New-Object -TypeName PSObject
    $obj |Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $_.FriendlyName
    $obj |Add-Member -MemberType NoteProperty -Name "Issuer" -Value $_.Issuer
    $obj |Add-Member -MemberType NoteProperty -Name "Subject" -Value $_.Subject
    $obj |Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $_.NotAfter
    $obj |Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $_.NotBefore
    $obj |Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $_.SerialNumber
    $obj |Add-Member -MemberType NoteProperty -Name "ThumbPrint" -Value $_.Thumbprint
    if($_.subject -ne $_.issuer) {$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Non-Root'}
    else{$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Root'}

    $certsrc=$null
    $ds = "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates\" + $_.Thumbprint
    $gpo = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates\" + $_.Thumbprint
    if([bool](test-path $ds))  {$certsrc = "DirectoryService"}
    if([bool](test-path $gpo)) {$certsrc = "GroupPolicy"}
    if(![string]::IsNullOrEmpty($certsrc))
    {$obj |Add-Member -MemberType NoteProperty -Name "Origin" -Value $certsrc}
    else
    {$obj |Add-Member -MemberType NoteProperty -Name "Origin" -Value 'Registry'}
    $certs += $obj
    $obj = $null
    $keyspec = $null
    })
    return $certs
 }

  function Get-IntermediateCACertificates
{
$certs = @()
Get-ChildItem -Path Cert:\LocalMachine\CA -recurse `
| Where-Object {$_.PSISContainer -eq $false} `
| foreach-object ({ `
    $obj = New-Object -TypeName PSObject
    $obj |Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $_.PSPath
    $obj |Add-Member -MemberType NoteProperty -Name "Issuer" -Value $_.Issuer
    $obj |Add-Member -MemberType NoteProperty -Name "Subject" -Value $_.Subject
    $obj |Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $_.NotAfter
    $obj |Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $_.NotBefore
    $obj |Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $_.SerialNumber
    $obj |Add-Member -MemberType NoteProperty -Name "ThumbPrint" -Value $_.Thumbprint
    if($_.subject -ne $_.issuer) {$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Non-Root'}
    else{$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Root'}

    $certsrc=$null
    $ds = "HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\CA\Certificates\" + $_.Thumbprint
    $gpo = "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates" + $_.Thumbprint
    if([bool](test-path $ds))  {$certsrc = "DirectoryService"}
    if([bool](test-path $gpo)) {$certsrc = "GroupPolicy"}
    if(![string]::IsNullOrEmpty($certsrc))
    {$obj |Add-Member -MemberType NoteProperty -Name "Origin" -Value $certsrc}
    else
    {$obj |Add-Member -MemberType NoteProperty -Name "Origin" -Value 'Registry'}
    $certs += $obj
    $obj = $null
    $keyspec = $null

    })

    return $certs
 } 

   function Get-NTauthCertificates
{
$certs = @()
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\NTAuth\Certificates\* -name blob `
| %{new-object System.Security.Cryptography.X509Certificates.X509Certificate2($_.Blob,$null)} `
| foreach-object ({ `
    $obj = New-Object -TypeName PSObject
    $obj |Add-Member -MemberType NoteProperty -Name "Issuer" -Value $_.Issuer
    $obj |Add-Member -MemberType NoteProperty -Name "Subject" -Value $_.Subject
    $obj |Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $_.NotAfter
    $obj |Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $_.NotBefore
    $obj |Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $_.SerialNumber
    $obj |Add-Member -MemberType NoteProperty -Name "ThumbPrint" -Value $_.Thumbprint
    if($_.subject -ne $_.issuer) {$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Non-Root'}
    else{$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Root'}
    #NTAuth is DS only
    $obj |Add-Member -MemberType NoteProperty -Name "Origin" -Value 'DirectoryService'
    $certs += $obj
    $obj = $null
    $keyspec = $null

    })

    return $certs
 } 

    function Get-ADFSTrustedDevicesCertificates
{
$certs = @()
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\SystemCertificates\AdfsTrustedDevices\Certificates\* -name blob `
| %{new-object System.Security.Cryptography.X509Certificates.X509Certificate2($_.Blob,$null)} `
| foreach-object ({ `
    $obj = New-Object -TypeName PSObject
    $obj |Add-Member -MemberType NoteProperty -Name "Issuer" -Value $_.Issuer
    $obj |Add-Member -MemberType NoteProperty -Name "Subject" -Value $_.Subject
    $obj |Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $_.NotAfter
    $obj |Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $_.NotBefore
    $obj |Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value $_.SerialNumber
    $obj |Add-Member -MemberType NoteProperty -Name "ThumbPrint" -Value $_.Thumbprint
    if($_.subject -ne $_.issuer) {$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Non-Root'}
    else{$obj |Add-Member -MemberType NoteProperty -Name "IsRoot" -Value 'Root'}
    $obj |Add-Member -MemberType NoteProperty -Name "Origin" -Value 'ADFS'
    $certs += $obj
    $obj = $null
    $keyspec = $null

    })

    return $certs
 } 