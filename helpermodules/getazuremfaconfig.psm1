#reads the AuthAdapterConfiguration from the Database. This way it can enumerate Secondary ADFS Servers in WID deployments
#checks if AzureMFA has been configured and searches for the AzureMFAClientAuthCertificate in the local store
#additional checks if RegistryKeys for AzureGov are configured

function AzureMFAConfig ()
{   
$ssd = get-servicesettingsfromdb
if($ssd -ne $null)
    { #loop through the AuthAdapters and find the config for AzureMFAAdapter; we might expand this for other adapters if necessary
        foreach ($AmD in $ssd.ServiceSettingsData.SecurityTokenService.AuthenticationMethods.AuthenticationMethodDescriptor)
        { 
            if ($AmD.Identifier -eq "AzureMfaAuthentication" -and (!$AmD.ConfigurationData.IsEmpty))
           {return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($AmD.ConfigurationData))}
        }
    }
}       

function Get-ADFSAzureMfaAdapterconfig
{


$MFAraw= AzureMFAConfig       
if($MFAraw -ne $null)
{   $obj = [PSCustomObject]@{}
        $obj| Add-Member -MemberType NoteProperty -Name 'AdapterConfig' -Value $MFAraw
        if(($MFAraw -as [XML]).ChildNodes.ClientId -ne '981f26a1-7f43-403b-a875-f8b09b8cd720')
        {$obj| Add-Member -MemberType NoteProperty -Name 'Error' -Value 'The configured ClientId is incorrect and does not match the Azure AD MFA ClientId required. Re-run the MFA AdapterConfig and update the ClientID'}
            
        $mfacert= (get-childitem Cert:\LocalMachine\my | where-object {$_.Subject -contains "CN="+ ($MFAraw -as [XML]).ChildNodes.TenantId +", OU=Microsoft AD FS Azure MFA"})
        if(![string]::IsNullOrEmpty($mfacert))
        { 
          $obj| Add-Member -MemberType NoteProperty -Name 'Information' -Value 'A suitable Azure MFA Certificate was found in the store. Verify that the certificate referenced below is properly registered in AzureAD'
          $obj| Add-Member -MemberType NoteProperty -Name 'Subject' -Value $mfacert.Subject
          $obj| Add-Member -MemberType NoteProperty -Name 'Thumbprint' -Value $mfacert.Thumbprint
          $obj| Add-Member -MemberType NoteProperty -Name 'NotAfter' -Value $mfacert.NotAfter
          $obj| Add-Member -MemberType NoteProperty -Name 'NotBefore' -Value $mfacert.NotBefore
          
        }
        else
        {
            #$obj| Add-Member -MemberType NoteProperty -Name 'Critical' -Value 'Could not find an Azure MFA Certificate matching the TenantID in the adapters configuration.'
            $mfacert= get-childitem Cert:\LocalMachine\my | where-object {$_.Subject -match 'OU=Microsoft AD FS Azure MFA'}
            if($mfacert.count -eq '0')
                {
                $obj| Add-Member -MemberType NoteProperty -Name 'Critical' -Value 'There are no Azure MFA Certificates existing in the local machines store'
                }

            if($mfacert.count -eq '1')
                {
                $obj| Add-Member -MemberType NoteProperty -Name 'Warning' -Value 'A Certificate was found in store but it does not match the TenantId in the configuration'
                $obj| Add-Member -MemberType NoteProperty -Name 'Subject' -Value $mfacert.Subject
                $obj| Add-Member -MemberType NoteProperty -Name 'Thumbprint' -Value $mfacert.Thumbprint
                }
            if($mfacert.count -gt '1')
                {
                $obj| Add-Member -MemberType NoteProperty -Name 'Warning' -Value 'More than one suitable Certificate was found in store but none of them matches the TenantId in the configuration'
                }
            
        }
        
        $adfsreg= Get-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\ADFS"
        $MFAREG = 'StsUrl','SasUrl','ResourceUri'
        
        if ($adfsreg.Property -notcontains 'SasUrl' -and $adfsreg.Property -notcontains 'StsUrl' -and $adfsreg.Property -notcontains 'ResourceUri')
            { 
            $obj| Add-Member -MemberType NoteProperty -Name 'TenantEnvironment ' -value 'Azure MFA has not been configured for Azure Government and will use the default Public environment.'}
            else
            { 
            $obj| Add-Member -MemberType NoteProperty -Name 'TenantEnvironment ' -value 'Registry Entries for Azure Government have been found. Please review the registy'
                foreach ($_ in $MFAREG)
                {
                 if($adfsreg.Property -contains $_)
                    { $obj| Add-Member -MemberType NoteProperty -Name $_ -value $adfsreg.GetValue($_) }
                 else
                    { $obj| Add-Member -MemberType NoteProperty -Name $_ -value 'Key does not exist' }
                }
             
            }
        return $obj
}
else
{return "Information:  AzureMFA is not configured in this ADFS Farm." }
}
