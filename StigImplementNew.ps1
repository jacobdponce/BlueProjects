#first run Set-ExecutionPolicy RemoteSigned -User CurrentUser
Install-Module -Name PolicyFileEditor -Confirm
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device -Value DevicePasswordLessBuildVersion 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name fMinimizeConnections -Value 3 
#This value does not exist# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\" -Name PreventCertErrorOverrides -Value 1 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuirtySignature -Value 1 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -Value 1 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -Value 1 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -Value 0x20080000 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -Value 0x20080000 
#This value does not exist# Set-ItemProperty -Path "HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Edge" -Name EnableOnlineRevocationChecks -Value 1 
#This value does not exist# Set-ItemProperty -Path "HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Edge" -Name QuicAllowed -Value 0 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name MaximumPasswordAge -Value 30 
BCDEDIT /set "{current}" nx OptOut 
#This value does not exist#Set-ItemProperty -Path "HKLM:\SYSTEM\Policies\Microsoft\Windows\DeviceGuard" -Name LsaCfgFlags -Value 1 
#Rename-LocalUser -Name "Administrator" -NewName "16 AF Magic Admin" 
#Rename-LocalUser -Name "Guest" -NewName "16 AF Magic Guest" | Get-LocalUser Guest | Disable-LocalUser "16 AF Magic Guest" 
# Loop through each profile on the machine</p>
Foreach ($UserProfile in $UserProfiles) {
    # Load User ntuser.dat if it's not already loaded
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
    }
# Manipulate the registry
#REVIEW THIS# $key = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
New-Item -Path $key -Force | Out-Null
Set-ItemProperty -Path $key -Name "State" -Value 0x23C00 -PropertyType STRING -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name AllowStrongNameBypass -Value 0  
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name AllowStrongNameBypass -Value 0 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -Value 1 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -Value 1 
#This value does not exist# Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name ProxySettings -Value auto_detect 
Get-ChildItem *.pfx | foreach { Remove-Item -Path "C:\" }
Get-ChildItem *.pfx | foreach { Remove-Item -Path "D:\" }
Get-ChildItem *.pfx | foreach { Remove-Item -Path "C:\" }
Get-ChildItem *.pfx | foreach { Remove-Item -Path "D:\" }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name EccCurves -Value "NistP384 NistP256" 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoPreviewPane -Value 1 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableThirdPartySuggestions -Value 1 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work product are private and confidential.  See User Agreement for details." 

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeCaption -Value "DoD Notice and Consent Banner", "US Department of Defense Warning Statement" 




#$Pin = ConvertTo-SecureString "205020" -AsPlainText -Force
#Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -Pin $Pin -TpmAndPinProtector -UsedSpaceOnly
#Enable-BitLocker -MountPoint "D:" -EncryptionMethod Aes256 -Pin $Pin -TpmAndPinProtector -UsedSpaceOnly 