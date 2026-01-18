net accounts /uniquepw:24

net accounts /maxpwage:365

net accounts /minpwage:1

net accounts /minpwlen:14

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SAM" -Name "RelaxMinimumPasswordLengthLimits" -Value 1 -Type DWord

net accounts /lockoutduration:15

net accounts /lockoutthreshold:5

net accounts /lockoutwindow:15

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 3 -Type DWord

Disable-LocalUser -Name "Guest"

Rename-LocalUser -Name "Administrator" -NewName "saltadmin"

Rename-LocalUser -Name "Guest" -NewName "saltguest"

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "4"

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -Value 1

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -Value 1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "SMBServerNameHardeningLevel" -Value 1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1

New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos" -Name Parameters -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Type DWord

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value 4

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name "Start" -Value 4

Set-Service -Name Wecsvc -StartupType Disabled

Set-Service -Name WMPNetworkSvc -StartupType Disabled

Set-Service -Name icssvc -StartupType Disabled
Stop-Service -Name icssvc -Force

Set-Service -Name WpnService -StartupType Disabled
Stop-Service -Name WpnService -Force

Set-Service -Name PushToInstall -StartupType Disabled
Stop-Service -Name PushToInstall -Force

Set-Service -Name WinRM -StartupType Disabled
Stop-Service -Name WinRM -Force

Set-Service -Name XboxGipSvc -StartupType Disabled
Stop-Service -Name XboxGipSvc -Force

Set-Service -Name XblAuthManager -StartupType Disabled
Stop-Service -Name XblAuthManager -Force

Set-Service -Name XblGameSave -StartupType Disabled
Stop-Service -Name XblGameSave -Force

Set-Service -Name XboxNetApiSvc -StartupType Disabled
Stop-Service -Name XboxNetApiSvc -Force

# Set the log file path for Domain Profile firewall logs
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
New-Item -Path $registryPath -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $registryPath -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\domainfw.log"

# Registry path for the Domain Profile firewall logging settings
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
# Ensure the registry path exists
New-Item -Path $registryPath -ErrorAction SilentlyContinue | Out-Null
# Set the LogFileSize to 16384 KB (16 MB)
Set-ItemProperty -Path $registryPath -Name "LogFileSize" -Value 16384

# Registry path for the Domain Profile firewall logging settings
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
# Ensure the registry path exists
New-Item -Path $registryPath -ErrorAction SilentlyContinue | Out-Null
# Enable logging of dropped packets (set to 1 = Yes)
Set-ItemProperty -Path $registryPath -Name "LogDroppedPackets" -Value 1

# Registry path for the Domain Profile firewall logging settings
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
# Ensure the registry path exists
New-Item -Path $registryPath -ErrorAction SilentlyContinue | Out-Null
# Enable logging of successful connections (set to 1 = Yes)
Set-ItemProperty -Path $registryPath -Name "LogSuccessfulConnections" -Value 1

# Registry path for the Private Profile firewall settings
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
# Ensure the registry path exists
New-Item -Path $registryPath -ErrorAction SilentlyContinue | Out-Null
# Disable firewall notifications (set to 1 = No notifications)
Set-ItemProperty -Path $registryPath -Name "DisableNotifications" -Value 1

# Registry path for Private Profile Logging settings
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# Create the registry key if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the LogFilePath to the recommended log file path
Set-ItemProperty -Path $registryPath -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\privatefw.log"

# Registry path for Private Profile Logging settings
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# Create the registry key if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
# Set the LogFileSize to 16384 KB (16 MB)
Set-ItemProperty -Path $registryPath -Name "LogFileSize" -Value 16384

# Define registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# Create the key if it does not exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set LogDroppedPackets to 1 (enabled)
Set-ItemProperty -Path $regPath -Name "LogDroppedPackets" -Value 1 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
# Ensure the registry key exists
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set LogSuccessfulConnections to 1 (enabled)
Set-ItemProperty -Path $regPath -Name "LogSuccessfulConnections" -Value 1 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set DisableNotifications to 1 to disable notifications
Set-ItemProperty -Path $regPath -Name "DisableNotifications" -Value 1 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
# Create key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set AllowLocalPolicyMerge to 0 to disallow local firewall rules
Set-ItemProperty -Path $regPath -Name "AllowLocalPolicyMerge" -Value 0 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "AllowLocalIPsecPolicyMerge" -Value 0 -Type DWord


$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\publicfw.log" -Type String

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "LogFileSize" -Value 16384 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "LogDroppedPackets" -Value 1 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "LogSuccessfulConnections" -Value 1 -Type DWord

auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable

auditpol /set /subcategory:"Security Group Management" /success:enable /failure:disable

auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

auditpol /set /subcategory:"Plug and Play Events" /success:enable

auditpol /set /subcategory:"Process Creation" /success:enable

auditpol /set /subcategory:"Account Lockout" /failure:enable

auditpol /set /subcategory:"Group Membership" /success:enable

auditpol /set /subcategory:"Logoff" /success:enable

auditpol /set /subcategory:"Logon" /success:enable /failure:enable

AuditPol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

AuditPol /set /subcategory:"Special Logon" /success:enable

AuditPol /set /subcategory:"Detailed File Share" /failure:enable

AuditPol /set /subcategory:"File Share" /success:enable /failure:enable

AuditPol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

AuditPol /set /subcategory:"Removable Storage" /success:enable /failure:enable

AuditPol /set /subcategory:"Audit Policy Change" /success:enable

AuditPol /set /subcategory:"Authentication Policy Change" /success:enable

AuditPol /set /subcategory:"Authorization Policy Change" /success:enable

AuditPol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

AuditPol /set /subcategory:"Other Policy Change Events" /failure:enable

AuditPol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

AuditPol /set /subcategory:"IPsec Driver" /success:enable /failure:enable

AuditPol /set /subcategory:"Other System Events" /success:enable /failure:enable

AuditPol /set /subcategory:"Security State Change" /success:enable /failure:disable

AuditPol /set /subcategory:"Security System Extension" /success:enable /failure:disable

AuditPol /set /subcategory:"System Integrity" /success:enable /failure:enable

# Create the key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Personalization" -Force
}
# Then set the value
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord

# Create the Personalization key if it does not exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Personalization" -Force
}
# Set NoLockScreenSlideshow DWORD to 1 (Enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1 -Type DWord

# Create the InputPersonalization key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "InputPersonalization" -Force
}
# Set AllowInputPersonalization DWORD to 0 (Disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0 -Type DWord

# Create the Explorer key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force
}
# Set AllowOnlineTips DWORD to 0 (Disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0 -Type DWord

# Create the Config key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust" -Name "Config" -Force
}
# Set EnableCertPaddingCheck DWORD to 1 (Enable strict Authenticode signature verification)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" -Name "EnableCertPaddingCheck" -Value 1 -Type DWord


# Create the kernel key if it does not exist
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "kernel" -Force
}
# Set DisableExceptionChainValidation DWORD to 0 to enable SEHOP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord

# Ensure the NetBT Parameters key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT" -Name "Parameters" -Force
}
# Set NodeType DWORD value to 2 (P-node)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
Write-Output "NetBIOS NodeType set to P-node (2). A restart is required for changes to take effect."

# Ensure the Tcpip6 Parameters registry key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6" -Name "Parameters" -Force
}

# Set DisableIPSourceRouting DWORD value to 2 (highest protection, source routing disabled)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Write-Output "IPv6 IP Source Routing disabled (DisableIPSourceRouting = 2). A restart may be required for changes to take effect."

# Ensure the Tcpip Parameters registry key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip" -Name "Parameters" -Force
}
# Set DisableIPSourceRouting DWORD value to 2 (highest protection, source routing disabled)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Write-Output "IPv4 IP Source Routing disabled (DisableIPSourceRouting = 2). A system restart may be required for changes to take effect."

# Ensure the RasMan Parameters registry key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan" -Name "Parameters" -Force
}
# Set DisableSavePassword DWORD value to 1 (prevents saving dial-up/VPN passwords)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "DisableSavePassword" -Value 1 -Type DWord
Write-Output "Saving dial-up and VPN passwords is now disabled (DisableSavePassword = 1)."

# Ensure the Tcpip Parameters registry key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip" -Name "Parameters" -Force
}
# Set EnableICMPRedirect DWORD value to 0 (disables ICMP redirects overriding OSPF)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
Write-Output "ICMP redirects overriding OSPF routes are now disabled (EnableICMPRedirect = 0)."

# Ensure the Tcpip Parameters registry key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip" -Name "Parameters" -Force
}
# Set KeepAliveTime DWORD value to 300000 (milliseconds = 5 minutes)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "KeepAliveTime" -Value 300000 -Type DWord
Write-Output "TCP KeepAliveTime is set to 300,000 milliseconds (5 minutes)."

# Ensure the Tcpip Parameters registry key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip" -Name "Parameters" -Force
}
# Set PerformRouterDiscovery DWORD value to 0 to disable IRDP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "PerformRouterDiscovery" -Value 0 -Type DWord
Write-Output "IRDP (PerformRouterDiscovery) has been disabled."

# Ensure the TCPIP6 Parameters key exists
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6" -Name "Parameters" -Force
}
# Set TcpMaxDataRetransmissions DWORD value to 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
Write-Output "TcpMaxDataRetransmissions (IPv6) set to 3."

# Define registry path and value
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
$regName = "TcpMaxDataRetransmissions"
$regValue = 3
# Check if the registry path exists, create if it doesn't
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry DWORD value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord
# Confirm the value is set
$setValue = Get-ItemProperty -Path $regPath -Name $regName
Write-Output "TcpMaxDataRetransmissions is set to: $($setValue.$regName)"

# Define registry path and value for IPv4 TcpMaxDataRetransmissions
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$regName = "TcpMaxDataRetransmissions"
$regValue = 3
# Check if the registry path exists, create if it doesn't
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the registry DWORD value
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Type DWord
# Confirm the value is set
$setValue = Get-ItemProperty -Path $regPath -Name $regName
Write-Output "TcpMaxDataRetransmissions is set to: $($setValue.$regName)"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DoHPolicy" -Value 2 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1 -Type DWord

$base="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"; @( "\\*\NETLOGON","\\*\SYSVOL" ) | ForEach-Object { if(-not(Test-Path "$base\$_")) { New-Item -Path "$base\$_" -Force | Out-Null }; Set-ItemProperty -Path "$base\$_" -Name "RequireMutualAuthentication" -Value 1 -Type DWord; Set-ItemProperty -Path "$base\$_" -Name "RequireIntegrity" -Value 1 -Type DWord; Set-ItemProperty -Path "$base\$_" -Name "RequirePrivacy" -Value 1 -Type DWord }

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -Value 0xFF -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"; @("DisableFlashConfigRegistrar","DisableInBand802DOT11Registrar","DisableUPnPRegistrar","DisableWPDRegistrar","EnableRegistrars") | ForEach-Object { Set-ItemProperty -Path $regPath -Name $_ -Value 0 -Type DWord }

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 3 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -Type DWord

# Create the key if it doesn't exist
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ErrorAction SilentlyContinue
# Set RedirectionguardPolicy to Enabled (1)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RedirectionguardPolicy" -Value 1 -Type DWord

# Create the key if missing
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ErrorAction SilentlyContinue
# Set RpcUseNamedPipeProtocol to 0 to disable named pipes and enforce RPC over TCP
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RpcUseNamedPipeProtocol" -Value 0 -Type DWord

# Create the registry key if it doesn't exist
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -ErrorAction SilentlyContinue
# Set RpcAuthentication DWORD value to 0 (Default)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RpcAuthentication" -Value 0 -Type DWord

# Create the registry key if it does not exist
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Force -ErrorAction SilentlyContinue
# Set RpcProtocols DWORD value to 7 (Enables RPC over TCP and disables Named Pipes)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RpcProtocols" -Value 7 -Type DWord

# Create the registry path if it doesn't exist
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Force -ErrorAction SilentlyContinue
# Set ForceKerberosForRpc to 1 to enforce Negotiate or higher for RPC authentication
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "ForceKerberosForRpc" -Value 1 -Type DWord

# Create the registry path if it doesn't exist
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Force -ErrorAction SilentlyContinue
# Set RpcTcpPort to 0 to enable dynamic port usage
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RpcTcpPort" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Force -ErrorAction SilentlyContinue
# Set CopyFilesPolicy to 1 (Limit queue-specific files to color profiles)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "CopyFilesPolicy" -Value 1 -Type DWord

# Ensure the PointAndPrint registry path exists
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force -ErrorAction SilentlyContinue
# Set UpdatePromptSettings to 0 (Show warning and elevation prompt)
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -Type DWord

# Ensure the PushNotifications registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force -ErrorAction SilentlyContinue
# Disable cloud application notifications (Turn off WNS)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoCloudApplicationNotification" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecommendedPersonalizedSites" -Type DWord -Value 1

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -Type DWord -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Type DWord -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureKernelShadowStacksLaunch" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -Value 1 -Type DWord -Force; New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name "1" -Value "SBP2\*" -Type String -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDs" -Value 1 -Type DWord -Force; New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name "1" -Value "PCI\CC_0C0A" -Type String -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ErrorAction SilentlyContinue; 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Value @("{d48179be-ec20-11d1-b6b8-00c04fa372a7}", "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}", "{c06ff265-ae09-48f0-812c-16753d7cba83}", "{6bdd1fc1-810f-11d0-bec7-08002be2092f}") -Type MultiString -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ErrorAction SilentlyContinue; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClassesRetroactive" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value 0 -Typ

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoGPOListChanges" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" -Name "ExitOnMSICW" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableHTTPPrinting" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" -Name "NoRegistration" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoPublishingWizard" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "BackupDirectory" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PwdExpirationProtectionEnabled" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "ADPasswordEncryptionEnabled" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordComplexity" -Value 4 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordLength" -Value 15 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PasswordAgeDays" -Value 30 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PostAuthenticationResetDelay" -Value 8 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "PostAuthenticationActions" -Value 3 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel" -Name "International" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings" -Name "f15576e8-98b7-4186-b944-eafa664402d9" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings" -Name "f15576e8-98b7-4186-b944-eafa664402d9" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings" -Name "abfc2519-3608-4c2a-94ea-171b0ed546ab" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "DCSettingIndex" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings" -Name "abfc2519-3608-4c2a-94ea-171b0ed546ab" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" -Name "ACSettingIndex" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider" -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI" -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" -Name "ScenarioExecutionEnabled" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -ErrorAction SilentlyContinue
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "BlockHostedAppAccessWinRT" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord -Force

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -Value 2 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -Value 2 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHardwareEncryption" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVPassphrase" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVAllowUserCert" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVEnforceUserCert" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSAllowSecureBootForIntegrity" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "FVE" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -Value 1 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHardwareEncryption" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSPassphrase" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecovery" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVManageDRA" -Value 1 -Type DWord

# Create the registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
# Set the RDVRecoveryPassword value to 0 (Do not allow 48-digit recovery password)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryPassword" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
# Set RDVRecoveryKey to 0 to disallow 256-bit recovery key usage
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRecoveryKey" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
# Set RDVHideRecoveryPage to 1 to omit recovery options from BitLocker setup wizard
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHideRecoveryPage" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
# Set RDVPassphrase to 0 to disable the use of passwords for removable data drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVPassphrase" -Value 0 -Type DWord

# Create registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue | Out-Null
# Enable the use of smart cards on removable data drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVAllowUserCert" -Value 1 -Type DWord

# Create the registry key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null
}
# Set the policy to require smart card use on removable drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVEnforceUserCert" -Value 1 -Type DWord

# Create the registry key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null
}
# Enable deny write access to non-BitLocker removable drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -Value 1 -Type DWord

# Create the registry key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null
}
# Disable deny write access to drives configured in other organizations
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyCrossOrg" -Value 0 -Type DWord

# Create the registry key if it doesn't exist
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" | Out-Null
}
# Enable disabling of new DMA devices when computer is locked
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord  

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableEnterpriseAuthProxy" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableAppInstaller" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 32768 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 196608 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 32768 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableGraphRecentItems" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Type DWord

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0 -Type DWord -Force
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Value 1 -Type DWord -Force
Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth"

Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules" -Value 1 -Type DWord -Force
Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -Name "ExploitGuard_ASR_Rules"

$ASRRules = @{
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 1  # Block Office communication application from creating child processes
    "3b576869-a4ec-4529-8536-b80a7769e899" = 1  # Block Office applications from creating executable content
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1  # Block abuse of exploited vulnerable signed drivers
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 1  # Block execution of potentially obfuscated scripts
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1  # Block Office applications from injecting code into other processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1  # Block Adobe Reader from creating child processes
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1  # Block Win32 API calls from Office macro
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1  # Block credential stealing from lsass.exe
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1  # Block untrusted and unsigned processes from USB
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1  # Block executable content from email client and webmail
    "d3e037e1-3eb8-44c8-a917-57927947596d" = 1  # Block JS or VBScript from launching downloaded executable content
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1  # Block Office applications from creating child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1  # Block persistence through WMI event subscription
}
$RegPath = "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
# Create key if it doesn't exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}
# Set each ASR rule to enabled (1)
foreach ($rule in $ASRRules.GetEnumerator()) {
    Set-ItemProperty -Path $RegPath -Name $rule.Key -Value $rule.Value -Type DWord -Force
}

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditApplicationGuard" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraMicrophoneRedirection" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0 -Type DWord

# Create the registry path if it does not exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force
# Set the SaveFilesToHost value to 0 (Disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "SaveFilesToHost" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force
# Set the AppHVSIClipboardSettings DWORD to 1 to enable clipboard operation from isolated session to host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIClipboardSettings" -Value 1 -Type DWord

# Create the registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force
# Set AllowAppHVSI_ProviderSet DWORD to 1 to enable MDAG in Managed Mode for Microsoft Edge only
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowAppHVSI_ProviderSet" -Value 1 -Type DWord

# Create the OneDrive policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force
# Set DisableFileSyncNGSC DWORD value to 1 to disable OneDrive sync
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Type DWord

# Create the PushToInstall policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" -Force
# Set DisablePushToInstall DWORD value to 1 to disable Push To Install service
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" -Name "DisablePushToInstall" -Value 1 -Type DWord

# Create the Terminal Services Client policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" -Force
# Set DisableCloudClipboardIntegration DWORD value to 1 to disable cloud clipboard integration
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" -Name "DisableCloudClipboardIntegration" -Value 1 -Type DWord

# Ensure the Terminal Services policy key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
# Set DisablePasswordSaving to 1 to prevent saving passwords
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Type DWord

# Ensure the Terminal Services policy key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
# Disable UI Automation Redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "EnableUiaRedirection" -Value 0 -Type DWord

# Ensure Terminal Services policy key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
# Enable 'Do not allow COM port redirection'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord

# Ensure Terminal Services policy key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
# Enable 'Do not allow COM port redirection'
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord

# Create the Terminal Services policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
# Set the policy to disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord

# Ensure the Terminal Services policy key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
# Set policy to disable location redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLocationRedir" -Value 1 -Type DWord

net user Guest /active:no
(Get-LocalUser -Name "Guest").Enabled  # Confirms the account is disabled (returns False)

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticetext' -Value 'WARNING: This system is for authorized users only. All activity is monitored.'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Value 'Security Warning'

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'legalnoticecaption' -Value 'Authorized Access Only'
(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').legalnoticecaption

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Type DWord
(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters').EnableSecuritySignature

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NTLMMinServerSec' -Value 537395200 -Type DWord
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0').NTLMMinServerSec

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Value 0 -Type DWord
(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').LocalAccountTokenFilterPolicy

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Value 2 -Type DWord
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters').DisableIPSourceRouting

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Value 0 -Type DWord
(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters').EnableICMPRedirect

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableFontProviders' -Value 0 -Type DWord
(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System').EnableFontProviders

@('\\*\NETLOGON','\\*\SYSVOL') | ForEach-Object { $path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\$_"; If (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; Set-ItemProperty -Path $path -Name 'RequireMutualAuthentication' -Value 1 -Type DWord; Set-ItemProperty -Path $path -Name 'RequireIntegrity' -Value 1 -Type DWord; Set-ItemProperty -Path $path -Name 'RequirePrivacy' -Value 1 -Type DWord }

$keys = 'DisableFlashConfigRegistrar','DisableInBand802DOT11Registrar','DisableUPnPRegistrar','DisableWPDRegistrar','EnableRegistrars'; 
$keys | ForEach-Object { Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name $_ -Value 0 -Type DWord }

New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Value 1 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint' -Value 2 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RedirectionguardPolicy' -Value 1 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RpcUseNamedPipeProtocol' -Value 0 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RpcAuthentication' -Value 0 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RpcProtocols' -Value 7 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'ForceKerberosForRpc' -Value 1 -Type DWord

New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' -Name 'RpcTcpPort' -Value 0 -Type DWord

# Create DeviceGuard key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null
# Enable Virtualization Based Security
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord

# Create DeviceGuard key if not present
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null
# Set RequirePlatformSecurityFeatures to 3 (Secure Boot and DMA Protection)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord

# Ensure the DeviceGuard key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null
# Set HypervisorEnforcedCodeIntegrity to 1 (Enabled with UEFI lock)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord

# Ensure DeviceGuard key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null
# Set HVCIMATRequired to 1 (Enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -Value 1 -Type DWord

# Ensure DeviceGuard key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null
# Set LsaCfgFlags to 1 (Enabled with UEFI lock)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 1 -Type DWord

# Ensure DeviceGuard key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null
# Enable Kernel-mode Hardware-enforced Stack Protection (value = 1)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureKernelShadowStacksLaunch" -Value 1 -Type DWord

# Verify current setting
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoBackgroundPolicy
# To set value to 0 (apply policy during background processing)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoBackgroundPolicy -Value 0 -Type DWord

# Verify current setting
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges
# To set value to 0 (process even if GPOs have not changed)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges -Value 0 -Type DWord

# Check current value
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name NoBackgroundPolicy
# Set to 0 to apply security policy during background processing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name NoBackgroundPolicy -Value 0 -Type DWord

# Check current value
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name NoGPOListChanges
# Set to 0 (enabled: TRUE)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name NoGPOListChanges -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoOnlinePrintsWizard" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Value 2 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" -Name "BlockUserInputMethodsForSignIn" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
# Set the value to disable picture password sign-in
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
# Set the value to disable cross-device clipboard synchronization
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCrossDeviceClipboard" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
# Set the value to disable upload of User Activities
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Disable Solicited Remote Assistance
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -ErrorAction SilentlyContinue
# Set DisableQueryRemoteServer to 1 to disable interactive communication
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 1 -Type DWord

# Ensure the registry key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -ErrorAction SilentlyContinue
# Set Enabled to 1 to enable the Windows NTP Client
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord

# Remove FDVDiscoveryVolumeType value or ensure it is not set
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVDiscoveryVolumeType" -ErrorAction SilentlyContinue

# Enable BitLocker fixed drive recovery policy
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecovery" -Value 1 -PropertyType DWord -Force

# Enable Allow Data Recovery Agent for BitLocker fixed drives
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVManageDRA" -Value 1 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryPassword" -Value 2 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRecoveryKey" -Value 2 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVHideRecoveryPage" -Value 1 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 0 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryInfoToStore" -Value 1 -PropertyType DWord -Force

New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVRequireActiveDirectoryBackup" -Value 0 -PropertyType DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Value 0 -Type DWord

# Create the registry key path if it does not exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
# Set the value UseTPMPIN to 1 to require a startup PIN with TPM
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord

# Create the registry key path if it does not exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
# Set RDVDiscoveryVolumeType to an empty string to disable access from earlier Windows versions
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDiscoveryVolumeType" -Value "" -Type String

# Ensure the registry key path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
# Set RDVActiveDirectoryBackup to 0 to disable saving BitLocker recovery info for removable drives to AD DS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryBackup" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableMPR" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "WindowsInkWorkspace" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "WindowsInkWorkspace" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Windows\GameDVR" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "ServiceEnabled" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse" -Value 1

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -ErrorAction SilentlyContinue
# Set the NotifyMalicious DWORD to 1 (Enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyMalicious" -Value 1

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -ErrorAction SilentlyContinue
# Set the CaptureThreatWindow DWORD to 1 (Enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "CaptureThreatWindow" -Value 1

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -ErrorAction SilentlyContinue
# Set AllowNewsAndInterests DWORD to 0 (Disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0

# Create the registry key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue
# Set RemoveWindowsStore DWORD value to 1 to disable the Microsoft Store
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1

# Create the registry key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue
# Set DisableOSUpgrade DWORD value to 1 to disable the offer to upgrade OS via Microsoft Store
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1

# Create the registry key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue
# Set RequirePrivateStoreOnly DWORD value to 1 to only display the private store in Microsoft Store
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RequirePrivateStoreOnly" -Value 1

# Create the key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -ErrorAction SilentlyContinue
# Set DisableStoreApps to 0 (policy Disabled, apps allowed)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value 0

# Create the key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -ErrorAction SilentlyContinue
# Set NoGenTicket to 1 to turn off KMS Client Online AVS Validation
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Value 1 -Type DWord

# Create key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue
# Set EnableDynamicContentInWSB to 0 to disable search highlights
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 -Type DWord

# Create key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue
# Disable Cortana and Search using location
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord

# Create key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue
# Disable Cortana interaction above lock screen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord

# Create key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue
# Disable Cortana
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord

# Create key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ErrorAction SilentlyContinue
# Disable Cloud Search by setting AllowCloudSearch to 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -Type DWord

# Create key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ErrorAction SilentlyContinue
# Disable enclosure download by setting DisableEnclosureDownload to 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord

# Create key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set MaxDisconnectionTime to 60000 (1 minute)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 60000 -Type DWord

# Create key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set MaxIdleTime to 900000 (15 minutes)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000 -Type DWord

# Create key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set SecurityLayer to 2 (SSL/TLS)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2 -Type DWord

# Create key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set fEncryptRPCTraffic to 1 (enable secure RPC)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord

# Ensure the registry key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set fPromptForPassword to 1 (enable prompt)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue
# Set fDisableWebAuthn to 1 to block WebAuthn redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableWebAuthn" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue
# Set fDisablePNPRedir to 1 to block PnP device redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue
# Set fDisableLPT to 1 to block LPT port redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue
# Set fDisableCdm to 1 to disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord

# Create registry path if not present
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force -ErrorAction SilentlyContinue
# Set COM port redirection to disabled
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
# Disable UI Automation redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "EnableUiaRedirection" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
# Disable password saving in Remote Desktop Connection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" -Force | Out-Null
# Disable cloud clipboard integration for server-to-client clipboard redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" -Name "DisableCloudClipboardIntegration" -Value 1 -Type DWord

# Create registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
# Disable News and Interests on the taskbar
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0 -Type DWord

# Create registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force | Out-Null
# Enable clipboard from isolated session to the host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIClipboardSettings" -Value 1 -Type DWord

# Create registry key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force | Out-Null
# Disable file download/save to host OS from MDAG container
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "SaveFilesToHost" -Value 0 -Type DWord

# Create registry key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force | Out-Null
# Disable data persistence in MDAG container
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0 -Type DWord

# Create registry key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force | Out-Null
# Disable camera and microphone access inside MDAG container
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraMicrophoneRedirection" -Value 0 -Type DWord

# Create registry key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Force | Out-Null
# Enable auditing of MDAG events
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AuditApplicationGuard" -Value 1 -Type DWord

# Create registry key if missing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force | Out-Null
# Enable email scanning (DisableEmailScanning = 0 means scanning enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableEmailScanning" -Value 0 -Type DWord

# Ensure registry key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force | Out-Null
# Enable scanning of removable drives (0 = enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRemovableDriveScanning" -Value 0 -Type DWord

# Ensure the registry key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Force | Out-Null
# Disable Watson event reporting (1 = disabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "DisableGenericRePorts" -Value 1 -Type DWord

# Create or ensure the registry key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Force | Out-Null
# Enable file hash computation (1 = enabled)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -Value 1 -Type DWord

# Create or ensure the registry key exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Force | Out-Null
# Enable Network Protection (1 = enabled, block)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" -Name "EnableNetworkProtection" -Value 1 -Type DWord

$path = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'ExploitGuard_ASR_Rules' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'DisableUserAuth' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'AllowMessageSync' -Value 0 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'MaxSize' -Value 32768 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'MaxSize' -Value 32768 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'MaxSize' -Value 196608 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'MaxSize' -Value 32768 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'EnableHashOverride' -Value 0 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'EnableExperimentalFeatures' -Value 0 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'EnableAppInstaller' -Value 0 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $path -Name 'LimitDiagnosticLogCollection' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
# Create the key if it does not exist
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
# Set EnableOneSettingsAuditing to 1 (Enabled)
Set-ItemProperty -Path $path -Name 'EnableOneSettingsAuditing' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
# Create the registry key if it does not exist
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
# Set DoNotShowFeedbackNotifications to 1 (Enabled)
Set-ItemProperty -Path $path -Name 'DoNotShowFeedbackNotifications' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
# Create the key if it does not exist
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
# Set DisableOneSettingsDownloads to 1 (Enabled)
Set-ItemProperty -Path $path -Name 'DisableOneSettingsDownloads' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
# Create the registry key if it does not exist
New-Item -Path $path -ErrorAction SilentlyContinue | Out-Null
# Set DisableEnterpriseAuthProxy to 1 (Enabled)
Set-ItemProperty -Path $path -Name 'DisableEnterpriseAuthProxy' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
# Create the registry key if it does not exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}
# Set AllowTelemetry to 0 (Diagnostic data off) or 1 (Send required diagnostic data)
# Change the value below to 0 or 1 depending on your environment
$desiredValue = 1
Set-ItemProperty -Path $path -Name 'AllowTelemetry' -Value $desiredValue -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
# Create the registry key if it does not exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}
# Set DisableCloudOptimizedContent to 1 to enable the policy (turn off cloud optimized content)
Set-ItemProperty -Path $path -Name 'DisableCloudOptimizedContent' -Value 1 -Type DWord

$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
# Create the registry key if it does not exist
if (-not (Test-Path $path)) {
    New-Item -Path $path -Force | Out-Null
}
# Set DisableConsumerAccountStateContent to 1 to enable the policy (turn off cloud consumer account state content)
Set-ItemProperty -Path $path -Name 'DisableConsumerAccountStateContent' -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVHardwareEncryption" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVActiveDirectoryInfoToStore" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Value 0 -Type DWord

# Create the registry key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
# Set OSRecoveryPassword to 1 to require the 48-digit recovery password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -Value 1 -Type DWord

# Create the key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -ErrorAction SilentlyContinue
# Set FDVActiveDirectoryBackup to 0 to disable saving recovery info to AD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 0 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; if (Test-Path "$regPath\FDVDiscoveryVolumeType") { Remove-ItemProperty -Path $regPath -Name 'FDVDiscoveryVolumeType' }

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'Enabled' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'DisableQueryRemoteServer' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'BlockUserInputMethodsForSignIn' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'CEIPEnable' -Value 0 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }; Set-ItemProperty -Path $regPath -Name 'CEIP' -Value 2 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }; Set-ItemProperty -Path $regPath -Name 'DisableHTTPPrinting' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'DisableWebPnPDownload' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'NoGPOListChanges' -Value 0 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'NoBackgroundPolicy' -Value 0 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'NoGPOListChanges' -Value 0 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'NoBackgroundPolicy' -Value 0 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'LsaCfgFlags' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'HVCIMATRequired' -Value 1 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'RequirePlatformSecurityFeatures' -Value 3 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'EnableVirtualizationBasedSecurity' -Value 1 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name 'UpdatePromptSettings' -Value 1 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'CopyFilesPolicy' -Value 1 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'ForceKerberosForRpc' -Value 1 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'RpcProtocols' -Value 7 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'RpcAuthentication' -Value 0 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set RpcUseNamedPipeProtocol to 1 to force RPC over TCP and prevent named pipes usage
Set-ItemProperty -Path $regPath -Name 'RpcUseNamedPipeProtocol' -Value 1 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'RedirectionguardPolicy' -Value 1 -Type DWord

$regPath = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'RegisterSpoolerRemoteRpcEndPoint' -Value 2 -Type DWord

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name 'DisableFlashConfigRegistrar' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'DisableInBand802DOT11Registrar' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'DisableUPnPRegistrar' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'DisableWPDRegistrar' -Value 1 -Type DWord
Set-ItemProperty -Path $regPath -Name 'EnableRegistrars' -Value 0 -Type DWord

$basePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
# Create keys if they don't exist
$paths = @('\\*\NETLOGON', '\\*\SYSVOL')
foreach ($path in $paths) {
    $fullPath = Join-Path $basePath $path
    if (-not (Test-Path $fullPath)) {
        New-Item -Path $fullPath -Force | Out-Null
    }

    Set-ItemProperty -Path $fullPath -Name 'RequireMutualAuthentication' -Value 1 -Type DWord
    Set-ItemProperty -Path $fullPath -Name 'RequireIntegrity' -Value 1 -Type DWord
    Set-ItemProperty -Path $fullPath -Name 'RequirePrivacy' -Value 1 -Type DWord  # Optional, enable only if environment supports SMB encryption
}

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -PropertyType DWord -Force
Write-Output "ICMP redirects are now disabled to prevent OSPF override."

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -PropertyType DWord -Force
Write-Output "IP source routing disabled (highest protection)."

$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
New-Item -Path $path -Force | Out-Null
@("DisableFlashConfigRegistrar","DisableInBand802DOT11Registrar","DisableUPnPRegistrar","DisableWPDRegistrar") | ForEach-Object { New-ItemProperty -Path $path -Name $_ -Value 1 -PropertyType DWord -Force }
New-ItemProperty -Path $path -Name "EnableRegistrars" -Value 0 -PropertyType DWord -Force

$path = "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
New-Item -Path $path -Force | Out-Null
New-ItemProperty -Path $path -Name "UpdatePromptSettings" -Value 1 -PropertyType DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\NETLOGON" -Value "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1"; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name "\\*\SYSVOL" -Value "RequireMutualAuthentication=1,RequireIntegrity=1,RequirePrivacy=1"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableFlashConfigRegistrar" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableInBand802DOT11Registrar" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableUPnPRegistrar" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "DisableWPDRegistrar" -Value 1; Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" -Name "EnableRegistrars" -Value 0

New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" -Name "DisableQueryRemoteServer" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVDiscoveryVolumeType" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "FDVActiveDirectoryBackup" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryPassword" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRecoveryKey" -Value 0 -Type DWord

# Create the registry path if it does not exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
# Set the policy to omit recovery options from the BitLocker setup wizard
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSHideRecoveryPage" -Value 1 -Type DWord

# Create the registry path if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
# Set the policy to "Do not allow TPM" by setting UseTPM to 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPM" -Value 0 -Type DWord

# Ensure the BitLocker policy registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
# Enable Require startup PIN with TPM by setting UseTPMPIN to 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 1 -Type DWord

# Ensure the BitLocker policy registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Force
# Set RDVRequireActiveDirectoryBackup to 0 (Disabled / False)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVRequireActiveDirectoryBackup" -Value 0 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Force
# Set MaxSize to 32768 KB (32 MB) or greater
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 32768 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force
# Set MaxSize to 196608 KB (192 MB) or greater
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 196608 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Force
# Set MaxSize to 32768 KB (32 MB) or greater
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord

# Ensure the registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Force
# Set MaxSize to 32768 KB (32 MB) or greater
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 32768 -Type DWord

$ASRRules = @(
    "26190899-1602-49E8-8B27-EB1D0A1CE869",
    "3B576869-A4EC-4529-8536-B80A7769E899",
    "56A863A9-875E-4185-98A7-B882C64B5CE5",
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
    "D3E037E1-3EB8-44C8-A917-57927947596D",
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
)

$regPath = "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
New-Item -Path $regPath -Force | Out-Null

foreach ($rule in $ASRRules) {
    Set-ItemProperty -Path $regPath -Name $rule -Value 1 -Type DWord
}

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowCameraMicrophoneRedirection" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowPersistence" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "SaveFilesToHost" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AppHVSIClipboardSettings" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" -Name "AllowAppHVSI_ProviderSet" -Value 1 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "EnableUiaRedirection" -Value 0 -Type DWord

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCcm" -Value 1 -Type DWord

# Ensure the Terminal Services policy registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set the fDisableCdm DWORD to 1 to disable drive redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord

# Ensure the Terminal Services policy registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set the fDisableLocationRedir DWORD to 1 to disable location redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLocationRedir" -Value 1 -Type DWord

# Ensure the Terminal Services policy registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set the fDisableLPT DWORD to 1 to disable LPT port redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableLPT" -Value 1 -Type DWord

# Ensure the Terminal Services policy registry path exists
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set the fDisablePNPRedir DWORD to 1 to disable Plug and Play device redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisablePNPRedir" -Value 1 -Type DWord

# Create the Terminal Services policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set fDisableWebAuthn DWORD to 1 to disable WebAuthn redirection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableWebAuthn" -Value 1

# Create the Terminal Services policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set fPromptForPassword DWORD to 1 to always prompt for password upon connection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fPromptForPassword" -Value 1 -Type DWord

# Create the Terminal Services policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set fEncryptRPCTraffic DWORD to 1 to require secure RPC communication for Remote Desktop Services
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord

# Create the Terminal Services policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set SecurityLayer DWORD to 2 to enforce TLS (SSL) for RDP connections
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -Value 2 -Type DWord

# Create the Terminal Services policy key if it doesn't exist
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set MaxIdleTime DWORD to 900000 (15 minutes in milliseconds)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 900000 -Type DWord

# Create Terminal Services key if not existing
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
# Set MaxDisconnectionTime to 60000 milliseconds (1 minute)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 60000 -Type DWord

# Define the registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
# Check if the path exists, create if it doesn't
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set the NoGenTicket DWORD value to 1
Set-ItemProperty -Path $regPath -Name "NoGenTicket" -Value 1 -Type DWord

# Registry path
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set DisableStoreApps to 0 (meaning Store apps allowed)
Set-ItemProperty -Path $regPath -Name "DisableStoreApps" -Value 0 -Type DWord

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
# Create the registry path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Set CaptureThreatWindow to 1 to enable data collection
Set-ItemProperty -Path $regPath -Name "CaptureThreatWindow" -Value 1 -Type DWord
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"

# Create the registry path if missing
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
# Enable NotifyMalicious
Set-ItemProperty -Path $regPath -Name "NotifyMalicious" -Value 1 -Type DWord

