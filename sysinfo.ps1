$NAME="sysinfo"
$VERSION="0.2"
$DATE="27-08-22"

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = ‘SilentlyContinue’

<#
Sysinfo for Hackers 


Useage
---------
Import-Module .\sysinfo.ps1
sysinfo 



To Do 
------
Check if Admin - then run extra chceks such as getting secpol est. 
print out local and domain groups of the current user 
Tidy the output
check SMB - singing 
remove blank linkes 
cached logons
amsi settings 
more windef settings
last updated 
WinRM 
Bitlocker
another way to get av - program files grep 
smb - enabled , versions, signing 
Read write access on folder...
RDP users who can login
number of logged in users and list them   so  Logged in Users : [2] blah\user1, blah\user2
if bitlocker is off then print off . NOT ENCRYPTED
detect if it is a vm	- is VM: Yes - Vmware
System Language .. maybe keybaord layout
NW  IP address [DHCP/STATIC][INTNAME] 192.168.80.1    ...  have it better

maybe have a focused sysinfo and a full 



add in applocker chceck.  see whats blocked  - $a = Get-AppLockerPolicy -Effective; $a.rulecollections













MSF example 
------------
meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 



winpeas example
-----------------
Hostname: hackpark
ProductName: Windows Server 2012 R2 Standard
EditionID: ServerStandard
ReleaseId: 
BuildBranch: 
CurrentMajorVersionNumber: 
CurrentVersion: 6.3
Architecture: AMD64
ProcessorCount: 2
SystemLang: en-US
KeyboardLang: English (United States)
TimeZone: (UTC-08:00) Pacific Time (US & Canada)
IsVirtualMachine: False
Current Time: 9/3/2022 12:49:16 AM
HighIntegrity: False
PartOfDomain: False
Hotfixes: KB2919355, KB2919442, KB2937220, KB2938772, KB2939471, KB2949621, KB3035131, KB3060716,



Systeminfo example
-----------------
C:\Users\trav>systeminfo

Host Name:                 EARTH
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19044 N/A Build 19044
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          teddy
Registered Organization:
Product ID:                00330-80000-00000-AA805
Original Install Date:     07/04/2021, 08:24:13
System Boot Time:          03/09/2022, 08:13:28
System Manufacturer:       ASUS
System Model:              System Product Name
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 165 Stepping 5 GenuineIntel ~4104 Mhz
BIOS Version:              American Megatrends Inc. 2004, 13/01/2021
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     32,671 MB
Available Physical Memory: 19,627 MB
Virtual Memory: Max Size:  37,535 MB
Virtual Memory: Available: 21,491 MB
Virtual Memory: In Use:    16,044 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\system1
Hotfix(s):                 20 Hotfix(s) Installed.
                           [01]: KB5013624
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4586864
                           [07]: KB4589212
                           [08]: KB5000736
                           [09]: KB5003791
                           [10]: KB5012170
                           [11]: KB5016616
                           [12]: KB5006753
                           [13]: KB5007273
                           [14]: KB5011352
                           [15]: KB5011651
                           [16]: KB5014032
                           [17]: KB5014035
                           [18]: KB5014671
                           [19]: KB5015895
                           [20]: KB5005699
Network Card(s):           7 NIC(s) Installed.
                           [01]: Intel(R) Ethernet Controller (2) I225-V
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.0.1
                                 IP address(es)
                                 [01]: 192.168.0.40
                                 [02]: fe80::a562:6af8:d28a:4a27
                           [02]: VirtualBox Host-Only Ethernet Adapter
                                 Connection Name: VirtualBox Host-Only Network
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.56.1
                                 [02]: fe80::b5d9:2a66:778f:d75a
                           [03]: Nlwt Tun
                                 Connection Name: NordLynx
                                 Status:          Media disconnected
                           [04]: TAP-Windows Adapter V9
                                 Connection Name: Ethernet 2
                                 Status:          Media disconnected
                           [05]: TAP-NordVPN Windows Adapter V9
                                 Connection Name: Ethernet 3
                                 Status:          Media disconnected
                           [06]: VMware Virtual Ethernet Adapter for VMnet1
                                 Connection Name: VMware Network Adapter VMnet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.110.1
                                 [02]: fe80::b54d:7469:58ed:ed21
                           [07]: VMware Virtual Ethernet Adapter for VMnet8
                                 Connection Name: VMware Network Adapter VMnet8
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.46.1
                                 [02]: fe80::5978:24e5:5314:6792
Hyper-V Requirements:      VM Monitor Mode Extensions: Yes
                           Virtualization Enabled In Firmware: Yes
                           Second Level Address Translation: Yes
                           Data Execution Prevention Available: Yes




#>
#########################################################################################################

function sysinfo {
$ProgressPreference = 'SilentlyContinue'	
	
$os_info = gwmi Win32_OperatingSystem
$IsHighIntegrity = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") 2> $null    
$Hostname		= $ENV:COMPUTERNAME 2> $null      
$IPv4			= (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}|findstr /v :) -join ", " 2> $null        		
$IPv6			= (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}|findstr :) -join ", " 2> $null       
$OS				= $os_info.caption + $os_info.CSDVersion 2> $null
$OSBuild			= $os_info.Version 2> $null 
$Arch			= $os_info.OSArchitecture 2> $null     

$UserName		= $(whoami)
$LocalUsers = $($(net user | select -Skip 4| findstr /v "The command completed") -Split ' '  | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "
#$DomainUsers = $($(net user /domain 2>$null| select -Skip 4| findstr /v "The command completed") -Split ' '  | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "      
$LoggedinUsers = $((Get-CimInstance -ClassName Win32_ComputerSystem).Username | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "    
                  
$LogonServer		= $ENV:LOGONSERVER          
$PSVersion       = $PSVersionTable.PSVersion.ToString()
$PSCompatibleVersions    = ($PSVersionTable.PSCompatibleVersions) -join ', '
$LSASSPROTECTION = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1){"Enabled"} Else {"Disabled"}
$LAPS            = If((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1){"Enabled"} Else {"Disabled"}

$ShellIsAdmin = ${env:=::} -eq $null

# RDP
$RDPEnabled = If((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 1).FDenyTSConnections -eq 1){"Disabled"} Else {"Enabled"} 2> $null
$FDenyTSConnections = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 1).FDenyTSConnections 2> $null
$RDPUsers = $($(net localgroup "Remote Desktop Users" | select -Skip 6 | findstr /v "The command completed") -Split ' ' | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", " 2> $null

$CurrentDir=$(Get-Location |%{$_.Path}) 2> $null

$CredSSP=$($(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name AllowEncryptionOracle 2> $null | findstr AllowEncryptionOracle) -replace (' ')) -Split ':' | findstr /v Oracle2> $null      

# UAC - Integrity 
$UAC             = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).EnableLUA -eq 1){"Enabled"} Else {"Disabled (UAC is Disabled)"} 2> $null
$integritylevel=$($(whoami /groups | select-string Label) -Split '\\' | Select-String - | findstr Level).Substring(0,22) -replace "`n",", " -replace "`r",", " 2> $null
 # LocalAccountTokenFilterPolicy = 1 disables local account token filtering for all non-rid500 accounts
$UACLocalAccountTokenFilterPolicy    = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).LocalAccountTokenFilterPolicy -eq 1){"Disabled (PTH likely w/ non-RID500 Local Admins)"} Else {"Enabled (Remote Administration restricted for non-RID500 Local Admins)"} 2> $null
$UACFilterAdministratorToken     	= If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).FilterAdministratorToken -eq 1){"Enabled (RID500 protected)"} Else {"Disabled (PTH likely with RID500 Account)"} 2> $null
$HighIntegrity           			= $IsHighIntegrity 2> $null
		

# Firewall 
$regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
$Private    = If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"} 2> $null
$Domain     = If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"} 2> $null
$Public     = If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"} 2> $null

## Secedit stuff - needs admin to do this 
#secedit /export /cfg temp 2> $null > $null 
#cat .\temp 2> $null | findstr "Password" | findstr /v "MACHINE Clear RequireLogon Age"
#cat .\temp 2> $null |  findstr "Lockout" | findstr /v Software 
#remove-item temp 2> $null > $null 
#

# NLA 
$NLASecurityLayer =$([bool]$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer | findstr SecurityLayer)-replace (' ')) -Split ':' | findstr /v Security 2> $null
$NLAUserAuthentication =$([bool]$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication| findstr UserAuthentication)-replace (' ')) -Split ':' | findstr /v Authentication 2> $null


# Password & Lockout  
$MinimumPasswordLength = $($(net accounts | findstr "length") -replace (' ')) -Split ':' | findstr /v Mini 2> $null
$LockoutThreshold = $($(net accounts | findstr "threshold") -replace (' ')) -Split ':' | findstr /v threshold 2> $null
$LockoutDuration = $($(net accounts | findstr "duration") -replace (' ')) -Split ':' | findstr /v duration 2> $null
$LockoutWindow = $($(net accounts | findstr "window") -replace (' ')) -Split ':' | findstr /v window 2> $null


$ComputerRole = $($(net accounts | findstr "role") -replace (' ')) -Split ':' | findstr /v role 2> $null

# Dotnet 
$dotnetversion=$(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select version |  %{$_.version})  -join ", " 2> $null

# AV
$av=$(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | select displayName | %{$_.displayName}) -join ", " 2> $null

# Bitlocker
$Bitlocker=$(manage-bde.exe  -status C: 2> $null)
$BitlockerStatus=$($(echo $Bitlocker | Select-String "Conversion Status:") -Split ':' | findstr /v "Conversion Status").Trim(" ") 2> $null
$BitlockerPercentage=$($($bitlocker | Select-String "Percentage Encrypted:") -Split ':'| findstr /v "Percentage Encrypted").Trim(" ") 2> $null

# check if VM
$IsVirtual = ((Get-WmiObject Win32_ComputerSystem).model).Contains("Virtual") 2> $null

#winrm
$WinRMENabled = [bool](Test-WSMan -ComputerName . -ErrorAction SilentlyContinue) 2> $null

# chached logons 
$CachedLogons=$($(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount | findstr CachedLogonsCount)-replace (' ')) -Split ':' | findstr /v CachedLogonsCount 2> $null


#########################################################################################################

$sysinfo="C:\windows\temp\sysinfo"

# Build the Table 
Write-Output "BLANK|BLANKy" >  $sysinfo  # this gets ignored

Write-Output "Hostname:|$Hostname" >> $sysinfo
Write-Output "OS:|$OS" >> $sysinfo
Write-Output "OS Build:|$OSBuild" >> $sysinfo
Write-Output "Arch:|$Arch" >> $sysinfo
Write-Output "Computer Role:|$ComputerRole" >> $sysinfo
Write-Output "Is Virtual:|$IsVirtual" >> $sysinfo
Write-Output "Whoami:|$UserName" >> $sysinfo
Write-Output "Logged in Users:|$LoggedinUsers" >> $sysinfo
Write-Output "Admin Shell?:|$ShellIsAdmin"  >> $sysinfo
Write-Output "Current Dir:|$CurrentDir" >> $sysinfo
Write-Output "IPv4:|$IPv4" >> $sysinfo
Write-Output "IPv6:|$IPv6" >> $sysinfo
Write-Output "Domain:|$env:USERDNSDOMAIN" >> $sysinfo
Write-Output "Logon Server:|$Logonserver" >> $sysinfo
Write-Output "Integrity Level:|$integritylevel (Is High Intergirty: $IsHighIntegrity)">> $sysinfo
Write-Output "UAC LocalAccountTokenFilterPolicy:|$UACLocalAccountTokenFilterPolicy">> $sysinfo
Write-Output "UAC FilterAdministratorToken:|$UACFilterAdministratorToken" >> $sysinfo 
Write-Output "Bitlocker:|C:/ $BitlockerStatus ($BitlockerPercentage)" >> $sysinfo
Write-Output "Windows Firewall:|Private:$Private, Domain:$Domain, Public:$Public" >> $sysinfo
Write-Output "AntiVirus:|$av">> $sysinfo
Write-Output "LSASS Proteciton:|$LSASSPROTECTION" >> $sysinfo
Write-Output "Dotnet Verions:|$dotnetversion" >> $sysinfo
Write-Output "PS Verion:|$PSVersion" >> $sysinfo
Write-Output "PS Compatibly:|$PSCompatibleVersions">> $sysinfo
Write-Output "PS Execution Policy:|$(Get-ExecutionPolicy)">> $sysinfo
Write-Output "Password - Minimum Length:|$MinimumPasswordLength characters"  >> $sysinfo
Write-Output "LAPS:|$LAPS" >> $sysinfo
Write-Output "Cached Logons:|$CachedLogons" >> $sysinfo
Write-Output "Lockout - Threshold:|$LockoutThreshold"  >> $sysinfo
Write-Output "Lockout - Duration:|$LockoutDuration mins"  >> $sysinfo
Write-Output "Lockout - Window:|$LockoutWindow mins"  >> $sysinfo
Write-Output "WinRM Enabled:|$WinRMENabled" >> $sysinfo
Write-Output "RDP Enabled:|$RDPEnabled (FDenyTSConnections:$FDenyTSConnections) " >> $sysinfo
Write-Output "RDP Users:|$RDPUsers"  >> $sysinfo
Write-Output "CredSSP (AllowEncryptionOracle):|$CredSSP (2 = Vulnerable, 0 = Forced, 1 = Mitigated)" >> $sysinfo
Write-Output "NLA:|SecurityLayer:$NLASecurityLayer, UserAuthentication:$NLAUserAuthentication" >> $sysinfo



#Write-Output "Groups - Local:|$UserLocalGroups" >> sysinfo
#Write-Output "Groups - Domain:|$UserDomainGroups" >> sysinfo

# print table 
$P = Import-Csv -Path "$sysinfo" -Delimiter '|'
$P  | Format-Table -HideTableHeaders | Out-String -Width 150 | ft 


# cleanup
Remove-Item C:\windows\temp\sysinfo 2> $null > $null
Remove-Item C:\windows\temp\dotnettemp 2> $null > $null
Remove-Item C:\windows\temp\avtemp 2> $null > $null
}