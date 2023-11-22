$NAME="sysinfo"
$VERSION="0.2"
$DATE="22-11-23"

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = ‘SilentlyContinue’

<#
Sysinfo for Hackers 


Useage
---------
Import-Module .\sysinfo.ps1
sysinfo


.\sysinfo.ps1


To Do 
------
Check if Admin - then run extra chceks such as getting secpol est. 
sort high integrity make it look better
section is suished on CS
print out local and domain groups of the current user 
Tidy the output
check wmi remote enabled
get logon server via diff methods
$host 
check language 
SMB version, check SMB - singing 
WinRM Enabled and settings
LDAP Signing if LDAP enabled 
remove blank linkes 
amsi settings 
more windef settings
last updated 
WinRM enabled?
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


add in more checks for RDP
;Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" | findstr fDenyTSConnections;Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' | findstr /c:"SecurityLayer" /c:"UserAuthentication";Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name AllowEncryptionOracle | findstr AllowEncryptionOracle;net localgroup "Remote Desktop Users"





Resources
----------------
https://github.com/S3cur3Th1sSh1t/Cobaltstrike-Aggressor-Scripts-Collection/blob/master/EnumKit/scripts/HostRecon.ps1
	good av checks
https://github.com/S3cur3Th1sSh1t/Cobaltstrike-Aggressor-Scripts-Collection/blob/master/EnumKit/scripts/HostEnum.ps1







Seatbelt

  ConsentPromptBehaviorAdmin     : 5 - PromptForNonWindowsBinaries
  EnableLUA (Is UAC enabled?)    : 1
  LocalAccountTokenFilterPolicy  : 
  FilterAdministratorToken       : 0



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


function Set-WindowSize {

<#
.SYNOPSIS
Sets the current console window to a specified size
 
.DESCRIPTION
Sets the current console window to a specified size.
Alternatively it can be maximized.
 
.EXAMPLE
PS> Set-WindowSize -Height 60 -Width 130
Sets the console window to the given dimensions
 
.EXAMPLE
PS> Set-WindowSize -Maximize
Sets the console window to the maximum size available
 
.NOTES
    When downsizing the contents of the buffer are flushed. If there's content wider thant the
    target content, it will be lost
 
    This function is only available in Windows
 
#>
    #[CmdletBinding(DefaultParameterSetName = "MaxSize")]
    #param(
    #    [Parameter(Mandatory, ParameterSetName = "CustomSize")]
    #    [ValidateScript({ $_ -gt 0})]
    #    # Target Height
    #    [int] $Height = 50,
    #
    #    [Parameter(Mandatory, ParameterSetName = "CustomSize")]
    #    [ValidateScript({ $_ -gt 0})]
    #    # Target Width
    #    [int] $Width = 120,
    #
    #    [Parameter(ParameterSetName = "MaxSize")]
    #    # Maximize the window
    #    [switch] $Maximize = $false
    #    )
    #
    $maxHeight = $Host.UI.RawUI.MaxPhysicalWindowSize.Height 
    $maxWidth = $Host.UI.RawUI.MaxPhysicalWindowSize.Width 
    if ($Maximize) {
        $Height = $maxHeight
        $Width  = $maxWidth - 2
    }

    $consoleBuffer = $Host.UI.RawUI.BufferSize 
    $consoleWindow = $Host.UI.RawUI.WindowSize 
 
    $consoleWindow.Height = ($Height) 
    $consoleWindow.Width = ($Width) 

    #$consoleBuffer.Height = (9999)
    $consoleBuffer.Height = (9000)
    $consoleBuffer.Width = ($Width) 

    $Host.UI.RawUI.FlushInputBuffer()
    $Host.UI.RawUI.set_bufferSize($consoleBuffer) 
    $Host.UI.RawUI.set_windowSize($consoleWindow) 
}
function cut {
  param(
    [Parameter(ValueFromPipeline=$True)] [string]$inputobject,
    [string]$delimiter='\s+',
    [string[]]$field
  )

  process {
    if ($field -eq $null) { $inputobject -split $delimiter } else {
      ($inputobject -split $delimiter)[$field] }
  }
}


function sysinfo {
$ProgressPreference = 'SilentlyContinue'	
$ErrorActionPreference = ‘SilentlyContinue’	

#Set-WindowSize -Height 200 -Width 600	
		
$os_info = gwmi Win32_OperatingSystem
  
$Hostname		= $ENV:COMPUTERNAME 2> $null      
$IPv4			= (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}|findstr /v :) -join ", " 2> $null        		
$IPv6			= (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}|findstr :) -join ", " 2> $null       
$OS				= $os_info.caption + $os_info.CSDVersion 2> $null
$OSBuild		= $os_info.Version 2> $null 
$Arch			= $os_info.OSArchitecture 2> $null     

$UserName		= $(whoami)
$UserGroups		= $((net user $env:USERNAME | Select-String -Pattern "Local Group Memberships").ToString() -replace "Local Group Memberships\s*", "" -split '\s+' -replace '^\*', '' -replace ',$' -join ', ')

$LocalUsers = $($(net user | select -Skip 4| findstr /v "The command completed") -Split ' '  | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "
#$DomainUsers = $($(net user /domain 2>$null| select -Skip 4| findstr /v "The command completed") -Split ' '  | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "      

  
  

# Logging in Users
$(query user | %{ $_.Split('')[0,1]} | Select-String -NotMatch USERNAME) | where{$_ -ne " "} > C:\windows\temp\temp; cat C:\windows\temp\temp| ForEach-object { $_.TrimEnd() } | where{$_ -ne ""} > C:\windows\temp\loggedinusers.txt
#$LoggedinUsers = $((Get-CimInstance -ClassName Win32_ComputerSystem).Username | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "    
$LoggedInUsersCount = (Get-Content  C:\windows\temp\loggedinusers.txt| Measure-Object –Line).Lines
$LoggedinUsers = $(cat C:\windows\temp\loggedinusers.txt | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "


        
                  
$LogonServer		= $ENV:LOGONSERVER          
$PSVersion       = $PSVersionTable.PSVersion.ToString()
$PSCompatibleVersions    = ($PSVersionTable.PSCompatibleVersions) -join ', '
$PSCLM = $ExecutionContext.SessionState.LanguageMode

$LSSASRunAsPPL = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1){"1"} Else {"0"}
$LSSASRunAsPPLBoot = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPLBoot -eq 1){"1"} Else {"0"}


$LAPS            = If((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1){"Enabled"} Else {"Disabled"}

$ShellIsAdmin = ${env:=::} -eq $null

# RDP
$RDPEnabled = If((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 1).FDenyTSConnections -eq 1){"Enabled"} Else {"Disabled"} 2> $null
$FDenyTSConnections = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 1).FDenyTSConnections 2> $null
$RDPUsers = $($(net localgroup "Remote Desktop Users" | select -Skip 6 | findstr /v "The command completed") -Split ' ' | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", " 2> $null

$RDPSecurityLayer = $(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' | findstr SecurityLayer) -replace '\s',''
$RDPUserAuthentication =$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\' | findstr UserAuthentication) -replace '\s',''
$RDPAllowEncryptionOracle = $(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name AllowEncryptionOracle | findstr AllowEncryptionOracle) -replace '\s',''


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
$MinimumPasswordLength = $($(net accounts | findstr "length") -replace (' ')) -Split ':' | findstr /v Minimum 2> $null


$LockoutThreshold = $($(net accounts | findstr "threshold") -replace (' ')) -Split ':' | findstr /v threshold 2> $null
$LockoutDuration = $($(net accounts | findstr "duration") -replace (' ')) -Split ':' | findstr /v duration 2> $null
$LockoutWindow = $($(net accounts | findstr "window") -replace (' ')) -Split ':' | findstr /v window 2> $null

$DOMAINORWG = $(if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) { Write-Output "$((Get-WmiObject Win32_ComputerSystem).Domain) (Domain)" } else { Write-Output "$((Get-WmiObject Win32_ComputerSystem).Workgroup) (workgroup)" })

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
$IsVirtual = $($model = (Get-WmiObject Win32_ComputerSystem).Model; $result = $model -match 'VMWare|Hyper|Virtual'; if ($result) { Write-Output "Virtual Machine - $model" } else { Write-Output "Physical Machine - $model" })
#$IsVirtual = ((Get-WmiObject Win32_ComputerSystem).model).Contains("Virtual") 2> $null


# Check applocker
$CheckApplocker = $(if ((Get-Service -Name "AppIDSvc").Status -eq 'Running') { Write-Output "Enabled" } else { Write-Output "Disabled" })


#winrm
$WinRMENabled = [bool](Test-WSMan -ComputerName . -ErrorAction SilentlyContinue) 2> $null
#$WinRMTrustedHosts = (Get-Item WSMan:\localhost\Client\TrustedHosts).value
#$WinRMPort = (Get-Item WSMan:\localhost\listener\*\Port).value 2> $null


# chached logons 
$CachedLogons=$($(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount | findstr CachedLogonsCount)-replace (' ')) -Split ':' | findstr /v CachedLogonsCount 2> $null

# proxy
$ISPROXY = $(if ($proxy = (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyServer) { Write-Output "$proxy" } else { Write-Output "Not Configured" })
#$ProxyEnable = $[bool](Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyEnable
#$ProxyServer = $(Get-ItemProperty -Path "Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings").ProxyServer
#$ProxyNetSH= $(netsh winhttp show proxy | findstr "Proxy Server")


$SMBRequireSecuritySignature = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters").RequireSecuritySignature
$SMBEnableSecuritySignature = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters").EnableSecuritySignature


#########################################################################################################

$sysinfo="C:\windows\temp\sysinfo"

# Build the Table 
Write-Output "BLANK|BLANKy" >  $sysinfo  # this gets ignored

Write-Output "Hostname:|$Hostname" >> $sysinfo
Write-Output "OS:|$OS (Build:$OSBuild)" >> $sysinfo
Write-Output "Arch:|$Arch" >> $sysinfo
Write-Output "Computer Role:|$ComputerRole" >> $sysinfo
Write-Output "Is Virtual:|$IsVirtual" >> $sysinfo
Write-Output "Whoami:|$UserName" >> $sysinfo
Write-Output "Local Group Meberships:|$UserGroups" >> $sysinfo
Write-Output "Local Users:|$LocalUsers" >> $sysinfo
Write-Output "Logged in Users:|[$LoggedInUsersCount] $LoggedInUsers" >> $sysinfo
Write-Output "Admin Shell?:|$ShellIsAdmin"  >> $sysinfo
Write-Output "Current Dir:|$CurrentDir" >> $sysinfo
Write-Output "IPv4:|$IPv4" >> $sysinfo
Write-Output "IPv6:|$IPv6" >> $sysinfo
Write-Output "Domain:|$DOMAINORWG" >> $sysinfo
Write-Output "Logon Server:|$Logonserver" >> $sysinfo

Write-Output "Proxy Server:|$ISPROXY"  >> $sysinfo

#Write-Output "Proxy Server:|$ProxyEnable ($ProxyServer)"  >> $sysinfo

Write-Output "Integrity Level:|$integritylevel">> $sysinfo
Write-Output "UAC LocalAccountTokenFilterPolicy:|$UACLocalAccountTokenFilterPolicy">> $sysinfo
Write-Output "UAC FilterAdministratorToken:|$UACFilterAdministratorToken" >> $sysinfo 
Write-Output "Bitlocker:|C:/ $BitlockerStatus ($BitlockerPercentage)" >> $sysinfo


Write-Output "Windows Firewall:|Private:$Private, Domain:$Domain, Public:$Public" >> $sysinfo
Write-Output "AntiVirus:|$av">> $sysinfo


Write-Output "LSASS Proteciton:| RunAsPPL:$LSSASRunAsPPL, RunAsPPLBoot:$LSSASRunAsPPLBoot" >> $sysinfo
                                
Write-Output "Dotnet Verions:|$dotnetversion" >> $sysinfo

Write-Output "PS Verion:|$PSVersion" >> $sysinfo
Write-Output "PS Compatibly:|$PSCompatibleVersions">> $sysinfo
Write-Output "PS Execution Policy:|$(Get-ExecutionPolicy)">> $sysinfo
Write-Output "PS CLM:|$PSCLM" >> $sysinfo


Write-Output "WinRM Enabled:|$WinRMENabled" >> $sysinfo
#Write-Output "WinRM Enabled:|$WinRMENabled (Port: $WinRMPort)(TrustedHosts: $WinRMTrustedHost)" >> $sysinfo

Write-Output "RDP Enabled:|$RDPEnabled - FDenyTSConnections:$FDenyTSConnections, $RDPSecurityLayer, $RDPUserAuthentication, $RDPAllowEncryptionOracle" >> $sysinfo
Write-Output "RDP Group Users:|$RDPUsers"  >> $sysinfo
#Write-Output "CredSSP (AllowEncryptionOracle):|$CredSSP (2 = Vulnerable, 0 = Forced, 1 = Mitigated)" >> $sysinfo
#Write-Output "NLA:|SecurityLayer:$NLASecurityLayer, UserAuthentication:$NLAUserAuthentication" >> $sysinfo

Write-Output "Applocker:|$CheckApplocker" >> $sysinfo

Write-Output "Password - Minimum Length:|$MinimumPasswordLength characters"  >> $sysinfo
Write-Output "LAPS:|$LAPS" >> $sysinfo


Write-Output "SMB:|RequireSecuritySignature:$SMBRequireSecuritySignature, EnableSecuritySignature:$SMBEnableSecuritySignature"  >> $sysinfo


Write-Output "Lockout - Threshold:|$LockoutThreshold"  >> $sysinfo
Write-Output "Lockout - Duration:|$LockoutDuration mins"  >> $sysinfo
Write-Output "Lockout - Window:|$LockoutWindow mins"  >> $sysinfo
Write-Output "Cached Logons:|$CachedLogons" >> $sysinfo





#Write-Output "Groups - Local:|$UserLocalGroups" >> sysinfo
#Write-Output "Groups - Domain:|$UserDomainGroups" >> sysinfo

# print table 
$P = Import-Csv -Path "$sysinfo" -Delimiter '|'
$P  | Format-Table -HideTableHeaders | Out-String -Width 250 | ft 


# cleanup
Remove-Item C:\windows\temp\sysinfo 2> $null > $null
Remove-Item C:\windows\temp\dotnettemp 2> $null > $null
Remove-Item C:\windows\temp\avtemp 2> $null > $null
Remove-Item C:\windows\temp\loggedinusers.txt 2> $null > $null
}



sysinfo
