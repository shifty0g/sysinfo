$NAME="sysinfo"
$VERSION="0.2"
$DATE="27-08-22"
<#
Sysinfo for Hackers 

To Do 
------
Check if Admin - then run extra chceks such as getting secpol est. 
print out local and domain groups of the current user 

Tidy the output
check SMB - singing 



Useage
---------
Import-Module .\sysinfo.ps1
sysinfo 



#>
#########################################################################################################

function sysinfo {
$os_info = gwmi Win32_OperatingSystem
$IsHighIntegrity = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")    
$Hostname		= $ENV:COMPUTERNAME      
$IPv4			= (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}|findstr /v :) -join ", "        		
$IPv6			= (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}|findstr :) -join ", "        
$OS				= $os_info.caption + $os_info.CSDVersion
$OSBuild			= $os_info.Version 
$Arch			= $os_info.OSArchitecture     

$UserName		= $ENV:USERNAME
$LocalUsers = $($(net user | select -Skip 4| findstr /v "The command completed") -Split ' '  | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "
#$DomainUsers = $($(net user /domain 2>$null| select -Skip 4| findstr /v "The command completed") -Split ' '  | ForEach-object { $_.TrimEnd() } | where{$_ -ne ""}) -join ", "      
      
                  
$LogonServer		= $ENV:LOGONSERVER          
$PSVersion       = $PSVersionTable.PSVersion.ToString()
$PSCompatibleVersions    = ($PSVersionTable.PSCompatibleVersions) -join ', '
$LSASSPROTECTION = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1){"Enabled"} Else {"Disabled"}
$LAPS            = If((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1){"Enabled"} Else {"Disabled"}

$ShellIsAdmin = ${env:=::} -eq $null

# RDP
$FDenyTSConnections = [bool](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 1).FDenyTSConnections         


$CredSSP=$($(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name AllowEncryptionOracle | findstr AllowEncryptionOracle) -replace (' ')) -Split ':' | findstr /v Oracle    

# UAC - Integrity 
$UAC             = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).EnableLUA -eq 1){"Enabled"} Else {"Disabled (UAC is Disabled)"}
$integritylevel=$($(whoami /groups | select-string Label) -Split '\\' | Select-String - | findstr Level).Substring(0,22) -replace "`n",", " -replace "`r",", "
 # LocalAccountTokenFilterPolicy = 1 disables local account token filtering for all non-rid500 accounts
$UACLocalAccountTokenFilterPolicy    = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).LocalAccountTokenFilterPolicy -eq 1){"Disabled (PTH likely w/ non-RID500 Local Admins)"} Else {"Enabled (Remote Administration restricted for non-RID500 Local Admins)"}
$UACFilterAdministratorToken     	= If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).FilterAdministratorToken -eq 1){"Enabled (RID500 protected)"} Else {"Disabled (PTH likely with RID500 Account)"}
$HighIntegrity           			= $IsHighIntegrity		
		

# Firewall 
$regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
$Private    = If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
$Domain     = If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
$Public     = If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}

## Secedit stuff - needs admin to do this 
#secedit /export /cfg temp 2> $null > $null 
#cat .\temp 2> $null | findstr "Password" | findstr /v "MACHINE Clear RequireLogon Age"
#cat .\temp 2> $null |  findstr "Lockout" | findstr /v Software 
#remove-item temp 2> $null > $null 
#

# NLA 
$NLASecurityLayer =$([bool]$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer | findstr SecurityLayer)-replace (' ')) -Split ':' | findstr /v Security
$NLAUserAuthentication =$([bool]$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication| findstr UserAuthentication)-replace (' ')) -Split ':' | findstr /v Authentication





# Password & Lockout  
$MinimumPasswordLength = $($(net accounts | findstr "length") -replace (' ')) -Split ':' | findstr /v Mini
$LockoutThreshold = $($(net accounts | findstr "threshold") -replace (' ')) -Split ':' | findstr /v threshold
$LockoutDuration = $($(net accounts | findstr "duration") -replace (' ')) -Split ':' | findstr /v duration
$LockoutWindow = $($(net accounts | findstr "window") -replace (' ')) -Split ':' | findstr /v window


$ComputerRole = $($(net accounts | findstr "role") -replace (' ')) -Split ':' | findstr /v role


# Dotnet 
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select version | ft > dotnettemp
$dotnetversion=$((cat dotnettemp  | select -Skip 3  | ForEach-object { $_.TrimEnd() } ) -join ", ")

# AV
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | select displayName | ft -HideTableHeaders | where{$_ -ne ""} > avtemp
$av=((cat avtemp  | ForEach-object { $_.TrimEnd() }  ) -join ", ").substring(2) 
Remove-Item avtemp 2> $null > $null

#########################################################################################################



# Build the Table 
Write-Output "BLANK|BLANKy" > sysinfo  # this gets ignored


Write-Output "Hostname:|$Hostname" >> sysinfo
Write-Output "OS:|$OS" >> sysinfo
Write-Output "OS Build:|$OSBuild" >> sysinfo
Write-Output "Computer Role:|$ComputerRole" >> sysinfo
Write-Output "User:|$UserName" >> sysinfo
Write-Output "Admin Shell?:|$ShellIsAdmin"  >> sysinfo
Write-Output "Arch:|$Arch" >> sysinfo
Write-Output "IPv4:|$IPv4" >> sysinfo
Write-Output "IPv6:|$IPv6" >> sysinfo
Write-Output "Domain:|$env:USERDNSDOMAIN" >> sysinfo
Write-Output "Logon Server:|$Logonserver" >> sysinfo
Write-Output "Dotnet Verions:|$dotnetversion" >> sysinfo
Write-Output "PS Verion:|$PSVersion" >> sysinfo
Write-Output "PC Compatibly:|$PSCompatibleVersions">> sysinfo
Write-Output "PS Ex Policy:|$(Get-ExecutionPolicy)">> sysinfo
Write-Output "Integrity Level:|$integritylevel (Is High Intergirty: $IsHighIntegrity)">> sysinfo
Write-Output "UAC LocalAccountTokenFilterPolicy:|$UACLocalAccountTokenFilterPolicy">> sysinfo
Write-Output "UAC FilterAdministratorToken:|$UACFilterAdministratorToken" >> sysinfo 
Write-Output "Windows Firewall:|Private:$Private, Domain:$Domain, Public:$Public" >> sysinfo
Write-Output "AntiVirus:|$av">> sysinfo
Write-Output "LSASS Proteciton:|$LSASSPROTECTION" >> sysinfo
Write-Output "Password - Minimum Length:|$MinimumPasswordLength"  >> sysinfo
Write-Output "Lockout - Threshold:|$LockoutThreshold"  >> sysinfo
Write-Output "Lockout - Duration:|$LockoutDuration mins"  >> sysinfo
Write-Output "Lockout - Window:|$LockoutWindow mins"  >> sysinfo
Write-Output "LAPS:|$LAPS" >> sysinfo
Write-Output "RDP - Enabled (FDenyTSConnections):|$FDenyTSConnections " >> sysinfo
Write-Output "CredSSP (AllowEncryptionOracle):|$CredSSP (2 = Vulnerable, 0 = Forced, 1 = Mitigated)" >> sysinfo
Write-Output "NLA:|SecurityLayer:$NLASecurityLayer, UserAuthentication:$NLAUserAuthentication" >> sysinfo


#Write-Output "Groups - Local:|$UserLocalGroups" >> sysinfo
#Write-Output "Groups - Domain:|$UserDomainGroups" >> sysinfo

# print table 
$P = Import-Csv -Path "sysinfo" -Delimiter '|'
$P | Format-Table -HideTableHeaders


# cleanup
Remove-Item sysinfo 2> $null > $null
}

