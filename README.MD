# sysinfo

This is a powershell alternative to runnig systeminfo this prints out key details quickly so when jumping on a windows system you have a very fast idea what you are dealing with. Aids with situational awarenes giving you a quick insight into key settings on the system 

As with most of my releases this is a work in progress and alot more i want to add but this is a nice start..  lots more testing is required ive only played with it on up to date windows 10 

## Useage 

```
Import-Module .\sysinfo.ps1
sysinfo
```

will put some temp files in C:\windows\temp  

## Output Example 

```
PS C:\> sysinfo

Hostname:                  BADMANWORKSTATION                                                                           
OS:                        Microsoft Windows 10 Education (Build:10.0.19044)                                 
Arch:                      64-bit                                                                            
Computer Role:             WORKSTATION                                                                       
BIOS Version:              AMAZON - 1                                                                        
Whoami:                    husky\tbundy                                                                       
Local Group Meberships:                                                                                      
Local Users:               Administrator, DefaultAccount, Guest, LapsAdmin, WDAGUtilityAccount
Logged in Users:           []
Admin Shell?:              False
Current Dir:               C:\Windows\system32
IPv4:                      10.10.123.102
IPv6:                      ::1
Domain:                    husk.dog (Domain)
Logon Server:              \\DC1
Proxy Server:              squid.husky.dog:3128
Integrity Level:           Medium Mandatory Level
Bitlocker:                 C:/  ()
Windows Firewall:          Private:Disabled, Domain:Disabled, Public:Disabled
AntiVirus:                 Windows Defender
UAC:                       LocalAccountTokenFilterPolicy:1, FilterAdministratorToken:, EnableLUA:1, EnableVirtualization:1, EnableInstallerDetection:1,
                           ConsentPromptBehaviorAdmin:5, ConsentPromptBehaviorUser:3, PromptOnSecureDesktop:1, ValidateAdminCodeSignatures:0           
LSASS Proteciton:          RunAsPPL:0, RunAsPPLBoot:0
Dotnet Verions:            4.8.04084, 4.8.04084, 4.0.0.0
PS Verion:                 5.1.19041.1682
PS Compatibly:             1.0, 2.0, 3.0, 4.0, 5.0, 5.1.19041.1682
PS Execution Policy:       Unrestricted
PS CLM:                    FullLanguage
WinRM Enabled:             False
RDP Enabled:               Disabled - FDenyTSConnections:0, SecurityLayer:2, UserAuthentication:1,
RDP Group Users:           husky\tbundy
Applocker:                 Disabled
Password - Minimum Length: 7 characters
LAPS:                      Enabled
SMB:                       RequireSecuritySignature:0, EnableSecuritySignature:1
Lockout - Threshold:       Never
Lockout - Duration:        30 mins
Lockout - Window:          30 mins
Cached Logons:             10
```
