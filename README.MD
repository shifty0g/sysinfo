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

Hostname:                           BadManSystem
OS:                                 Microsoft Windows 10 Pro
OS Build:                           10.0.19044
Computer Role:                      WORKSTATION
User:                               dangermouse
Admin Shell?:                       True
Arch:                               64-bit
IPv4:                               10.0.0.2, 192.168.56.2, 192.168.0.44
IPv6:                               fe80::5802:68d1:dd42:cf0c%10, fe80::7065:1b0:9f5:4f11%21, fe80::30e3:5b03:a0cf:2149%11
Domain:                             HUSKY.DOG
Logon Server:                       \\BEEFCAKE-DC
Dotnet Verions:                     2.0.50727.4927, 3.0.30729.4926, 3.0.4506.4926, 3.0.6920.4902, 3.5.30729.4926, 4.8.04084, 4.8.04084, 4.0.0.0, ,
PS Verion:                          5.1.19041.1682
PC Compatibly:                      1.0, 2.0, 3.0, 4.0, 5.0, 5.1.19041.1682
PS Ex Policy:                       Unrestricted
Integrity Level:                    High Mandatory Level   (Is High Intergirty: True)
UAC LocalAccountTokenFilterPolicy:  Disabled (PTH likely w/ non-RID500 Local Admins)
UAC FilterAdministratorToken:       Enabled (RID500 protected)
Windows Firewall:                   Private - Enabled, Domain - Enabled, Public - Enabled
AntiVirus:                          Sophos Anti-Virus, Windows Defender, Sophos Intercept X, Sophos Intercept X, ,
LSASS Proteciton:                   Disabled
Password - Minimum Length:          9
Lockout - Threshold:                5
Lockout - Duration:                 30 mins
Lockout - Window:                   30 mins
LAPS:                               Disabled
RDP - Enabled (FDenyTSConnections): True
CredSSP (AllowEncryptionOracle):    0 (2 = Vulnerable, 0 = Forced, 1 = Mitigated)
NLA:                                SecurityLayer:True, UserAuthentication:True
```