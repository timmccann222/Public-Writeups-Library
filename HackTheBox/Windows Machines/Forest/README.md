# Forest

# User Flag

## NMAP Enumeration

NMAP All Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.161

# Output
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
49671/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49680/tcp open  unknown          syn-ack ttl 127
49700/tcp open  unknown          syn-ack ttl 127
49941/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.161 -p 88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49671,49674,49675,49680,49700,49941

# Output
PORT      STATE SERVICE      VERSION
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-06-02 14:38:23Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
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
49666/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49674/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  msrpc        Microsoft Windows RPC
49700/tcp open  msrpc        Microsoft Windows RPC
49941/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-02T14:39:14
|_  start_date: 2024-06-02T14:28:31
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-06-02T07:39:17-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m53s, deviation: 4h02m31s, median: 6m52s
```

## SMB Enumeration

Could not list any shares with `smbmap`, `smbclient` or `crackmapexec`.

List users with `crackmapexec`:

```bash
crackmapexec smb 10.10.10.161 --users

# Output
SMB         10.10.10.161    445    FOREST           [*] Trying with SAMRPC protocol
SMB         10.10.10.161    445    FOREST           [+] Enumerated domain user(s)
SMB         10.10.10.161    445    FOREST           htb.local\Administrator                  Built-in account for administering the computer/domain                                                                                                                               
SMB         10.10.10.161    445    FOREST           htb.local\Guest                          Built-in account for guest access to the computer/domain                                                                                                                             
SMB         10.10.10.161    445    FOREST           htb.local\krbtgt                         Key Distribution Center Service Account
SMB         10.10.10.161    445    FOREST           htb.local\DefaultAccount                 A user account managed by the system.
SMB         10.10.10.161    445    FOREST           htb.local\$331000-VK4ADACQNUCA           
SMB         10.10.10.161    445    FOREST           htb.local\SM_2c8eef0a09b545acb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_ca8c2ed5bdab4dc9b           
SMB         10.10.10.161    445    FOREST           htb.local\SM_75a538d3025e4db9a           
SMB         10.10.10.161    445    FOREST           htb.local\SM_681f53d4942840e18           
SMB         10.10.10.161    445    FOREST           htb.local\SM_1b41c9286325456bb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_9b69f1b9d2cc45549           
SMB         10.10.10.161    445    FOREST           htb.local\SM_7c96b981967141ebb           
SMB         10.10.10.161    445    FOREST           htb.local\SM_c75ee099d0a64c91b           
SMB         10.10.10.161    445    FOREST           htb.local\SM_1ffab36a2f5f479cb           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxc3d7722           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxfc9daad           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxc0a90c9           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox670628e           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox968e74d           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox6ded678           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox83d6781           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxfd87238           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailboxb01ac64           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox7108a4e           
SMB         10.10.10.161    445    FOREST           htb.local\HealthMailbox0659cc1           
SMB         10.10.10.161    445    FOREST           htb.local\sebastien                      
SMB         10.10.10.161    445    FOREST           htb.local\lucinda                        
SMB         10.10.10.161    445    FOREST           htb.local\svc-alfresco                   
SMB         10.10.10.161    445    FOREST           htb.local\andy                           
SMB         10.10.10.161    445    FOREST           htb.local\mark                           
SMB         10.10.10.161    445    FOREST           htb.local\santi
```

## Kerberos

Enumerate users with kerbrute using the domain details discovered during the NMAP scans and user list found during SMB enumeration:

```bash
./kerbrute_linux_amd64 userenum --dc 10.10.10.161 -d htb.local -o kerbrute-user-enum userlist

# Output
2024/06/02 15:51:48 >  [+] VALID USERNAME:       Administrator@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailboxc0a90c9@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailboxc3d7722@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailboxfc9daad@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailbox670628e@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailbox6ded678@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailbox968e74d@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailbox83d6781@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailboxfd87238@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailboxb01ac64@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       lucinda@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       sebastien@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailbox7108a4e@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       HealthMailbox0659cc1@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       andy@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       svc-alfresco@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       mark@htb.local
2024/06/02 15:51:48 >  [+] VALID USERNAME:       santi@htb.local
```





















