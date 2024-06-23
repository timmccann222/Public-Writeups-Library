# Intelligence

# User Flag

## NMAP Enumeration

NMAP Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.248

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
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
49683/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49694/tcp open  unknown          syn-ack ttl 127
49739/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.248 -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49683,49684,49694,49739

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-22 22:50:50Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-22T22:52:21+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-22T22:28:03
| Not valid after:  2025-06-22T22:28:03
| MD5:   a9d5:6c92:b581:0378:3dd4:7036:c81e:a275
|_SHA-1: 0ac4:e42f:df47:3d9f:88dd:d22c:42d4:7ed9:1f16:70e5
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-22T22:28:03
| Not valid after:  2025-06-22T22:28:03
| MD5:   a9d5:6c92:b581:0378:3dd4:7036:c81e:a275
|_SHA-1: 0ac4:e42f:df47:3d9f:88dd:d22c:42d4:7ed9:1f16:70e5
|_ssl-date: 2024-06-22T22:52:21+00:00; +7h00m00s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-22T22:52:21+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-22T22:28:03
| Not valid after:  2025-06-22T22:28:03
| MD5:   a9d5:6c92:b581:0378:3dd4:7036:c81e:a275
|_SHA-1: 0ac4:e42f:df47:3d9f:88dd:d22c:42d4:7ed9:1f16:70e5
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-22T22:52:21+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-22T22:28:03
| Not valid after:  2025-06-22T22:28:03
| MD5:   a9d5:6c92:b581:0378:3dd4:7036:c81e:a275
|_SHA-1: 0ac4:e42f:df47:3d9f:88dd:d22c:42d4:7ed9:1f16:70e5
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-22T22:51:44
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
```

## HTTP Port 80 - Enumeration

Found a potential user `contact@intelligence.htb` while looking through the website.

Used `ffuf` to enumerate hidden directories:

```bash
ffuf -u http://10.10.10.248/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

documents               [Status: 301, Size: 153, Words: 9, Lines: 2, Duration: 79ms]
Documents               [Status: 301, Size: 153, Words: 9, Lines: 2, Duration: 109ms]
```

The `documents` sub-directory contains PDF uploads with the naming convention seen below:

```bash
2020-01-01-upload.pdf
2020-12-15-upload.pdf
```

Used Burpsuite Intruder and the observed naming convention to see if there were any other documents under this sub directory. Used the payload ClusterBomb and set the variables to the month and date.

![BurpSuite Intruder](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Intelligence/Images/BurpSuite%20Intruder.png)

Found a PDF titled `2020-06-04-upload.pdf` that contained a password:

![Account Guide](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Intelligence/Images/Account%20Guide.png)

Found a PDF titled `2020-12-30-upload.pdf` which contains potnetial user `ted` and reference to **service accounts**:

![Internal IT Update](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Intelligence/Images/Internal%20IT%20Update.png)

## SMB Enumeration

Used `enum4linux` but did not return anything of interest.

```bash
enum4linux -a 10.10.10.248 > enum4linux.txt
```

Tested for NULL shares with anonymous login. Was successful but did not return any shares:

```bash
smbclient -L //10.10.10.248 -N
             
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
```

Tried enumerating shares with `crackmapexec` but didn't return anything useful.

```bash
crackmapexec smb 10.10.10.248 -u '' -p '' --shares
crackmapexec smb 10.10.10.248 -u 'guest' -p '' --shares
crackmapexec smb 10.10.10.248 -u '' -p '' --users
crackmapexec smb 10.10.10.248 -u 'guest' -p '' --users
crackmapexec smb 10.10.10.248 -u '' -p '' --shares -M spider_plus
```

## LDAP Enumeration

Extracted base naming contexts:

```bash
ldapsearch -x -H ldap://10.10.10.248 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=intelligence,DC=htb
namingcontexts: CN=Configuration,DC=intelligence,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=intelligence,DC=htb
namingcontexts: DC=DomainDnsZones,DC=intelligence,DC=htb
namingcontexts: DC=ForestDnsZones,DC=intelligence,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

Attempted to extract users via LDAP:

```bash
```














