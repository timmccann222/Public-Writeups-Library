# Escape

# User Flag

## NMAP Enumeration

NMAP All Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.202

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
1433/tcp  open  ms-sql-s         syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49686/tcp open  unknown          syn-ack ttl 127
49726/tcp open  unknown          syn-ack ttl 127
64619/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.202 -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49673,49674,49686,49726,64619

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-16 00:29:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
|_ssl-date: 2024-06-16T00:30:58+00:00; +7h59m59s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
|_ssl-date: 2024-06-16T00:30:57+00:00; +8h00m00s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.10.11.202:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-06-16T00:30:58+00:00; +7h59m59s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-06-16T00:17:59
| Not valid after:  2054-06-16T00:17:59
| MD5:   592e:e6f4:3ebd:0dc0:62ee:e1ed:9526:d943
|_SHA-1: 1bd8:7c8f:76b8:ebe2:2a66:4a5e:865f:813f:2b47:b66b
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
|_ssl-date: 2024-06-16T00:30:57+00:00; +8h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-16T00:30:57+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4c:c647:ebb2:c23e:f472:1d70:2880:9d82
|_SHA-1: d88d:12ae:8a50:fcf1:2242:909e:3dd7:5cff:92d1:a480
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49726/tcp open  msrpc         Microsoft Windows RPC
64619/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-16T00:30:19
|_  start_date: N/A
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

## SMB Enumeration

Used `smbclient` to enumerate shares:

```bash
smbclient -L //10.10.11.202 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share
```

Accessed the SMB share `Public`:

```bash
smb: \> dir
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022
```


The file `SQL Server Procedures.pdf` makes reference to SQL server incidents.

![](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Escape/Images/SQL%20Server%20Document.png)

Found a user `brandon.brown@sequel.htb` and a set of credentials `PublicUser:GuestUserCantWrite1` in the `SQL Server Procedures.pdf` doucment. 

Enumerated users with `crackmapexec`:

```bash
crackmapexec smb 10.10.11.202 -u 'guest' -p '' --rid-brute

SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [+] Brute forcing RIDs
SMB         10.10.11.202    445    DC               498: sequel\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.202    445    DC               500: sequel\Administrator (SidTypeUser)
SMB         10.10.11.202    445    DC               501: sequel\Guest (SidTypeUser)
SMB         10.10.11.202    445    DC               502: sequel\krbtgt (SidTypeUser)
SMB         10.10.11.202    445    DC               512: sequel\Domain Admins (SidTypeGroup)
SMB         10.10.11.202    445    DC               513: sequel\Domain Users (SidTypeGroup)
SMB         10.10.11.202    445    DC               514: sequel\Domain Guests (SidTypeGroup)
SMB         10.10.11.202    445    DC               515: sequel\Domain Computers (SidTypeGroup)
SMB         10.10.11.202    445    DC               516: sequel\Domain Controllers (SidTypeGroup)
SMB         10.10.11.202    445    DC               517: sequel\Cert Publishers (SidTypeAlias)
SMB         10.10.11.202    445    DC               518: sequel\Schema Admins (SidTypeGroup)
SMB         10.10.11.202    445    DC               519: sequel\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.202    445    DC               520: sequel\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.202    445    DC               521: sequel\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.202    445    DC               522: sequel\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.202    445    DC               525: sequel\Protected Users (SidTypeGroup)
SMB         10.10.11.202    445    DC               526: sequel\Key Admins (SidTypeGroup)
SMB         10.10.11.202    445    DC               527: sequel\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.202    445    DC               553: sequel\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.202    445    DC               571: sequel\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.202    445    DC               572: sequel\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.202    445    DC               1000: sequel\DC$ (SidTypeUser)
SMB         10.10.11.202    445    DC               1101: sequel\DnsAdmins (SidTypeAlias)
SMB         10.10.11.202    445    DC               1102: sequel\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.202    445    DC               1103: sequel\Tom.Henn (SidTypeUser)
SMB         10.10.11.202    445    DC               1104: sequel\Brandon.Brown (SidTypeUser)
SMB         10.10.11.202    445    DC               1105: sequel\Ryan.Cooper (SidTypeUser)
SMB         10.10.11.202    445    DC               1106: sequel\sql_svc (SidTypeUser)
SMB         10.10.11.202    445    DC               1107: sequel\James.Roberts (SidTypeUser)
SMB         10.10.11.202    445    DC               1108: sequel\Nicole.Thompson (SidTypeUser)
SMB         10.10.11.202    445    DC               1109: sequel\SQLServer2005SQLBrowserUser$DC (SidTypeAlias)
```

## Port 1433 - MSSQL Enumeration















