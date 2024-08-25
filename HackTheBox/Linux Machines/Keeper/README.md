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

New webpage isreutrned when navigating to `http://tickets.keeper.htb/rt/`:

![Login Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Linux%20Machines/Keeper/Images/Login%20Page.png)




