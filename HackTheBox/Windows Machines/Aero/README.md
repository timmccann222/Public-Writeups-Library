# Aero

# User Flag

## NMAP Enumeration

All Port Scan:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN all-ports-nmap-report 10.10.11.237

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 127
```

NMAP Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report 10.10.11.237 -p 80

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Aero Theme Hub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Web Enumeration

Notes:

* Email found `support@aerohub.htb`
* Upload functionality found:

![Upload Page](https://github.com/timmccann222/Public-Writeups-Library/blob/main/HackTheBox/Windows%20Machines/Aero/Images/Upload%20Page.png)

Selecting the browse button to upload a file shows that the available file types supported are `.theme` and `.themepack`.








