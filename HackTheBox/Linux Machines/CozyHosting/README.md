# CozyHosting

# User Flag

## NMAP Enumeration

Masscan UDP/TCP Port Scan:

```bash
sudo masscan -p1-65535,U:1-65535 10.10.11.230 --rate=1000 -e tun0

N/A
```

NMAP All Open ports:

```bash
sudo nmap -T5 --open -sS -vvv --min-rate=300 --max-retries=3 -p- -oN nmap-report-all-open-ports 10.10.11.230

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

All Ports (Filtered, Closed, etc.)

```bash
sudo nmap -T5 -sS -vvv --min-rate=100 --max-retries=3 -p- -oN nmap-report-all-ports 10.10.11.230

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Port Service Scan:

```bash
nmap -sV -sC -Pn -v -oN nmap-report-service-scan 10.10.11.230 -p 

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Service Enumeration (Port 80)

Web App Enumeration:

* Login Page
* Email found `info@cozyhosting.htb`
* No developer comments on web page.
* 

Directory Fuzzing with `ffuf` tool to find hidden directories:

```bash
ffuf -c -u http://cozyhosting.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic

index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 111ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 127ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 982ms]
admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 169ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 130ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 466ms]
                        [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 169ms]
27079%5Fclassicpeople2%2Ejpg [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 104ms]
children%2527s_tent     [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 161ms]
tiki%2Epng              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 77ms]
Wanted%2e%2e%2e         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 74ms]
How_to%2e%2e%2e         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 86ms]
squishdot_rss10%2Etxt   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 108ms]
b33p%2Ehtml             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 73ms]
help%2523drupal         [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 102ms]
```





















